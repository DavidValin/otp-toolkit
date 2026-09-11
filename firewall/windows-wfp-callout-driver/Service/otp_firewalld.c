/*
 * otp_firewalld.c - Windows equivalent of firewall/linux-kernel-module/otp_firewalld.c:
 * a Windows Service that plays the same role otp_firewalld plays on
 * Linux and the System Extension plays on macOS - startup
 * (keychain/config/log init), then a loop moving packets between the
 * kernel driver and the unmodified cipher.c/keychain.c library via
 * packet_codec.c.
 *
 * UNVERIFIED - not built or run against a real Windows toolchain; see
 * ../README.md's confidence table.
 *
 * One genuine structural difference from Linux's otp_firewalld.c, not just a
 * syntax port, called out here rather than left implicit: Linux's
 * daemon is single-threaded by construction (SIGALRM interrupts a
 * blocking recv() via EINTR - see otp_firewalld.c's own comment on why
 * sigaction() without SA_RESTART matters). OTP_FW_IOCTL_DEQUEUE_PACKET
 * is a synchronous, blocking DeviceIoControl() call with no equivalent
 * "signal interrupts a blocked syscall" mechanism, so periodic config
 * reload here genuinely needs a second thread - which in turn means
 * every access to g_keychain (a bare global in keychain.c, not
 * thread-safe) and to FwContext must be serialized with an explicit
 * CRITICAL_SECTION. Neither of the other two platforms needs this the
 * same way: FreeBSD's daemon is single-threaded like Linux's (a
 * select()-based main loop, no separate thread ever touches this
 * state); macOS's bridge is called from Swift code whose exact
 * threading isn't confirmable without a real target to test against,
 * so it takes the same conservative approach as here - wrapping every
 * call in an explicit lock (a pthread_mutex there) rather than assuming
 * safety.
 */

#include "ack.h"
#include "common.h"
#include "config.h"
#include "keychain_setup.h"
#include "kernel_ctl.h"
#include "log.h"
#include "packet_codec.h"
#include "pin.h"
#include "trial.h"

#include "keychain.h"
#include "cipher.h"

#include "../Driver/otp_toolkit_firewall.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OTP_FW_SVC_NAME L"OTPFirewall"
#define OTP_FW_DEFAULT_RESOLVE_INTERVAL_MS (60 * 1000)
#define OTP_FW_ACK_TICK_MS 1000 /* mirrors otp_firewalld.c's OTP_FW_TICK_INTERVAL_SECONDS */

typedef struct
{
  FwConfig cfg;
  PinTable pins;
  AckTable acks;
  char keychain_dir[512];
} FwContext;

static FwContext g_ctx;
static CRITICAL_SECTION g_state_lock; /* guards g_ctx and every g_keychain access - see file header */
static char g_config_path[1024];
static int g_resolve_interval_ms = OTP_FW_DEFAULT_RESOLVE_INTERVAL_MS;
static HANDLE g_stop_event;
static HANDLE g_packet_thread;
static HANDLE g_reload_thread;
static HANDLE g_ack_thread;
static HANDLE g_device = INVALID_HANDLE_VALUE; /* opened once in startup(), closed once from ServiceMain's own cleanup path after both worker threads have exited */
static int g_ack_fd4 = -1; /* int, not SOCKET, to match ack.h's platform-uniform int fd type - see ack.c's own note on the SOCKET/int cast this implies on Windows */
static int g_ack_fd6 = -1;
static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS g_status;
static volatile LONG g_stop_requested = 0; /* guards ServiceCtrlHandler against SCM delivering STOP and SHUTDOWN back to back */
static BOOL g_wsa_started = FALSE;   /* only WSACleanup() if WSAStartup() actually succeeded */
static BOOL g_crit_initialized = FALSE; /* only DeleteCriticalSection() if InitializeCriticalSection() actually ran */

/* Mirrors otp_firewalld.c's reconcile_pins_with_config() exactly (same
 * unmodified pin.h/config.h API, only the surrounding daemon shape
 * differs) - a pin is dropped only when its contact was actually
 * removed from the keychain, or the config now EXPLICITLY maps that IP
 * to a different contact; an IP simply absent from the config keeps
 * its pin. */
static void reconcile_pins_with_config(void)
{
  for (int i = 0; i < g_ctx.pins.count; i++)
  {
    char ip[OTP_FW_IPSTR_LEN];
    char contact[MAX_NAME_LENGTH];
    snprintf(ip, sizeof(ip), "%s", g_ctx.pins.entries[i].ip);
    snprintf(contact, sizeof(contact), "%s", g_ctx.pins.entries[i].contact);

    if (!find_contact(contact))
    {
      pin_clear_ip(&g_ctx.pins, ip);
      i--;
      continue;
    }
    const char *configured = fwconfig_contact_for_ip(&g_ctx.cfg, ip);
    if (configured && strcmp(configured, contact) != 0)
    {
      pin_clear_ip(&g_ctx.pins, ip);
      i--;
    }
  }
}

/* Mirrors otp_firewalld.c's reconcile_acks_with_keychain(): a stale
 * outstanding-ack slot (see ack.h) for a contact no longer in the
 * keychain is harmless but pointless to keep around. */
static void reconcile_acks_with_keychain(void)
{
  for (int i = 0; i < g_ctx.acks.count; i++)
  {
    char contact[MAX_NAME_LENGTH];
    snprintf(contact, sizeof(contact), "%s", g_ctx.acks.slots[i].contact);
    if (!find_contact(contact))
    {
      ack_clear_contact(&g_ctx.acks, contact);
      i--;
    }
  }
}

/* Mirrors otp_firewalld.c's reload_config_and_push(), including the keychain
 * snapshot/restore-on-failure fix documented there in detail - that
 * fix is load-bearing (a transient failure must not silently wipe
 * every known contact), so it is not something this port can afford to
 * simplify away. */
static void reload_config_and_push(void)
{
  static Keychain keychain_snapshot;

  EnterCriticalSection(&g_state_lock);
  keychain_snapshot = g_keychain;
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Warning: failed to reload keychain - keeping the previous in-memory state\n");
    g_keychain = keychain_snapshot;
  }
  if (fwconfig_load(g_config_path, &g_ctx.cfg) == 0)
    fwconfig_resolve(&g_ctx.cfg);
  reconcile_pins_with_config();
  reconcile_acks_with_keychain();
  otp_fw_kernel_push_candidates(&g_ctx.cfg);
  LeaveCriticalSection(&g_state_lock);
}

/* Shared by process_packet()'s inbound branch (a normal candidate
 * packet dequeued from the driver) and handle_redeliver_packet_locked()
 * (a packet reconstructed from an ack-port REDELIVER, see ack.h) - both
 * need exactly the same trial-decrypt/pin/ack-send logic. Must be
 * called with g_state_lock already held. On OTP_FW_OK, also sends the
 * delivery ack back to `src_ip` - the receiving half of the same
 * mechanism process_packet()'s ack_mark_outstanding() call is the
 * sending half of. */
static otp_fw_result_t process_inbound_locked(const unsigned char *pkt, int pkt_len, const char *src_ip,
                                              unsigned char *out_data, int out_cap, int *out_len,
                                              char *contact_out, size_t contact_out_size)
{
  /* Same static-buffer reasoning as otp_firewalld.c's ingress_cb(): CandidateList
   * is too large (~2.5MB) for a stack local, and reusing one is safe
   * because trial_select_primary() rebuilds it from scratch every call
   * and g_state_lock already serializes all callers. */
  static CandidateList candidates;
  trial_select_primary(g_ctx.keychain_dir, &g_ctx.cfg, &g_ctx.pins, src_ip, &candidates);

  otp_fw_result_t r = otp_fw_decrypt_packet(g_ctx.keychain_dir, &candidates, pkt, pkt_len,
                                            out_data, out_cap, out_len, contact_out, contact_out_size);

  if (r != OTP_FW_OK && !candidates.exclusive)
  {
    trial_add_fallback_scan(g_ctx.keychain_dir, &candidates);
    r = otp_fw_decrypt_packet(g_ctx.keychain_dir, &candidates, pkt, pkt_len,
                              out_data, out_cap, out_len, contact_out, contact_out_size);
  }

  if (r == OTP_FW_OK)
  {
    if (pin_set(&g_ctx.pins, src_ip, contact_out) != 0)
      fprintf(stderr, "Warning: pin table full (%d entries) - '%s' will use the slower "
                      "trial path on every packet until a pin frees up\n",
             OTP_FW_MAX_PINS, src_ip);

    Contact *c = find_contact(contact_out);
    unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN];
    if (c && ack_read_source_id_file(contact_out, c->DecryptedSequence, 0, source_id) == 0)
    {
      int family = strchr(src_ip, ':') ? AF_INET6 : AF_INET;
      ack_socket_send(src_ip, family, source_id);
    }
    else
    {
      fprintf(stderr, "Warning: could not capture delivery-ack reference for inbound message from '%s' - no ack sent\n", contact_out);
    }
  }

  return r;
}

/* Runs one dequeued packet through the same egress/ingress logic
 * otp_firewalld.c's egress_cb()/ingress_cb() run, and fills in `verdict` for
 * OTP_FW_IOCTL_SUBMIT_VERDICT. Holds g_state_lock for the whole call:
 * every path through here touches g_keychain (via
 * otp_fw_encrypt_packet/otp_fw_decrypt_packet) and/or g_ctx (cfg,
 * pins), same reasoning as reload_config_and_push() above. */
static void process_packet(const otp_fw_dequeued_packet_t *in, otp_fw_verdict_submission_t *out)
{
  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  otp_fw_describe_packet(in->data, (int)in->data_len, src_ip, sizeof(src_ip), &src_port,
                        dst_ip, sizeof(dst_ip), &dst_port, &proto);

  out->packet_id = in->packet_id;
  out->data_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r;

  EnterCriticalSection(&g_state_lock);

  if (in->direction == OTP_FW_PKT_OUTBOUND)
  {
    /* Free (no key spent) contact resolution first, so the delivery-ack
     * gate (see ack.h) can reject a packet BEFORE ever calling the
     * real, key-spending encrypt - see otp_firewalld.c's identical reasoning. */
    r = otp_fw_classify_egress(g_ctx.keychain_dir, &g_ctx.cfg, in->data, (int)in->data_len, contact, sizeof(contact));
    int out_len = 0;
    if (r == OTP_FW_OK)
    {
      if (!ack_egress_allowed(&g_ctx.acks, contact))
        r = OTP_FW_ACK_PENDING;
      else
        r = otp_fw_encrypt_packet(g_ctx.keychain_dir, &g_ctx.cfg, in->data, (int)in->data_len,
                                  out->data, sizeof(out->data), &out_len, contact, sizeof(contact));
    }

    if (r == OTP_FW_OK)
    {
      otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);

      /* Track this message for delivery acknowledgment - see otp_firewalld.c's
       * identical reasoning. */
      int header_len = otp_fw_header_length(in->data, (int)in->data_len);
      Contact *c = find_contact(contact);
      unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN];
      if (header_len > 0 && c &&
         ack_read_source_id_file(contact, c->EncryptedSequence, 1, source_id) == 0)
      {
        int family = strchr(dst_ip, ':') ? AF_INET6 : AF_INET;
        if (ack_mark_outstanding(&g_ctx.acks, contact, c->EncryptedSequence, source_id, dst_ip, family, in->data, header_len) != 0)
          fprintf(stderr, "Warning: ack table full - '%s' will send without delivery tracking until a slot frees up\n", contact);
      }
      else
      {
        fprintf(stderr, "Warning: could not capture delivery-ack reference for '%s' - sending without tracking\n", contact);
      }

      out->verdict = OTP_FW_VERDICT_FORWARD_MODIFIED;
      out->data_len = (uint32_t)out_len;
    }
    else
    {
      otp_fw_log_restricted("egress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                            proto, otp_fw_result_reason(r));
      out->verdict = OTP_FW_VERDICT_DROP;
    }
  }
  else
  {
    int out_len = 0;
    r = process_inbound_locked(in->data, (int)in->data_len, src_ip, out->data, sizeof(out->data),
                               &out_len, contact, sizeof(contact));

    if (r == OTP_FW_OK)
    {
      otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
      out->verdict = OTP_FW_VERDICT_FORWARD_MODIFIED;
      out->data_len = (uint32_t)out_len;
    }
    else
    {
      otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                            proto, otp_fw_result_reason(r));
      out->verdict = OTP_FW_VERDICT_DROP;
    }
  }

  LeaveCriticalSection(&g_state_lock);
}

/* Handles one REDELIVER packet from the ack socket (see ack.h):
 * reconstructed IP+L4 header + ciphertext, run through the same
 * trial-decrypt logic a normal dequeued packet would use. From the
 * protocol's point of view this is indistinguishable from the original
 * packet having simply arrived late - its only purpose is getting this
 * contact's DecryptionKeyOffset back in sync and (on success, inside
 * process_inbound_locked()) triggering the ack send back to the sender.
 * There is no verdict to submit: this never came from the driver's
 * queue. Must be called with g_state_lock already held. */
static void handle_redeliver_packet_locked(const unsigned char *pkt, int pkt_len)
{
  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  if (otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                             dst_ip, sizeof(dst_ip), &dst_port, &proto) != 0)
    return; /* malformed reconstruction - nothing sane to log or process */

  static unsigned char outbuf[OTP_FW_MAX_PACKET];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = process_inbound_locked(pkt, pkt_len, src_ip, outbuf, sizeof(outbuf), &out_len,
                                             contact, sizeof(contact));

  if (r == OTP_FW_OK)
    otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
  else
    otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                          proto, otp_fw_result_reason(r));
}

/* ack_scan_timeouts() callback (see ack.h) - identical reasoning to
 * otp_firewalld.c's retry_outstanding_message(): resend the exact kept
 * ciphertext via keychain_recover_last(), never a fresh encrypt. Called
 * with g_state_lock already held (from AckThreadProc below). */
static void retry_outstanding_message_locked(const AckSlot *slot, void *user_data)
{
  UNREFERENCED_PARAMETER(user_data);

  char *cipherbuf = NULL;
  size_t cipherlen = 0;
  FILE *outf = open_memstream(&cipherbuf, &cipherlen);
  if (!outf)
    return;
  int rc = keychain_recover_last(slot->contact, /*sent=*/1, outf);
  fclose(outf);

  if (rc != 0)
  {
    free(cipherbuf);
    fprintf(stderr, "Warning: no kept ciphertext to retry for '%s' - it may have been removed\n", slot->contact);
    return;
  }

  if (ack_socket_send_redeliver(slot->dest_ip, slot->family, slot->header, slot->header_len,
                                (const unsigned char *)cipherbuf, (int)cipherlen) == 0)
    ack_touch_retry(&g_ctx.acks, slot->contact);
  else
    fprintf(stderr, "Warning: failed to send delivery retry to '%s'\n", slot->contact);

  free(cipherbuf);
}

static void drain_ack_socket_locked(int fd)
{
  /* static: AckRecvResult embeds a 70000-byte reconstruction buffer
   * (OTP_FW_ACK_MAX_REDELIVER) - see otp_firewalld.c's identical reasoning for
   * why this must not be a stack local. */
  static AckRecvResult res;
  for (;;)
  {
    int rc = ack_socket_recv(fd, &res);
    if (rc <= 0)
      return;

    if (res.type == OTP_FW_ACK_PKT_ACK)
    {
      for (int i = 0; i < g_ctx.acks.count; i++)
        if (ack_clear_if_matching(&g_ctx.acks, g_ctx.acks.slots[i].contact, res.source_id))
          break;
    }
    else if (res.type == OTP_FW_ACK_PKT_REDELIVER)
    {
      handle_redeliver_packet_locked(res.reconstructed, res.reconstructed_len);
    }
  }
}

/* Drives the delivery-acknowledgment mechanism (see ack.h): unlike
 * Linux's select()-based main loop, this uses WinSock's own select()
 * with a short timeout as a simple poll-and-tick primitive, since this
 * thread has nothing else to wait on besides the two ack sockets and
 * the stop event. */
static DWORD WINAPI AckThreadProc(LPVOID unused)
{
  UNREFERENCED_PARAMETER(unused);

  for (;;)
  {
    if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0)
      return 0;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET((SOCKET)g_ack_fd4, &rfds);
    SOCKET maxfd = (SOCKET)g_ack_fd4;
    if (g_ack_fd6 >= 0)
    {
      FD_SET((SOCKET)g_ack_fd6, &rfds);
      if ((SOCKET)g_ack_fd6 > maxfd)
        maxfd = (SOCKET)g_ack_fd6;
    }

    struct timeval tv;
    tv.tv_sec = OTP_FW_ACK_TICK_MS / 1000;
    tv.tv_usec = (OTP_FW_ACK_TICK_MS % 1000) * 1000;
    int nready = select((int)maxfd + 1, &rfds, NULL, NULL, &tv);

    EnterCriticalSection(&g_state_lock);
    if (nready > 0)
    {
      if (FD_ISSET((SOCKET)g_ack_fd4, &rfds))
        drain_ack_socket_locked(g_ack_fd4);
      if (g_ack_fd6 >= 0 && FD_ISSET((SOCKET)g_ack_fd6, &rfds))
        drain_ack_socket_locked(g_ack_fd6);
    }
    /* Timeouts are scanned on every loop iteration regardless of
     * whether select() found anything readable - the whole point of
     * the short select() timeout above is to guarantee this runs
     * roughly every OTP_FW_ACK_TICK_MS, the same cadence otp_firewalld.c's
     * OTP_FW_TICK_INTERVAL_SECONDS drives on Linux. */
    ack_scan_timeouts(&g_ctx.acks, OTP_FW_ACK_DEFAULT_TIMEOUT_SECONDS, retry_outstanding_message_locked, NULL);
    LeaveCriticalSection(&g_state_lock);
  }
}

static DWORD WINAPI PacketThreadProc(LPVOID unused)
{
  UNREFERENCED_PARAMETER(unused);
  static otp_fw_dequeued_packet_t in_buf;
  static otp_fw_verdict_submission_t out_buf;

  for (;;)
  {
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(g_device, OTP_FW_IOCTL_DEQUEUE_PACKET,
                              NULL, 0, &in_buf, sizeof(in_buf), &bytes, NULL);
    if (!ok)
    {
      /* Expected on shutdown: ServiceCtrlHandler calls
       * CancelSynchronousIo() on this thread to unblock exactly this
       * call, which surfaces as ERROR_OPERATION_ABORTED. Any other
       * failure is logged and this thread exits - the service as a
       * whole is then only as healthy as SCM's restart policy makes
       * it, same "let it crash and restart cleanly rather than spin in
       * a broken loop" posture as the other daemons' unrecoverable-error
       * paths. */
      DWORD err = GetLastError();
      if (err != ERROR_OPERATION_ABORTED && err != ERROR_INVALID_HANDLE)
        fprintf(stderr, "Error: DeviceIoControl(DEQUEUE_PACKET) failed: %lu\n", err);
      return 0;
    }
    if (bytes < sizeof(in_buf))
      continue; /* short read: shouldn't happen with METHOD_BUFFERED, but never process a partial packet */

    RtlZeroMemory(&out_buf, sizeof(out_buf));
    process_packet(&in_buf, &out_buf);

    DWORD verdict_bytes = 0;
    if (!DeviceIoControl(g_device, OTP_FW_IOCTL_SUBMIT_VERDICT,
                         &out_buf, sizeof(out_buf), NULL, 0, &verdict_bytes, NULL))
    {
      /* Unlike DEQUEUE_PACKET's failure, this one must not be silent:
       * if the driver never gets this verdict, it never calls
       * FwpsCompleteOperation0() for the pended classify, and the
       * underlying connection hangs with nothing else to explain why. */
      fprintf(stderr, "Error: DeviceIoControl(SUBMIT_VERDICT) failed for packet_id=%llu: %lu\n",
             (unsigned long long)out_buf.packet_id, GetLastError());
    }
  }
}

static DWORD WINAPI ReloadThreadProc(LPVOID unused)
{
  UNREFERENCED_PARAMETER(unused);
  for (;;)
  {
    DWORD wait = WaitForSingleObject(g_stop_event, (DWORD)g_resolve_interval_ms);
    if (wait == WAIT_OBJECT_0)
      return 0; /* stop requested */
    reload_config_and_push();
  }
}

static VOID WINAPI ServiceCtrlHandler(DWORD ctrl)
{
  if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
  {
    /* SCM can plausibly deliver both STOP and SHUTDOWN to the same
     * process (e.g. a stop requested right as the machine powers off);
     * only the first call should act; a second must not re-signal an
     * already-set manual-reset event (harmless) or re-cancel I/O on a
     * thread that may already be gone (not harmless). */
    if (InterlockedCompareExchange(&g_stop_requested, 1, 0) != 0)
      return;

    g_status.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_status_handle, &g_status);
    SetEvent(g_stop_event);
    /* CancelSynchronousIo(), not CloseHandle(), to unblock
     * PacketThreadProc's pending synchronous DeviceIoControl from this
     * other thread: closing a HANDLE that another thread is actively
     * blocked on is documented as unsafe, and doing so here would also
     * leave g_device holding a stale/closed value that ServiceMain's
     * own cleanup path (which now owns closing g_device) would double-close.
     * g_packet_thread may still be NULL if a stop arrives before
     * ServiceMain gets around to creating it. */
    if (g_packet_thread)
      CancelSynchronousIo(g_packet_thread);
  }
}

static int startup(void)
{
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
  {
    fprintf(stderr, "Error: WSAStartup failed\n");
    return -1;
  }
  g_wsa_started = TRUE;

  memset(&g_ctx, 0, sizeof(g_ctx));
  fwconfig_init(&g_ctx.cfg);
  pin_init(&g_ctx.pins);
  ack_table_init(&g_ctx.acks);
  InitializeCriticalSection(&g_state_lock);
  g_crit_initialized = TRUE;

  if (otp_fw_setup_keychain_dir() != 0)
    return -1;
  if (get_keychain_dir(g_ctx.keychain_dir, sizeof(g_ctx.keychain_dir)) != 0)
    return -1;
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: failed to load keychain\n");
    return -1;
  }
  /* Required for the same reason otp_firewalld.c documents at length: without
   * this, encrypt/decrypt_with_contact() block on an interactive
   * delivery-confirmation prompt this service, with no console, could
   * never answer. Genuinely true by the time it's consulted, though,
   * not a blind assumption - see ack.h's file header. */
  keychain_set_assume_delivered(1);
  cipher_set_ack_file(1);

  if (otp_fw_log_init() != 0)
    return -1;

  /* AF_INET must succeed - see otp_firewalld.c's identical reasoning. AF_INET6
   * is best-effort. */
  g_ack_fd4 = ack_socket_open(AF_INET);
  if (g_ack_fd4 < 0)
  {
    fprintf(stderr, "Error: could not open the IPv4 delivery-ack socket on port %d: %d\n",
           OTP_FW_ACK_PORT, WSAGetLastError());
    return -1;
  }
  g_ack_fd6 = ack_socket_open(AF_INET6);
  if (g_ack_fd6 < 0)
    fprintf(stderr, "Warning: could not open the IPv6 delivery-ack socket - IPv6 contacts will send without delivery tracking\n");

  snprintf(g_config_path, sizeof(g_config_path), "%s", OTP_FW_CONFIG_NAME); /* relative to ~/.otp, per the chdir inside otp_fw_setup_keychain_dir() */
  reload_config_and_push();

  /* Crash/restart recovery - see ack.h's ack_recover_outstanding() doc
   * comment and otp_firewalld.c's identical call. Must run before the device is
   * opened and any real traffic is processed. */
  ack_recover_outstanding(&g_ctx.acks, &g_ctx.cfg);

  g_device = CreateFileA(OTP_FW_WIN32_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (g_device == INVALID_HANDLE_VALUE)
  {
    fprintf(stderr, "Error: cannot open %s (driver not loaded/started?): %lu\n",
           OTP_FW_WIN32_DEVICE_PATH, GetLastError());
    return -1;
  }
  return 0;
}

static VOID WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
  UNREFERENCED_PARAMETER(argc);
  UNREFERENCED_PARAMETER(argv);

  g_status_handle = RegisterServiceCtrlHandlerW(OTP_FW_SVC_NAME, ServiceCtrlHandler);
  if (!g_status_handle)
    return;

  ZeroMemory(&g_status, sizeof(g_status));
  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwCurrentState = SERVICE_START_PENDING;
  g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  SetServiceStatus(g_status_handle, &g_status);

  g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);

  if (startup() != 0)
  {
    /* startup() can fail after WSAStartup()/InitializeCriticalSection()
     * already succeeded (e.g. the driver isn't loaded yet, so the final
     * CreateFileA on \\.\OTPFirewall fails) - clean those up here too,
     * mirroring the success-path cleanup below, rather than only
     * reaching them via the post-thread-join path further down. SCM's
     * restart policy means this path can run repeatedly. */
    if (g_device != INVALID_HANDLE_VALUE)
    {
      CloseHandle(g_device);
      g_device = INVALID_HANDLE_VALUE;
    }
    if (g_ack_fd4 >= 0)
    {
      closesocket((SOCKET)g_ack_fd4);
      g_ack_fd4 = -1;
    }
    if (g_ack_fd6 >= 0)
    {
      closesocket((SOCKET)g_ack_fd6);
      g_ack_fd6 = -1;
    }
    fwconfig_free(&g_ctx.cfg);
    cleanup_keychain();
    if (g_crit_initialized)
      DeleteCriticalSection(&g_state_lock);
    if (g_wsa_started)
      WSACleanup();
    CloseHandle(g_stop_event);

    g_status.dwCurrentState = SERVICE_STOPPED;
    g_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    g_status.dwServiceSpecificExitCode = 1;
    SetServiceStatus(g_status_handle, &g_status);
    return;
  }

  g_status.dwCurrentState = SERVICE_RUNNING;
  SetServiceStatus(g_status_handle, &g_status);

  g_packet_thread = CreateThread(NULL, 0, PacketThreadProc, NULL, 0, NULL);
  g_reload_thread = CreateThread(NULL, 0, ReloadThreadProc, NULL, 0, NULL);
  g_ack_thread = CreateThread(NULL, 0, AckThreadProc, NULL, 0, NULL);

  HANDLE waitables[3] = {g_packet_thread, g_reload_thread, g_ack_thread};
  WaitForMultipleObjects(3, waitables, TRUE, INFINITE);

  CloseHandle(g_packet_thread);
  CloseHandle(g_reload_thread);
  CloseHandle(g_ack_thread);
  CloseHandle(g_stop_event);
  if (g_device != INVALID_HANDLE_VALUE)
  {
    CloseHandle(g_device);
    g_device = INVALID_HANDLE_VALUE;
  }
  if (g_ack_fd4 >= 0)
  {
    closesocket((SOCKET)g_ack_fd4);
    g_ack_fd4 = -1;
  }
  if (g_ack_fd6 >= 0)
  {
    closesocket((SOCKET)g_ack_fd6);
    g_ack_fd6 = -1;
  }
  fwconfig_free(&g_ctx.cfg);
  cleanup_keychain();
  DeleteCriticalSection(&g_state_lock);
  WSACleanup();

  g_status.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(g_status_handle, &g_status);
}

int wmain(void)
{
  SERVICE_TABLE_ENTRYW table[] = {
      {(LPWSTR)OTP_FW_SVC_NAME, ServiceMain},
      {NULL, NULL}};
  if (!StartServiceCtrlDispatcherW(table))
  {
    fprintf(stderr, "Error: this executable must be started by the Service Control Manager "
                    "(see ../README.md: sc create / sc start), not run directly.\n");
    return 1;
  }
  return 0;
}
