/*
 * otp_firewall_svc.c - Windows equivalent of firewall/daemon/main.c:
 * a Windows Service that plays the same role otp-firewalld plays on
 * Linux and the System Extension plays on macOS - startup
 * (keychain/config/log init), then a loop moving packets between the
 * kernel driver and the unmodified cipher.c/keychain.c library via
 * packet_codec_windows.c.
 *
 * UNVERIFIED - not built or run against a real Windows toolchain; see
 * ../README.md's confidence table.
 *
 * One genuine structural difference from Linux's main.c, not just a
 * syntax port, called out here rather than left implicit: Linux's
 * daemon is single-threaded by construction (SIGALRM interrupts a
 * blocking recv() via EINTR - see main.c's own comment on why
 * sigaction() without SA_RESTART matters). OTP_FW_IOCTL_DEQUEUE_PACKET
 * is a synchronous, blocking DeviceIoControl() call with no equivalent
 * "signal interrupts a blocked syscall" mechanism, so periodic config
 * reload here genuinely needs a second thread - which in turn means
 * every access to g_keychain (a bare global in keychain.c, not
 * thread-safe) and to FwContext must be serialized with an explicit
 * CRITICAL_SECTION. Neither of the other two platforms needs this:
 * Linux's signal-interrupt model and macOS's NEPacketTunnelProvider
 * packet-handling queue both already serialize everything that would
 * otherwise race.
 */

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

#include "../Driver/otp_firewall_protocol.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OTP_FW_SVC_NAME L"OTPFirewall"
#define OTP_FW_DEFAULT_RESOLVE_INTERVAL_MS (60 * 1000)

typedef struct
{
  FwConfig cfg;
  PinTable pins;
  char keychain_dir[512];
} FwContext;

static FwContext g_ctx;
static CRITICAL_SECTION g_state_lock; /* guards g_ctx and every g_keychain access - see file header */
static char g_config_path[1024];
static int g_resolve_interval_ms = OTP_FW_DEFAULT_RESOLVE_INTERVAL_MS;
static HANDLE g_stop_event;
static HANDLE g_packet_thread;
static HANDLE g_reload_thread;
static HANDLE g_device = INVALID_HANDLE_VALUE; /* opened once in startup(), closed once from ServiceMain's own cleanup path after both worker threads have exited */
static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS g_status;
static volatile LONG g_stop_requested = 0; /* guards ServiceCtrlHandler against SCM delivering STOP and SHUTDOWN back to back */
static BOOL g_wsa_started = FALSE;   /* only WSACleanup() if WSAStartup() actually succeeded */
static BOOL g_crit_initialized = FALSE; /* only DeleteCriticalSection() if InitializeCriticalSection() actually ran */

/* Mirrors main.c's reconcile_pins_with_config() exactly (same
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

/* Mirrors main.c's reload_config_and_push(), including the keychain
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
  otp_fw_kernel_push_candidates(&g_ctx.cfg);
  LeaveCriticalSection(&g_state_lock);
}

static const wchar_t *widen_dir(otp_fw_pkt_direction_t d)
{
  return d == OTP_FW_PKT_OUTBOUND ? L"egress" : L"ingress";
}

/* Runs one dequeued packet through the same egress/ingress logic
 * main.c's egress_cb()/ingress_cb() run, and fills in `verdict` for
 * OTP_FW_IOCTL_SUBMIT_VERDICT. Holds g_state_lock for the whole call:
 * every path through here touches g_keychain (via
 * otp_fw_encrypt_packet/otp_fw_decrypt_packet) and/or g_ctx (cfg,
 * pins), same reasoning as reload_config_and_push() above. */
static void process_packet(const otp_fw_dequeued_packet_t *in, otp_fw_verdict_submission_t *out)
{
  char narrow_dir[8];
  snprintf(narrow_dir, sizeof(narrow_dir), "%s", in->direction == OTP_FW_PKT_OUTBOUND ? "egress" : "ingress");
  (void)widen_dir;

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
    int out_len = 0;
    r = otp_fw_encrypt_packet(g_ctx.keychain_dir, &g_ctx.cfg, in->data, (int)in->data_len,
                              out->data, sizeof(out->data), &out_len, contact, sizeof(contact));
    if (r == OTP_FW_OK)
    {
      otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);
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
    /* Same static-buffer reasoning as main.c's ingress_cb(): CandidateList
     * is too large (~2.5MB) for a stack local, and reusing one is safe
     * because trial_select_primary() rebuilds it from scratch every call
     * and g_state_lock already serializes all callers. */
    static CandidateList candidates;
    trial_select_primary(g_ctx.keychain_dir, &g_ctx.cfg, &g_ctx.pins, src_ip, &candidates);

    int out_len = 0;
    r = otp_fw_decrypt_packet(g_ctx.keychain_dir, &candidates, in->data, (int)in->data_len,
                              out->data, sizeof(out->data), &out_len, contact, sizeof(contact));

    if (r != OTP_FW_OK && !candidates.exclusive)
    {
      trial_add_fallback_scan(g_ctx.keychain_dir, &candidates);
      r = otp_fw_decrypt_packet(g_ctx.keychain_dir, &candidates, in->data, (int)in->data_len,
                                out->data, sizeof(out->data), &out_len, contact, sizeof(contact));
    }

    if (r == OTP_FW_OK)
    {
      if (pin_set(&g_ctx.pins, src_ip, contact) != 0)
        fprintf(stderr, "Warning: pin table full (%d entries) - '%s' will use the slower "
                        "trial path on every packet until a pin frees up\n",
               OTP_FW_MAX_PINS, src_ip);
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
  /* Required for the same reason main.c documents at length: without
   * this, encrypt/decrypt_with_contact() block on an interactive
   * delivery-confirmation prompt this service, with no console, could
   * never answer. */
  keychain_set_assume_delivered(1);

  if (otp_fw_log_init() != 0)
    return -1;

  snprintf(g_config_path, sizeof(g_config_path), "%s", OTP_FW_CONFIG_NAME); /* relative to ~/.otp, per the chdir inside otp_fw_setup_keychain_dir() */
  reload_config_and_push();

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

  HANDLE waitables[2] = {g_packet_thread, g_reload_thread};
  WaitForMultipleObjects(2, waitables, TRUE, INFINITE);

  CloseHandle(g_packet_thread);
  CloseHandle(g_reload_thread);
  CloseHandle(g_stop_event);
  if (g_device != INVALID_HANDLE_VALUE)
  {
    CloseHandle(g_device);
    g_device = INVALID_HANDLE_VALUE;
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
