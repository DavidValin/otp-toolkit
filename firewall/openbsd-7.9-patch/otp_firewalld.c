/*
 * otp_firewalld.c - OpenBSD port of firewall/linux-kernel-module/otp_firewalld.c: same
 * role (startup, config/keychain reload, the loop moving packets
 * between the kernel and packet_codec/cipher/keychain), but reading
 * candidate packets from /dev/otpfw (see kernel/otpfw.c) via
 * read()/write() instead of an NFQUEUE socket - functionally identical
 * to the FreeBSD port's own otp_firewalld.c, just talking to a
 * statically-compiled-in kernel hook (see README.md's "Why this is a
 * kernel patch, not a loadable module") instead of a loadable KLD.
 *
 * Single-threaded, SIGALRM-driven periodic reload - select() over
 * /dev/otpfw plus the two delivery-ack sockets (see ack.h), same EINTR/
 * SA_RESTART-omitted reasoning as every other platform's otp_firewalld.c.
 *
 * UNVERIFIED - see README.md's Status section. Unlike kernel/otpfw.c
 * itself (which needs real OpenBSD kernel headers this project doesn't
 * have access to), this file sticks to ordinary POSIX open()/read()/
 * write()/ioctl()/select() calls - see the Status section for how far
 * that verification actually goes here.
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

#include "otp_firewall_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h> /* AF_INET/AF_INET6 for ack_socket_open()/ack.h's family parameter */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define OTP_FW_DEFAULT_RESOLVE_INTERVAL 60

/* How often the main loop wakes up to check for ack timeouts (see
 * ack.h), independent of --resolve-interval - same reasoning as every
 * other platform's otp_firewalld.c: the default 5-second ack retry
 * timeout needs checking far more often than the default 60-second DNS
 * re-resolve interval, so this drives a short, fixed tick instead of
 * trying to run two independent alarm(2) timers. */
#define OTP_FW_TICK_INTERVAL_SECONDS 1

typedef struct
{
  FwConfig cfg;
  PinTable pins;
  AckTable acks;
  char keychain_dir[512];
  otp_fw_mode_t mode;
  int ack_timeout_seconds;
} FwContext;

static volatile sig_atomic_t g_resolve_due = 0;
static volatile sig_atomic_t g_shutdown = 0;

static void on_alarm(int sig)
{
  (void)sig;
  g_resolve_due = 1;
}

static void on_term(int sig)
{
  (void)sig;
  g_shutdown = 1;
}

/* A pin is invalidated here either because its contact no longer exists
 * in the (freshly reloaded, see reload_config_and_push()) keychain, or
 * because the config now EXPLICITLY maps its IP to a different contact -
 * an IP simply absent from the config (e.g. one that was only ever
 * reached via the fallback keychain scan) must keep its pin, per
 * ../README.md's "Incoming traffic" trial order. */
static void reconcile_pins_with_config(FwContext *ctx)
{
  for (int i = 0; i < ctx->pins.count; i++)
  {
    char ip[OTP_FW_IPSTR_LEN];
    char contact[MAX_NAME_LENGTH];
    snprintf(ip, sizeof(ip), "%s", ctx->pins.entries[i].ip);
    snprintf(contact, sizeof(contact), "%s", ctx->pins.entries[i].contact);

    if (!find_contact(contact))
    {
      pin_clear_ip(&ctx->pins, ip);
      i--;
      continue;
    }

    const char *configured = fwconfig_contact_for_ip(&ctx->cfg, ip);
    if (configured && strcmp(configured, contact) != 0)
    {
      pin_clear_ip(&ctx->pins, ip);
      i--;
    }
  }
}

/* Mirrors every other platform's reconcile_acks_with_keychain(): a stale
 * outstanding-ack slot (see ack.h) for a contact no longer in the
 * keychain is harmless but pointless to keep around. */
static void reconcile_acks_with_keychain(FwContext *ctx)
{
  for (int i = 0; i < ctx->acks.count; i++)
  {
    char contact[MAX_NAME_LENGTH];
    snprintf(contact, sizeof(contact), "%s", ctx->acks.slots[i].contact);
    if (!find_contact(contact))
    {
      ack_clear_contact(&ctx->acks, contact);
      i--;
    }
  }
}

/* Mirrors every other platform's reload_config_and_push() exactly,
 * including the keychain snapshot/restore-on-failure fix documented in
 * Linux's otp_firewalld.c in detail - see that file for why it's
 * load-bearing. */
static void reload_config_and_push(FwContext *ctx, const char *config_path)
{
  static Keychain keychain_snapshot;
  keychain_snapshot = g_keychain;
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Warning: failed to reload keychain - keeping the previous in-memory state\n");
    g_keychain = keychain_snapshot;
  }

  if (fwconfig_load(config_path, &ctx->cfg) == 0)
    fwconfig_resolve(&ctx->cfg);
  reconcile_pins_with_config(ctx);
  reconcile_acks_with_keychain(ctx);
  otp_fw_kernel_push_candidates(&ctx->cfg);
}

/* Shared by the main loop's ingress branch (a normal candidate packet
 * from /dev/otpfw) and handle_redeliver_packet() (a packet reconstructed
 * from an ack-port REDELIVER, see ack.h) - both need exactly the same
 * trial-decrypt/pin/ack-send logic. On OTP_FW_OK, also sends the
 * delivery ack back to `src_ip` - the receiving half of the same
 * mechanism the egress branch's ack_mark_outstanding() call is the
 * sending half of. */
static otp_fw_result_t process_ingress_packet(FwContext *ctx, const unsigned char *pkt, int pkt_len,
                                              const char *src_ip, unsigned char *out_data, int out_cap,
                                              int *out_len, char *contact_out, size_t contact_out_size)
{
  /* static: CandidateList is too large for a stack local - see every
   * other platform's matching comment. Safe to share: trial_select_primary()
   * rebuilds it from scratch every call and this daemon is
   * single-threaded. */
  static CandidateList candidates;
  trial_select_primary(ctx->keychain_dir, &ctx->cfg, &ctx->pins, src_ip, &candidates);

  otp_fw_result_t r;
  if (ctx->mode == OTP_FW_MODE_LOGONLY)
    r = otp_fw_classify_ingress(&candidates, contact_out, contact_out_size);
  else
    r = otp_fw_decrypt_packet(ctx->keychain_dir, &candidates, pkt, pkt_len,
                              out_data, out_cap, out_len, contact_out, contact_out_size);

  int primary_failed = (ctx->mode == OTP_FW_MODE_LOGONLY) ? (r == OTP_FW_NO_CONTACT) : (r != OTP_FW_OK);
  if (primary_failed && !candidates.exclusive)
  {
    trial_add_fallback_scan(ctx->keychain_dir, &candidates);
    if (ctx->mode == OTP_FW_MODE_LOGONLY)
      r = otp_fw_classify_ingress(&candidates, contact_out, contact_out_size);
    else
      r = otp_fw_decrypt_packet(ctx->keychain_dir, &candidates, pkt, pkt_len,
                                out_data, out_cap, out_len, contact_out, contact_out_size);
  }

  if (r == OTP_FW_OK)
  {
    if (pin_set(&ctx->pins, src_ip, contact_out) != 0)
      fprintf(stderr, "Warning: pin table full (%d entries) - '%s' will use the slower "
                      "trial path on every packet until a pin frees up\n",
             OTP_FW_MAX_PINS, src_ip);

    if (ctx->mode == OTP_FW_MODE_ENFORCE)
    {
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
  }

  return r;
}

/* Handles one REDELIVER packet from the ack socket (see ack.h):
 * reconstructed IP+L4 header + ciphertext, run through the same
 * trial-decrypt logic a normal candidate packet would use. From the
 * protocol's point of view this is indistinguishable from the original
 * packet having simply arrived late - its only purpose is getting this
 * contact's DecryptionKeyOffset back in sync and (on success, inside
 * process_ingress_packet()) triggering the ack send back to the sender.
 * There is no verdict to write: this never came from the kernel queue
 * and nothing is waiting on it to be forwarded anywhere. */
static void handle_redeliver_packet(FwContext *ctx, const unsigned char *pkt, int pkt_len)
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
  otp_fw_result_t r = process_ingress_packet(ctx, pkt, pkt_len, src_ip, outbuf, sizeof(outbuf),
                                             &out_len, contact, sizeof(contact));

  if (r == OTP_FW_OK)
    otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
  else
    otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                          proto, otp_fw_result_reason(r));
}

/* ack_scan_timeouts() callback (see ack.h) - resends the exact kept
 * ciphertext for a message that's gone unacknowledged past the retry
 * timeout, via keychain_recover_last() - never a fresh encrypt, which
 * would spend new key material and, worse, a NEW offset the receiver
 * (still stuck expecting the OLD one) could never match. */
static void retry_outstanding_message(const AckSlot *slot, void *user_data)
{
  FwContext *ctx = (FwContext *)user_data;

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
  {
    ack_touch_retry(&ctx->acks, slot->contact);
    fprintf(stderr, "Info: retried unacknowledged message to '%s' (no ack within %d seconds)\n",
           slot->contact, ctx->ack_timeout_seconds);
  }
  else
  {
    fprintf(stderr, "Warning: failed to send delivery retry to '%s'\n", slot->contact);
  }
  free(cipherbuf);
}

/* Drains every packet currently queued on the ack socket (see ack.h),
 * non-blocking - called once per select() readability notification, but
 * loops until EAGAIN rather than reading just one, matching every other
 * platform's identical reasoning. */
static void drain_ack_socket(FwContext *ctx, int fd)
{
  /* static: AckRecvResult embeds a 70000-byte reconstruction buffer
   * (OTP_FW_ACK_MAX_REDELIVER) - see every other platform's identical
   * reasoning for why this must not be a stack local. */
  static AckRecvResult res;
  for (;;)
  {
    int rc = ack_socket_recv(fd, &res);
    if (rc <= 0)
      return;

    if (res.type == OTP_FW_ACK_PKT_ACK)
    {
      for (int i = 0; i < ctx->acks.count; i++)
        if (ack_clear_if_matching(&ctx->acks, ctx->acks.slots[i].contact, res.source_id))
          break;
    }
    else if (res.type == OTP_FW_ACK_PKT_REDELIVER)
    {
      handle_redeliver_packet(ctx, res.reconstructed, res.reconstructed_len);
    }
  }
}

static void usage(const char *argv0)
{
  fprintf(stderr,
         "Usage: %s [--mode=enforce|log-only] [--config=PATH] [--resolve-interval=SECONDS]\n"
         "          [--ack-timeout=SECONDS]\n",
         argv0);
}

int main(int argc, char **argv)
{
  otp_fw_mode_t mode = OTP_FW_MODE_ENFORCE;
  int resolve_interval = OTP_FW_DEFAULT_RESOLVE_INTERVAL;
  int ack_timeout = OTP_FW_ACK_DEFAULT_TIMEOUT_SECONDS;
  char config_path_override[1024] = {0};

  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "--mode=enforce") == 0)
      mode = OTP_FW_MODE_ENFORCE;
    else if (strcmp(argv[i], "--mode=log-only") == 0)
      mode = OTP_FW_MODE_LOGONLY;
    else if (strncmp(argv[i], "--config=", 9) == 0)
      snprintf(config_path_override, sizeof(config_path_override), "%s", argv[i] + 9);
    else if (strncmp(argv[i], "--resolve-interval=", 19) == 0)
      resolve_interval = atoi(argv[i] + 19);
    else if (strncmp(argv[i], "--ack-timeout=", 14) == 0)
      ack_timeout = atoi(argv[i] + 14);
    else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
    {
      usage(argv[0]);
      return 0;
    }
    else
    {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      usage(argv[0]);
      return 1;
    }
  }
  if (ack_timeout <= 0)
  {
    fprintf(stderr, "Error: --ack-timeout must be a positive number of seconds\n");
    return 1;
  }

  FwContext ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.mode = mode;
  ctx.ack_timeout_seconds = ack_timeout;
  fwconfig_init(&ctx.cfg);
  pin_init(&ctx.pins);
  ack_table_init(&ctx.acks);

  if (otp_fw_setup_keychain_dir() != 0)
    return 1;
  if (get_keychain_dir(ctx.keychain_dir, sizeof(ctx.keychain_dir)) != 0)
    return 1;
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: failed to load keychain\n");
    return 1;
  }
  /* Required for the same reason every other platform's otp_firewalld.c
   * documents at length: without this, encrypt/decrypt_with_contact()
   * block on an interactive delivery-confirmation prompt this daemon,
   * with no terminal, can never answer. Genuinely true by the time it's
   * consulted, though, not a blind assumption - see ack.h's file header. */
  keychain_set_assume_delivered(1);
  cipher_set_ack_file(1);

  if (otp_fw_log_init() != 0)
    return 1;

  /* AF_INET must succeed - see every other platform's identical
   * reasoning. AF_INET6 is best-effort. */
  int ack_fd4 = ack_socket_open(AF_INET);
  if (ack_fd4 < 0)
  {
    fprintf(stderr, "Error: could not open the IPv4 delivery-ack socket on port %d: %s\n",
           OTP_FW_ACK_PORT, strerror(errno));
    return 1;
  }
  int ack_fd6 = ack_socket_open(AF_INET6);
  if (ack_fd6 < 0)
    fprintf(stderr, "Warning: could not open the IPv6 delivery-ack socket - IPv6 contacts will send without delivery tracking\n");

  char config_path[1024];
  if (config_path_override[0])
    snprintf(config_path, sizeof(config_path), "%s", config_path_override);
  else
    snprintf(config_path, sizeof(config_path), "%s", OTP_FW_CONFIG_NAME); /* relative to ~/.otp, per the chdir inside otp_fw_setup_keychain_dir() */

  reload_config_and_push(&ctx, config_path);

  /* Crash/restart recovery - see ack.h's ack_recover_outstanding() doc
   * comment. Must run before the device is opened and any real traffic
   * is processed. */
  ack_recover_outstanding(&ctx.acks, &ctx.cfg);

  int fd = open(OTP_FW_DEVICE_PATH, O_RDWR);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot open %s (kernel built without `pseudo-device otpfw`? "
                    "not running as root? - see README.md's \"Kernel integration\"): %s\n",
           OTP_FW_DEVICE_PATH, strerror(errno));
    return 1;
  }

  /* sigaction() with sa_flags=0 (SA_RESTART deliberately omitted), same
   * reasoning as every other platform: this relies on select() actually
   * returning EINTR so the periodic tick below runs and shutdown doesn't
   * stall until the next packet. */
  struct sigaction sa_alarm, sa_term;
  memset(&sa_alarm, 0, sizeof(sa_alarm));
  sa_alarm.sa_handler = on_alarm;
  sigaction(SIGALRM, &sa_alarm, NULL);
  memset(&sa_term, 0, sizeof(sa_term));
  sa_term.sa_handler = on_term;
  sigaction(SIGTERM, &sa_term, NULL);
  sigaction(SIGINT, &sa_term, NULL);
  alarm(OTP_FW_TICK_INTERVAL_SECONDS);

  time_t last_resolve = time(NULL);
  fprintf(stderr, "otp_firewalld: running (mode=%s, ack-timeout=%ds)\n",
         mode == OTP_FW_MODE_ENFORCE ? "enforce" : "log-only", ack_timeout);

  static otp_fw_dequeued_packet_t in_buf;
  static otp_fw_verdict_submission_t out_buf;

  while (!g_shutdown)
  {
    /* Checked unconditionally at the top of every iteration, not only
     * inside the EINTR branch - same reasoning as every other platform:
     * under sustained traffic, select() keeps finding data ready and
     * returns normally rather than blocking, so a SIGALRM landing
     * mid-select() (or mid packet-processing) would otherwise never get
     * picked up again for the rest of the process's life. */
    if (g_resolve_due)
    {
      g_resolve_due = 0;
      ack_scan_timeouts(&ctx.acks, ctx.ack_timeout_seconds, retry_outstanding_message, &ctx);

      time_t now = time(NULL);
      if (resolve_interval > 0 && now - last_resolve >= resolve_interval)
      {
        reload_config_and_push(&ctx, config_path);
        last_resolve = now;
      }
      alarm(OTP_FW_TICK_INTERVAL_SECONDS);
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    FD_SET(ack_fd4, &rfds);
    int maxfd = fd > ack_fd4 ? fd : ack_fd4;
    if (ack_fd6 >= 0)
    {
      FD_SET(ack_fd6, &rfds);
      if (ack_fd6 > maxfd)
        maxfd = ack_fd6;
    }

    int nready = select(maxfd + 1, &rfds, NULL, NULL, NULL);
    if (nready < 0)
    {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "Error: select() failed: %s\n", strerror(errno));
      break;
    }

    if (FD_ISSET(ack_fd4, &rfds))
      drain_ack_socket(&ctx, ack_fd4);
    if (ack_fd6 >= 0 && FD_ISSET(ack_fd6, &rfds))
      drain_ack_socket(&ctx, ack_fd6);

    if (!FD_ISSET(fd, &rfds))
      continue;

    ssize_t n = read(fd, &in_buf, sizeof(in_buf));
    if (n < 0)
    {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "Error: read() failed: %s\n", strerror(errno));
      break;
    }
    if (n != (ssize_t)sizeof(in_buf))
      continue; /* short read: shouldn't happen with this device's uiomove() contract, but never process a partial packet */

    char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
    unsigned src_port, dst_port;
    const char *proto;
    otp_fw_describe_packet(in_buf.data, (int)in_buf.data_len, src_ip, sizeof(src_ip), &src_port,
                          dst_ip, sizeof(dst_ip), &dst_port, &proto);

    memset(&out_buf, 0, sizeof(out_buf));
    out_buf.packet_id = in_buf.packet_id;
    char contact[MAX_NAME_LENGTH] = {0};
    otp_fw_result_t r;

    if (in_buf.direction == OTP_FW_PKT_OUTBOUND)
    {
      /* Free (no key spent) contact resolution first, so the
       * delivery-ack gate (see ack.h) can reject a packet BEFORE ever
       * calling the real, key-spending encrypt - see every other
       * platform's identical reasoning. log-only must never call the
       * real encrypt_with_contact() either, for the usual reason
       * (spends real key material for output that's about to be
       * discarded). */
      r = otp_fw_classify_egress(ctx.keychain_dir, &ctx.cfg, in_buf.data, (int)in_buf.data_len, contact, sizeof(contact));
      int out_len = 0;
      if (r == OTP_FW_OK && ctx.mode == OTP_FW_MODE_ENFORCE)
      {
        if (!ack_egress_allowed(&ctx.acks, contact))
          r = OTP_FW_ACK_PENDING;
        else
          r = otp_fw_encrypt_packet(ctx.keychain_dir, &ctx.cfg, in_buf.data, (int)in_buf.data_len,
                                    out_buf.data, sizeof(out_buf.data), &out_len, contact, sizeof(contact));
      }

      if (r == OTP_FW_OK)
      {
        otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);

        if (ctx.mode == OTP_FW_MODE_ENFORCE)
        {
          /* Track this message for delivery acknowledgment - see every
           * other platform's identical reasoning. */
          int header_len = otp_fw_header_length(in_buf.data, (int)in_buf.data_len);
          Contact *c = find_contact(contact);
          unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN];
          if (header_len > 0 && c &&
             ack_read_source_id_file(contact, c->EncryptedSequence, 1, source_id) == 0)
          {
            int family = strchr(dst_ip, ':') ? AF_INET6 : AF_INET;
            if (ack_mark_outstanding(&ctx.acks, contact, c->EncryptedSequence, source_id, dst_ip, family, in_buf.data, header_len) != 0)
              fprintf(stderr, "Warning: ack table full - '%s' will send without delivery tracking until a slot frees up\n", contact);
          }
          else
          {
            fprintf(stderr, "Warning: could not capture delivery-ack reference for '%s' - sending without tracking\n", contact);
          }
        }

        out_buf.verdict = (ctx.mode == OTP_FW_MODE_ENFORCE) ? OTP_FW_VERDICT_FORWARD_MODIFIED : OTP_FW_VERDICT_FORWARD_ORIGINAL;
        out_buf.data_len = (uint32_t)out_len;
      }
      else
      {
        otp_fw_log_restricted("egress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                              proto, otp_fw_result_reason(r));
        out_buf.verdict = (ctx.mode == OTP_FW_MODE_LOGONLY) ? OTP_FW_VERDICT_FORWARD_ORIGINAL : OTP_FW_VERDICT_DROP;
      }
    }
    else
    {
      int out_len = 0;
      r = process_ingress_packet(&ctx, in_buf.data, (int)in_buf.data_len, src_ip,
                                 out_buf.data, sizeof(out_buf.data), &out_len, contact, sizeof(contact));

      if (r == OTP_FW_OK)
      {
        otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
        out_buf.verdict = (ctx.mode == OTP_FW_MODE_ENFORCE) ? OTP_FW_VERDICT_FORWARD_MODIFIED : OTP_FW_VERDICT_FORWARD_ORIGINAL;
        out_buf.data_len = (uint32_t)out_len;
      }
      else
      {
        otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                              proto, otp_fw_result_reason(r));
        out_buf.verdict = (ctx.mode == OTP_FW_MODE_LOGONLY) ? OTP_FW_VERDICT_FORWARD_ORIGINAL : OTP_FW_VERDICT_DROP;
      }
    }

    if (write(fd, &out_buf, sizeof(out_buf)) != (ssize_t)sizeof(out_buf))
      fprintf(stderr, "Error: write() verdict failed for packet_id=%llu: %s\n",
             (unsigned long long)out_buf.packet_id, strerror(errno));
  }

  close(fd);
  close(ack_fd4);
  if (ack_fd6 >= 0)
    close(ack_fd6);
  fwconfig_free(&ctx.cfg);
  cleanup_keychain();
  return 0;
}
