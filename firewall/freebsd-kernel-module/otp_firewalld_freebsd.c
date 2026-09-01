/*
 * otp_firewalld_freebsd.c - FreeBSD port of firewall/daemon/main.c: same
 * role (startup, config/keychain reload, the loop moving packets
 * between the kernel and packet_codec/cipher/keychain), but reading
 * candidate packets from /dev/otp_firewall via read()/write() instead of
 * an NFQUEUE socket.
 *
 * Unlike the Windows port, this does NOT need a second thread: FreeBSD's
 * read() on a blocking cdev returns EINTR on a delivered signal with no
 * SA_RESTART, exactly like Linux's recv() on an NFQUEUE socket - so the
 * same single-threaded, SIGALRM-driven periodic-reload design from
 * firewall/daemon/main.c ports over directly. This file is close to a
 * line-for-line adaptation of main.c with the NFQUEUE-specific pieces
 * (nfq_open/nfq_create_queue/nfq_handle_packet) replaced by
 * open()/read()/write()/ioctl() on /dev/otp_firewall - every other piece
 * (the keychain-snapshot/restore-on-failure fix, the pin-reconciliation
 * logic, the log-only vs enforce split) is unchanged in shape.
 *
 * UNVERIFIED - see ../README.md.
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

#include "otp_firewall_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define OTP_FW_DEFAULT_RESOLVE_INTERVAL 60

typedef struct
{
  FwConfig cfg;
  PinTable pins;
  char keychain_dir[512];
  otp_fw_mode_t mode;
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

/* Mirrors main.c's reload_config_and_push() exactly, including the
 * keychain snapshot/restore-on-failure fix documented there in detail -
 * see that file for why it's load-bearing. */
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
  otp_fw_kernel_push_candidates(&ctx->cfg);
}

static void usage(const char *argv0)
{
  fprintf(stderr,
         "Usage: %s [--mode=enforce|log-only] [--config=PATH] [--resolve-interval=SECONDS]\n",
         argv0);
}

int main(int argc, char **argv)
{
  otp_fw_mode_t mode = OTP_FW_MODE_ENFORCE;
  int resolve_interval = OTP_FW_DEFAULT_RESOLVE_INTERVAL;
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

  FwContext ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.mode = mode;
  fwconfig_init(&ctx.cfg);
  pin_init(&ctx.pins);

  if (otp_fw_setup_keychain_dir() != 0)
    return 1;
  if (get_keychain_dir(ctx.keychain_dir, sizeof(ctx.keychain_dir)) != 0)
    return 1;
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: failed to load keychain\n");
    return 1;
  }
  /* Required for the same reason main.c documents at length: without
   * this, encrypt/decrypt_with_contact() block on an interactive
   * delivery-confirmation prompt this daemon, with no terminal, can
   * never answer. */
  keychain_set_assume_delivered(1);

  if (otp_fw_log_init() != 0)
    return 1;

  char config_path[1024];
  if (config_path_override[0])
    snprintf(config_path, sizeof(config_path), "%s", config_path_override);
  else
    snprintf(config_path, sizeof(config_path), "%s", OTP_FW_CONFIG_NAME); /* relative to ~/.otp, per the chdir inside otp_fw_setup_keychain_dir() */

  reload_config_and_push(&ctx, config_path);

  int fd = open(OTP_FW_DEVICE_PATH, O_RDWR);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot open %s (kernel module not loaded?): %s\n",
           OTP_FW_DEVICE_PATH, strerror(errno));
    return 1;
  }

  /* sigaction() with sa_flags=0 (SA_RESTART deliberately omitted), same
   * reasoning as main.c: this relies on read() actually returning EINTR
   * so periodic re-resolution runs and shutdown doesn't stall until the
   * next packet. */
  struct sigaction sa_alarm, sa_term;
  memset(&sa_alarm, 0, sizeof(sa_alarm));
  sa_alarm.sa_handler = on_alarm;
  sigaction(SIGALRM, &sa_alarm, NULL);
  memset(&sa_term, 0, sizeof(sa_term));
  sa_term.sa_handler = on_term;
  sigaction(SIGTERM, &sa_term, NULL);
  sigaction(SIGINT, &sa_term, NULL);
  if (resolve_interval > 0)
    alarm((unsigned)resolve_interval);

  fprintf(stderr, "otp_firewalld_freebsd: running (mode=%s)\n",
         mode == OTP_FW_MODE_ENFORCE ? "enforce" : "log-only");

  static otp_fw_dequeued_packet_t in_buf;
  static otp_fw_verdict_submission_t out_buf;

  while (!g_shutdown)
  {
    /* Checked unconditionally at the top of every iteration, not only
     * inside the EINTR branch - same reasoning as main.c: under
     * sustained traffic, read() keeps finding data ready and returns
     * normally rather than blocking, so a SIGALRM landing mid-read()
     * (or mid packet-processing) would otherwise never get picked up
     * again for the rest of the process's life. */
    if (g_resolve_due)
    {
      g_resolve_due = 0;
      reload_config_and_push(&ctx, config_path);
      if (resolve_interval > 0)
        alarm((unsigned)resolve_interval);
    }

    ssize_t n = read(fd, &in_buf, sizeof(in_buf));
    if (n < 0)
    {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "Error: read() failed: %s\n", strerror(errno));
      break;
    }
    if (n != (ssize_t)sizeof(in_buf))
      continue; /* short read: shouldn't happen with this cdev's uiomove() contract, but never process a partial packet */

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
      int out_len = 0;
      /* log-only must never call the real encrypt_with_contact(): a
       * genuine success there permanently spends real key material even
       * though the rewritten packet is discarded - see main.c's
       * matching comment. */
      if (ctx.mode == OTP_FW_MODE_LOGONLY)
        r = otp_fw_classify_egress(ctx.keychain_dir, &ctx.cfg, in_buf.data, (int)in_buf.data_len, contact, sizeof(contact));
      else
        r = otp_fw_encrypt_packet(ctx.keychain_dir, &ctx.cfg, in_buf.data, (int)in_buf.data_len,
                                  out_buf.data, sizeof(out_buf.data), &out_len, contact, sizeof(contact));

      if (r == OTP_FW_OK)
      {
        otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);
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
      /* static: CandidateList is too large for a stack local - see
       * main.c's matching comment. Safe to share: trial_select_primary()
       * rebuilds it from scratch every call and this daemon is
       * single-threaded. */
      static CandidateList candidates;
      trial_select_primary(ctx.keychain_dir, &ctx.cfg, &ctx.pins, src_ip, &candidates);

      int out_len = 0;
      if (ctx.mode == OTP_FW_MODE_LOGONLY)
        r = otp_fw_classify_ingress(&candidates, contact, sizeof(contact));
      else
        r = otp_fw_decrypt_packet(ctx.keychain_dir, &candidates, in_buf.data, (int)in_buf.data_len,
                                  out_buf.data, sizeof(out_buf.data), &out_len, contact, sizeof(contact));

      int primary_failed = (ctx.mode == OTP_FW_MODE_LOGONLY) ? (r == OTP_FW_NO_CONTACT) : (r != OTP_FW_OK);
      if (primary_failed && !candidates.exclusive)
      {
        trial_add_fallback_scan(ctx.keychain_dir, &candidates);
        if (ctx.mode == OTP_FW_MODE_LOGONLY)
          r = otp_fw_classify_ingress(&candidates, contact, sizeof(contact));
        else
          r = otp_fw_decrypt_packet(ctx.keychain_dir, &candidates, in_buf.data, (int)in_buf.data_len,
                                    out_buf.data, sizeof(out_buf.data), &out_len, contact, sizeof(contact));
      }

      if (r == OTP_FW_OK)
      {
        if (pin_set(&ctx.pins, src_ip, contact) != 0)
          fprintf(stderr, "Warning: pin table full (%d entries) - '%s' will use the slower "
                          "trial path on every packet until a pin frees up\n",
                 OTP_FW_MAX_PINS, src_ip);
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
  fwconfig_free(&ctx.cfg);
  cleanup_keychain();
  return 0;
}
