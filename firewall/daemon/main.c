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

#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define OTP_FW_DEFAULT_RESOLVE_INTERVAL 60
#define OTP_FW_PACKET_BUF_CAP 70000

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

static int emit_verdict(struct nfq_q_handle *qh, uint32_t id, int accept,
                        const unsigned char *pkt, int pkt_len)
{
  uint32_t v = accept ? NF_ACCEPT : NF_DROP;
  if (accept && pkt && pkt_len > 0)
    return nfq_set_verdict(qh, id, v, (uint32_t)pkt_len, pkt);
  return nfq_set_verdict(qh, id, v, 0, NULL);
}

static int egress_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                     struct nfq_data *nfa, void *data)
{
  (void)nfmsg;
  FwContext *ctx = (FwContext *)data;

  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  uint32_t id = ph ? ntohl(ph->packet_id) : 0;

  unsigned char *pkt = NULL;
  int pkt_len = nfq_get_payload(nfa, &pkt);
  if (pkt_len < 0 || !pkt)
    return emit_verdict(qh, id, ctx->mode == OTP_FW_MODE_LOGONLY, NULL, 0);

  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                         dst_ip, sizeof(dst_ip), &dst_port, &proto);

  static unsigned char outbuf[OTP_FW_PACKET_BUF_CAP];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r;
  /* log-only must never call the real encrypt_with_contact(): a genuine
   * success there permanently spends real key material even though the
   * rewritten packet is discarded and the original is passed through
   * unchanged - exactly the irreversible side effect log-only mode
   * exists to avoid during evaluation. otp_fw_classify_egress() reports
   * the same verdict for free, since contact selection here is
   * deterministic from firewall.config rather than conditional on
   * running the cipher. */
  if (ctx->mode == OTP_FW_MODE_LOGONLY)
    r = otp_fw_classify_egress(ctx->keychain_dir, &ctx->cfg, pkt, pkt_len, contact, sizeof(contact));
  else
    r = otp_fw_encrypt_packet(ctx->keychain_dir, &ctx->cfg, pkt, pkt_len,
                              outbuf, sizeof(outbuf), &out_len,
                              contact, sizeof(contact));

  if (r == OTP_FW_OK)
  {
    otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    if (ctx->mode == OTP_FW_MODE_ENFORCE)
      return emit_verdict(qh, id, 1, outbuf, out_len);
    return emit_verdict(qh, id, 1, NULL, 0);
  }

  otp_fw_log_restricted("egress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                        proto, otp_fw_result_reason(r));
  return emit_verdict(qh, id, ctx->mode == OTP_FW_MODE_LOGONLY, NULL, 0);
}

static int ingress_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                      struct nfq_data *nfa, void *data)
{
  (void)nfmsg;
  FwContext *ctx = (FwContext *)data;

  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  uint32_t id = ph ? ntohl(ph->packet_id) : 0;

  unsigned char *pkt = NULL;
  int pkt_len = nfq_get_payload(nfa, &pkt);
  if (pkt_len < 0 || !pkt)
    return emit_verdict(qh, id, ctx->mode == OTP_FW_MODE_LOGONLY, NULL, 0);

  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                         dst_ip, sizeof(dst_ip), &dst_port, &proto);

  /* static: CandidateList is ~2.5MB (OTP_FW_MAX_CANDIDATES *
   * MAX_NAME_LENGTH) - as a plain stack local this would allocate that
   * on every single inbound packet, a real stack-overflow risk. Safe to
   * share across calls: trial_select_primary() unconditionally resets
   * count to 0 and rebuilds the list from scratch each time, and the
   * daemon is single-threaded (one NFQUEUE callback in flight at once). */
  static CandidateList candidates;
  trial_select_primary(ctx->keychain_dir, &ctx->cfg, &ctx->pins, src_ip, &candidates);

  static unsigned char outbuf[OTP_FW_PACKET_BUF_CAP];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r;
  /* log-only must never call the real decrypt_with_contact(): unlike the
   * egress side, whether an inbound packet validates can only be known
   * by actually decrypting it, and a genuine success there is just as
   * irreversible (spends real key material) as a live decrypt. So this
   * never claims OTP_FW_OK - see otp_fw_classify_ingress(). */
  if (ctx->mode == OTP_FW_MODE_LOGONLY)
    r = otp_fw_classify_ingress(&candidates, contact, sizeof(contact));
  else
    r = otp_fw_decrypt_packet(ctx->keychain_dir, &candidates, pkt, pkt_len,
                              outbuf, sizeof(outbuf), &out_len,
                              contact, sizeof(contact));

  /* The primary candidate(s) - pin or configured match - cover the
   * common case; scanning the rest of the keychain (one file check per
   * contact) only runs when that wasn't enough, instead of unconditionally
   * on every single inbound packet regardless of whether the result ever
   * gets used. Never for an exclusive (pinned) list - trial_add_fallback_scan()
   * already enforces that, this check just avoids the call entirely. */
  int primary_failed = (ctx->mode == OTP_FW_MODE_LOGONLY) ? (r == OTP_FW_NO_CONTACT) : (r != OTP_FW_OK);
  if (primary_failed && !candidates.exclusive)
  {
    trial_add_fallback_scan(ctx->keychain_dir, &candidates);
    if (ctx->mode == OTP_FW_MODE_LOGONLY)
      r = otp_fw_classify_ingress(&candidates, contact, sizeof(contact));
    else
      r = otp_fw_decrypt_packet(ctx->keychain_dir, &candidates, pkt, pkt_len,
                                outbuf, sizeof(outbuf), &out_len,
                                contact, sizeof(contact));
  }

  if (r == OTP_FW_OK)
  {
    if (pin_set(&ctx->pins, src_ip, contact) != 0)
      fprintf(stderr, "Warning: pin table full (%d entries) - '%s' will use the slower "
                      "trial path on every packet until a pin frees up\n",
             OTP_FW_MAX_PINS, src_ip);
    otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    if (ctx->mode == OTP_FW_MODE_ENFORCE)
      return emit_verdict(qh, id, 1, outbuf, out_len);
    return emit_verdict(qh, id, 1, NULL, 0);
  }

  otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                        proto, otp_fw_result_reason(r));
  return emit_verdict(qh, id, ctx->mode == OTP_FW_MODE_LOGONLY, NULL, 0);
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
      i--; /* pin_clear_ip swaps the last entry into this slot */
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

static void reload_config_and_push(FwContext *ctx, const char *config_path)
{
  /* load_keychain() fully rebuilds g_keychain from the .meta files
   * currently on disk (see src/keychain.c), so this is what actually
   * picks up contacts added or removed since startup. Without it, a
   * newly added contact stays invisible to find_contact() - and
   * therefore rejected - until some OTHER contact's traffic happens to
   * trigger cipher.c's own internal load_keychain() call as a side
   * effect of encrypt_with_contact()/decrypt_with_contact(); with no
   * other contact's traffic ever arriving, that could be never.
   *
   * On failure, src/keychain.c's own load_keychain() has ALREADY wiped
   * g_keychain to empty (cleanup_keychain()+init_keychain() run
   * unconditionally before the failure point - e.g. get_keychain_dir()'s
   * unconditional mkdir() hitting a transient EROFS/ENOSPC/permission
   * change) - that's not just "new contacts not reflected", it's every
   * existing contact gone from memory until the next successful reload,
   * which would in turn make reconcile_pins_with_config() below read
   * that empty keychain as "every pinned contact was removed" and clear
   * every pin. Since the core library offers no "restore previous state
   * on failure" the way fwconfig_load() was fixed to do, this snapshots
   * g_keychain here (static: ~13MB, too large for a stack local, but a
   * plain struct copy with no pointers inside Contact - cheap enough,
   * sub-millisecond, to do on every reload regardless of whether this
   * one actually fails) and restores it on failure instead. */
  static Keychain keychain_snapshot;
  keychain_snapshot = g_keychain;
  int keychain_ok = (load_keychain() == 0);
  if (!keychain_ok)
  {
    fprintf(stderr, "Warning: failed to reload keychain - keeping the previous in-memory state\n");
    g_keychain = keychain_snapshot;
  }

  int config_ok = (fwconfig_load(config_path, &ctx->cfg) == 0);
  if (config_ok)
    /* Only re-resolve when the config actually (potentially) changed:
     * fwconfig_load() restores the previous, already-resolved config on
     * failure, so re-resolving it again here would just be a repeated,
     * synchronous getaddrinfo() pass (real latency on a DNS timeout,
     * not just wasted traffic) over entries that are known unchanged. */
    fwconfig_resolve(&ctx->cfg);
  reconcile_pins_with_config(ctx);
  otp_fw_kernel_push_candidates(&ctx->cfg);
}

static void usage(const char *argv0)
{
  fprintf(stderr,
         "Usage: %s [--mode=enforce|log-only] [--config=PATH]\n"
         "          [--queue-egress=N] [--queue-ingress=N] [--resolve-interval=SECONDS]\n",
         argv0);
}

int main(int argc, char **argv)
{
  otp_fw_mode_t mode = OTP_FW_MODE_ENFORCE;
  uint16_t queue_egress = 0;
  uint16_t queue_ingress = 1;
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
    else if (strncmp(argv[i], "--queue-egress=", 15) == 0)
      queue_egress = (uint16_t)atoi(argv[i] + 15);
    else if (strncmp(argv[i], "--queue-ingress=", 16) == 0)
      queue_ingress = (uint16_t)atoi(argv[i] + 16);
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
  /* Required: encrypt/decrypt_with_contact() otherwise block on an
   * interactive "did the previous message arrive?" confirmation prompt
   * (cipher.h:51-64) that this daemon, with no terminal, can never
   * answer. The per-packet meta-header validation is already the
   * automatic proof of correct, in-order delivery. */
  keychain_set_assume_delivered(1);

  if (otp_fw_log_init() != 0)
    return 1;

  char config_path[1024];
  if (config_path_override[0])
    snprintf(config_path, sizeof(config_path), "%s", config_path_override);
  else
    snprintf(config_path, sizeof(config_path), "%s", OTP_FW_CONFIG_NAME); /* relative to ~/.otp, per chdir above */

  reload_config_and_push(&ctx, config_path);

  struct nfq_handle *h = nfq_open();
  if (!h)
  {
    fprintf(stderr, "Error: nfq_open() failed: %s\n", strerror(errno));
    return 1;
  }
  if (nfq_bind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET6) < 0)
  {
    fprintf(stderr, "Error: nfq_bind_pf() failed (need root / CAP_NET_ADMIN): %s\n", strerror(errno));
    nfq_close(h);
    return 1;
  }

  struct nfq_q_handle *qh_egress = nfq_create_queue(h, queue_egress, &egress_cb, &ctx);
  struct nfq_q_handle *qh_ingress = nfq_create_queue(h, queue_ingress, &ingress_cb, &ctx);
  if (!qh_egress || !qh_ingress)
  {
    fprintf(stderr, "Error: nfq_create_queue() failed: %s\n", strerror(errno));
    nfq_close(h);
    return 1;
  }
  if (nfq_set_mode(qh_egress, NFQNL_COPY_PACKET, 0xffff) < 0 ||
     nfq_set_mode(qh_ingress, NFQNL_COPY_PACKET, 0xffff) < 0)
  {
    fprintf(stderr, "Error: nfq_set_mode() failed: %s\n", strerror(errno));
    nfq_close(h);
    return 1;
  }

  /* sigaction() with sa_flags=0 (SA_RESTART deliberately omitted) rather
   * than signal(): whether glibc's signal() sets SA_RESTART by default is
   * version/feature-macro dependent, and this code relies on recv()
   * actually returning EINTR - if it silently auto-restarted instead,
   * periodic hostname re-resolution would never run and SIGTERM/SIGINT
   * shutdown could stall until the next packet arrives. */
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

  int fd = nfq_fd(h);
  char buf[OTP_FW_PACKET_BUF_CAP] __attribute__((aligned(4)));
  fprintf(stderr, "otp-firewalld: running (mode=%s, queues=%u/%u)\n",
         mode == OTP_FW_MODE_ENFORCE ? "enforce" : "log-only", queue_egress, queue_ingress);

  while (!g_shutdown)
  {
    /* Checked unconditionally at the top of every iteration, not only
     * inside the EINTR branch below: under sustained packet traffic,
     * recv() keeps finding data ready and returns normally rather than
     * blocking, so a SIGALRM that lands while nfq_handle_packet() (or
     * anything else) is running sets g_resolve_due but recv() is never
     * actually interrupted - the EINTR branch, and the alarm()
     * re-arming that used to live only inside it, would then never run
     * again for the rest of the process's life. Checking here instead
     * catches it on the very next iteration regardless of which path
     * got us back to the top of the loop. */
    if (g_resolve_due)
    {
      g_resolve_due = 0;
      reload_config_and_push(&ctx, config_path);
      if (resolve_interval > 0)
        alarm((unsigned)resolve_interval);
    }

    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n >= 0)
    {
      nfq_handle_packet(h, buf, (int)n);
      continue;
    }
    if (errno == EINTR)
    {
      continue;
    }
    if (errno == ENOBUFS)
    {
      fprintf(stderr, "Warning: netlink socket overflowed (ENOBUFS), packets were dropped by the kernel\n");
      continue;
    }
    fprintf(stderr, "Error: recv() failed: %s\n", strerror(errno));
    break;
  }

  nfq_destroy_queue(qh_egress);
  nfq_destroy_queue(qh_ingress);
  nfq_close(h);
  fwconfig_free(&ctx.cfg);
  cleanup_keychain();
  return 0;
}
