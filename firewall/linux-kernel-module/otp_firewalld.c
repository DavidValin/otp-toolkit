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

#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define OTP_FW_DEFAULT_RESOLVE_INTERVAL 60
#define OTP_FW_PACKET_BUF_CAP 70000

/* How often the main loop wakes up to check for ack timeouts (see
 * ack.h), independent of --resolve-interval: the default 5-second ack
 * retry timeout needs checking far more often than the default 60-second
 * DNS re-resolve interval, so this drives a short, fixed tick instead of
 * trying to run two independent alarm(2) timers (POSIX only gives a
 * process one real-time alarm at a time). Config re-resolution still
 * only actually runs once every --resolve-interval seconds - see the
 * elapsed-time check in the main loop. */
#define OTP_FW_TICK_INTERVAL_SECONDS 1

typedef struct
{
  FwConfig cfg;
  PinTable pins;
  AckTable acks;
  char keychain_dir[512];
  otp_fw_mode_t mode;
  int ack_timeout_seconds;
  int ack_fd4;
  int ack_fd6;
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
  {
    r = otp_fw_classify_egress(ctx->keychain_dir, &ctx->cfg, pkt, pkt_len, contact, sizeof(contact));
  }
  else
  {
    /* Free (no key spent) contact resolution first, so the delivery-ack
     * gate (see ack.h) can reject a packet BEFORE ever calling the real,
     * key-spending encrypt - otherwise a contact with a message already
     * outstanding would burn key material on something guaranteed to be
     * rejected anyway. */
    r = otp_fw_classify_egress(ctx->keychain_dir, &ctx->cfg, pkt, pkt_len, contact, sizeof(contact));
    if (r == OTP_FW_OK)
    {
      if (!ack_egress_allowed(&ctx->acks, contact))
        r = OTP_FW_ACK_PENDING;
      else
        r = otp_fw_encrypt_packet(ctx->keychain_dir, &ctx->cfg, pkt, pkt_len,
                                  outbuf, sizeof(outbuf), &out_len,
                                  contact, sizeof(contact));
    }
  }

  if (r == OTP_FW_OK)
  {
    otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    if (ctx->mode == OTP_FW_MODE_ENFORCE)
    {
      /* Track this message for delivery acknowledgment (see ack.h) -
       * only reached in enforce mode, since log-only never calls the
       * real encrypt_with_contact() and therefore never wrote a real
       * ack-file (cipher_set_ack_file(1), set at startup) to read here. */
      int header_len = otp_fw_header_length(pkt, pkt_len);
      Contact *c = find_contact(contact);
      unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN];
      if (header_len > 0 && c &&
         ack_read_source_id_file(contact, c->EncryptedSequence, 1, source_id) == 0)
      {
        int family = strchr(dst_ip, ':') ? AF_INET6 : AF_INET;
        if (ack_mark_outstanding(&ctx->acks, contact, c->EncryptedSequence, source_id, dst_ip, family, pkt, header_len) != 0)
          fprintf(stderr, "Warning: ack table full - '%s' will send without delivery tracking until a slot frees up\n", contact);
      }
      else
      {
        fprintf(stderr, "Warning: could not capture delivery-ack reference for '%s' - sending without tracking\n", contact);
      }
      return emit_verdict(qh, id, 1, outbuf, out_len);
    }
    return emit_verdict(qh, id, 1, NULL, 0);
  }

  otp_fw_log_restricted("egress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                        proto, otp_fw_result_reason(r));
  return emit_verdict(qh, id, ctx->mode == OTP_FW_MODE_LOGONLY, NULL, 0);
}

/* Shared by ingress_cb() (a normal candidate packet from NFQUEUE) and
 * handle_redeliver_packet() (a packet reconstructed from an ack-port
 * REDELIVER, see ack.h) - both need exactly the same trial-decrypt/pin/
 * ack-send logic, differing only in what happens to the verdict
 * afterwards. On OTP_FW_OK, also sends the delivery ack back to
 * `src_ip` (see ack.h) - the receiving half of the same mechanism
 * egress_cb's ack_mark_outstanding() call is the sending half of. */
static otp_fw_result_t process_ingress_packet(FwContext *ctx, const unsigned char *pkt, int pkt_len,
                                              const char *src_ip, unsigned char *outbuf, int out_cap,
                                              int *out_len, char *contact_out, size_t contact_out_size)
{
  /* static: CandidateList is ~2.5MB (OTP_FW_MAX_CANDIDATES *
   * MAX_NAME_LENGTH) - as a plain stack local this would allocate that
   * on every single inbound packet, a real stack-overflow risk. Safe to
   * share across calls: trial_select_primary() unconditionally resets
   * count to 0 and rebuilds the list from scratch each time, and the
   * daemon is single-threaded (one ingress event in flight at once,
   * whether from NFQUEUE or the ack socket). */
  static CandidateList candidates;
  trial_select_primary(ctx->keychain_dir, &ctx->cfg, &ctx->pins, src_ip, &candidates);

  otp_fw_result_t r;
  /* log-only must never call the real decrypt_with_contact(): unlike the
   * egress side, whether an inbound packet validates can only be known
   * by actually decrypting it, and a genuine success there is just as
   * irreversible (spends real key material) as a live decrypt. So this
   * never claims OTP_FW_OK - see otp_fw_classify_ingress(). */
  if (ctx->mode == OTP_FW_MODE_LOGONLY)
    r = otp_fw_classify_ingress(&candidates, contact_out, contact_out_size);
  else
    r = otp_fw_decrypt_packet(ctx->keychain_dir, &candidates, pkt, pkt_len,
                              outbuf, out_cap, out_len, contact_out, contact_out_size);

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
      r = otp_fw_classify_ingress(&candidates, contact_out, contact_out_size);
    else
      r = otp_fw_decrypt_packet(ctx->keychain_dir, &candidates, pkt, pkt_len,
                                outbuf, out_cap, out_len, contact_out, contact_out_size);
  }

  if (r == OTP_FW_OK)
  {
    if (pin_set(&ctx->pins, src_ip, contact_out) != 0)
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

  static unsigned char outbuf[OTP_FW_PACKET_BUF_CAP];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = process_ingress_packet(ctx, pkt, pkt_len, src_ip, outbuf, sizeof(outbuf),
                                             &out_len, contact, sizeof(contact));

  if (r == OTP_FW_OK)
  {
    otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    if (ctx->mode == OTP_FW_MODE_ENFORCE)
      return emit_verdict(qh, id, 1, outbuf, out_len);
    return emit_verdict(qh, id, 1, NULL, 0);
  }

  otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                        proto, otp_fw_result_reason(r));
  return emit_verdict(qh, id, ctx->mode == OTP_FW_MODE_LOGONLY, NULL, 0);
}

/* Handles one REDELIVER packet from the ack socket (see ack.h):
 * reconstructed IP+L4 header + ciphertext, run through the exact same
 * trial-decrypt logic a normal candidate packet from NFQUEUE would use.
 * From the protocol's point of view this is indistinguishable from the
 * original packet having simply arrived late - its only purpose is
 * getting this contact's DecryptionKeyOffset back in sync and (on
 * success, inside process_ingress_packet()) triggering the ack send
 * back to the sender. There is no verdict to emit: this never came from
 * NFQUEUE and nothing is waiting on it to be forwarded anywhere. */
static void handle_redeliver_packet(FwContext *ctx, const unsigned char *pkt, int pkt_len)
{
  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  if (otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                             dst_ip, sizeof(dst_ip), &dst_port, &proto) != 0)
    return; /* malformed reconstruction - nothing sane to log or process */

  static unsigned char outbuf[OTP_FW_PACKET_BUF_CAP];
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

/* ack_scan_timeouts() callback (see ack.h): resends the exact kept
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
    /* KEYCHAIN_RECOVER_NO_COPY or an error: nothing kept to resend -
     * shouldn't happen given mark_outstanding() only ever runs right
     * after a real successful encrypt, but fail closed rather than
     * resend garbage (e.g. the contact was removed out from under this
     * slot in the meantime). */
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

/* A stale ack-outstanding slot (see ack.h) for a contact that no longer
 * exists in the keychain would otherwise sit forever - harmless (that
 * contact can never egress again anyway, since resolve_egress_contact()
 * already rejects an unknown contact before the ack gate is ever
 * checked), but there's no reason to keep it around. Separate from
 * reconcile_pins_with_config() above: ack slots are keyed by contact,
 * not by IP, and don't depend on firewall.config mappings at all - only
 * on whether the contact still exists in the keychain. */
static void reconcile_acks_with_keychain(FwContext *ctx)
{
  for (int i = 0; i < ctx->acks.count; i++)
  {
    char contact[MAX_NAME_LENGTH];
    snprintf(contact, sizeof(contact), "%s", ctx->acks.slots[i].contact);
    if (!find_contact(contact))
    {
      ack_clear_contact(&ctx->acks, contact);
      i--; /* ack_clear_contact swaps the last entry into this slot */
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
  reconcile_acks_with_keychain(ctx);
  otp_fw_kernel_push_candidates(&ctx->cfg);
}

static void usage(const char *argv0)
{
  fprintf(stderr,
         "Usage: %s [--mode=enforce|log-only] [--config=PATH]\n"
         "          [--queue-egress=N] [--queue-ingress=N] [--resolve-interval=SECONDS]\n"
         "          [--ack-timeout=SECONDS]\n",
         argv0);
}

/* Drains every packet currently queued on the ack socket (see ack.h),
 * non-blocking - called once per select() readability notification, but
 * loops until EAGAIN rather than reading just one: a burst of acks
 * arriving between two select() calls would otherwise be handled one
 * per loop iteration with everything else (NFQUEUE, the tick) starved
 * behind them. */
static void drain_ack_socket(FwContext *ctx, int fd)
{
  /* static: AckRecvResult embeds a 70000-byte reconstruction buffer
   * (OTP_FW_ACK_MAX_REDELIVER) - as a stack local this would be a real
   * stack-overflow risk, same reasoning as the other large buffers in
   * this file. Safe to share: single-threaded, and every field is fully
   * overwritten (or explicitly zeroed) by ack_socket_recv() before use. */
  static AckRecvResult res;
  for (;;)
  {
    int rc = ack_socket_recv(fd, &res);
    if (rc <= 0)
      return; /* 0: nothing left / malformed packet ignored; -1: real socket error, nothing more to do this round */

    if (res.type == OTP_FW_ACK_PKT_ACK)
    {
      /* Which contact this ack belongs to isn't in the packet itself
       * (deliberately minimal, see ack.h) - ack_clear_if_matching()
       * doesn't need it either, since a source_id can only ever match
       * the ONE contact it was generated for; this scans every
       * outstanding slot's expected source_id looking for a match. */
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

int main(int argc, char **argv)
{
  otp_fw_mode_t mode = OTP_FW_MODE_ENFORCE;
  uint16_t queue_egress = 0;
  uint16_t queue_ingress = 1;
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
    else if (strncmp(argv[i], "--queue-egress=", 15) == 0)
      queue_egress = (uint16_t)atoi(argv[i] + 15);
    else if (strncmp(argv[i], "--queue-ingress=", 16) == 0)
      queue_ingress = (uint16_t)atoi(argv[i] + 16);
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
  /* Required: encrypt/decrypt_with_contact() otherwise block on an
   * interactive "did the previous message arrive?" confirmation prompt
   * (cipher.h) that this daemon, with no terminal, can never answer.
   * Genuinely true by the time it's consulted, though, not a blind
   * assumption: the delivery-ack mechanism (ack.h) gates all new
   * encryption behind having actually seen the peer's ack for the
   * previous message, using the source_id --with-ack-file below writes
   * out - see ack.h's file header for the full design. */
  keychain_set_assume_delivered(1);
  cipher_set_ack_file(1);

  if (otp_fw_log_init() != 0)
    return 1;

  /* AF_INET must succeed - without it there's no delivery-ack channel
   * at all, which this design depends on for correctness (see ack.h),
   * not just convenience. AF_INET6 is best-effort: some machines
   * genuinely have no IPv6 stack enabled, and that shouldn't block
   * startup on an otherwise IPv4-only host - IPv6 contacts simply won't
   * get delivery-ack tracking in that case, same "reduced but not
   * broken" posture other optional pieces of this project take. */
  ctx.ack_fd4 = ack_socket_open(AF_INET);
  if (ctx.ack_fd4 < 0)
  {
    fprintf(stderr, "Error: could not open the IPv4 delivery-ack socket on port %d: %s\n",
           OTP_FW_ACK_PORT, strerror(errno));
    return 1;
  }
  ctx.ack_fd6 = ack_socket_open(AF_INET6);
  if (ctx.ack_fd6 < 0)
    fprintf(stderr, "Warning: could not open the IPv6 delivery-ack socket - IPv6 contacts will send without delivery tracking\n");

  char config_path[1024];
  if (config_path_override[0])
    snprintf(config_path, sizeof(config_path), "%s", config_path_override);
  else
    snprintf(config_path, sizeof(config_path), "%s", OTP_FW_CONFIG_NAME); /* relative to ~/.otp, per chdir above */

  reload_config_and_push(&ctx, config_path);

  /* Crash/restart recovery: reconstructs any AckTable state that would
   * otherwise have been lost with the previous process - see ack.h's
   * ack_recover_outstanding() doc comment. Must run after the keychain
   * and config are loaded, and before any real traffic is processed. */
  ack_recover_outstanding(&ctx.acks, &ctx.cfg);

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
   * version/feature-macro dependent, and this code relies on select()
   * actually returning EINTR - if it silently auto-restarted instead,
   * the periodic tick below would never run and SIGTERM/SIGINT shutdown
   * could stall until the next packet arrives. */
  struct sigaction sa_alarm, sa_term;
  memset(&sa_alarm, 0, sizeof(sa_alarm));
  sa_alarm.sa_handler = on_alarm;
  sigaction(SIGALRM, &sa_alarm, NULL);
  memset(&sa_term, 0, sizeof(sa_term));
  sa_term.sa_handler = on_term;
  sigaction(SIGTERM, &sa_term, NULL);
  sigaction(SIGINT, &sa_term, NULL);
  alarm(OTP_FW_TICK_INTERVAL_SECONDS);

  int nfq_socket_fd = nfq_fd(h);
  char buf[OTP_FW_PACKET_BUF_CAP] __attribute__((aligned(4)));
  time_t last_resolve = time(NULL);
  fprintf(stderr, "otp_firewalld: running (mode=%s, queues=%u/%u, ack-timeout=%ds)\n",
         mode == OTP_FW_MODE_ENFORCE ? "enforce" : "log-only", queue_egress, queue_ingress, ack_timeout);

  while (!g_shutdown)
  {
    /* Checked unconditionally at the top of every iteration, not only
     * inside the EINTR branch below: under sustained packet traffic,
     * select() keeps finding data ready and returns normally rather
     * than blocking, so a SIGALRM that lands while a callback (or
     * anything else) is running sets g_resolve_due but select() is
     * never actually interrupted - the EINTR branch, and the alarm()
     * re-arming that used to live only inside it, would then never run
     * again for the rest of the process's life. Checking here instead
     * catches it on the very next iteration regardless of which path
     * got us back to the top of the loop. */
    if (g_resolve_due)
    {
      g_resolve_due = 0;
      /* Ack-timeout retries run every tick (OTP_FW_TICK_INTERVAL_SECONDS,
       * far shorter than a typical --resolve-interval); the heavier
       * config/keychain reload only runs once --resolve-interval
       * seconds have actually elapsed - see the file header's note on
       * why one shared alarm(2) timer drives both instead of two. */
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
    FD_SET(nfq_socket_fd, &rfds);
    FD_SET(ctx.ack_fd4, &rfds);
    int maxfd = nfq_socket_fd > ctx.ack_fd4 ? nfq_socket_fd : ctx.ack_fd4;
    if (ctx.ack_fd6 >= 0)
    {
      FD_SET(ctx.ack_fd6, &rfds);
      if (ctx.ack_fd6 > maxfd)
        maxfd = ctx.ack_fd6;
    }

    int nready = select(maxfd + 1, &rfds, NULL, NULL, NULL);
    if (nready < 0)
    {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "Error: select() failed: %s\n", strerror(errno));
      break;
    }

    if (FD_ISSET(ctx.ack_fd4, &rfds))
      drain_ack_socket(&ctx, ctx.ack_fd4);
    if (ctx.ack_fd6 >= 0 && FD_ISSET(ctx.ack_fd6, &rfds))
      drain_ack_socket(&ctx, ctx.ack_fd6);

    if (!FD_ISSET(nfq_socket_fd, &rfds))
      continue;

    ssize_t n = recv(nfq_socket_fd, buf, sizeof(buf), 0);
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
  close(ctx.ack_fd4);
  if (ctx.ack_fd6 >= 0)
    close(ctx.ack_fd6);
  fwconfig_free(&ctx.cfg);
  cleanup_keychain();
  return 0;
}
