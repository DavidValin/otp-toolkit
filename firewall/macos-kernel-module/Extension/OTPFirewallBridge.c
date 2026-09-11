/*
 * OTPFirewallBridge.c - the macOS analog of Linux's otp_firewalld.c
 * (egress_cb()/ingress_cb()), minus the NFQUEUE plumbing (there's no
 * separate kernel piece here to hand a verdict back to - this bridge,
 * called from OTPFirewallProvider.swift's packet loop, IS the
 * enforcement point). Reuses this directory's own {common,config,pin,
 * trial,packet_codec,log,keychain_setup}.h (byte-identical to Linux's
 * copies - see README.md) and links against the real
 * src/{cipher,keychain,commit}.c unmodified, exactly like the Linux
 * daemon does.
 *
 * UNVERIFIED: written and reviewed by hand, never compiled - see
 * ../README.md. The locking discipline below (a single mutex around
 * every call) is deliberately conservative: unlike the Linux daemon's
 * single NFQUEUE recv loop, this bridge is called from Swift code whose
 * exact threading (does NEPacketTunnelProvider ever deliver reads
 * concurrently? does a config-reload timer run on a different queue
 * than the packet loop?) isn't something this could be confirmed
 * without a real target to test against.
 */

#include "OTPFirewallBridge.h"

#include "ack.h"
#include "common.h"
#include "config.h"
#include "keychain_setup.h"
#include "log.h"
#include "packet_codec.h"
#include "pin.h"
#include "trial.h"

#include "keychain.h"
#include "cipher.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static FwConfig g_cfg;
static PinTable g_pins;
static AckTable g_acks;
static char g_keychain_dir[512];
static int g_setup_done = 0;
static int g_ack_fd4 = -1;
static int g_ack_fd6 = -1;

static void reconcile_pins_with_config_locked(void)
{
  for (int i = 0; i < g_pins.count; i++)
  {
    char ip[OTP_FW_IPSTR_LEN];
    snprintf(ip, sizeof(ip), "%s", g_pins.entries[i].ip);
    const char *configured = fwconfig_contact_for_ip(&g_cfg, ip);
    if (configured && strcmp(configured, g_pins.entries[i].contact) != 0)
    {
      pin_clear_ip(&g_pins, ip);
      i--;
    }
  }
}

/* Mirrors Linux's otp_firewalld.c's reconcile_acks_with_keychain(): a
 * stale outstanding-ack slot for a contact no longer in the keychain is
 * harmless but pointless to keep around. */
static void reconcile_acks_with_keychain_locked(void)
{
  for (int i = 0; i < g_acks.count; i++)
  {
    char contact[MAX_NAME_LENGTH];
    snprintf(contact, sizeof(contact), "%s", g_acks.slots[i].contact);
    if (!find_contact(contact))
    {
      ack_clear_contact(&g_acks, contact);
      i--;
    }
  }
}

int otp_fw_bridge_setup(void)
{
  pthread_mutex_lock(&g_lock);

  fwconfig_init(&g_cfg);
  pin_init(&g_pins);
  ack_table_init(&g_acks);

  int rc = otp_fw_setup_keychain_dir();
  if (rc == 0)
    rc = get_keychain_dir(g_keychain_dir, sizeof(g_keychain_dir));
  if (rc == 0)
    rc = load_keychain();
  if (rc == 0)
  {
    /* Required: encrypt/decrypt_with_contact() otherwise block on an
     * interactive "did the previous message arrive?" confirmation
     * prompt (cipher.h) that this extension, with no terminal, can
     * never answer. Genuinely true by the time it's consulted, though,
     * not a blind assumption: the delivery-ack mechanism below (see
     * ack.h) gates all new encryption behind having actually seen the
     * peer's ack for the previous message. */
    keychain_set_assume_delivered(1);
    cipher_set_ack_file(1);
    rc = otp_fw_log_init();
  }
  if (rc == 0)
  {
    /* AF_INET must succeed - see Linux's otp_firewalld.c for identical
     * reasoning. AF_INET6 is best-effort. */
    g_ack_fd4 = ack_socket_open(AF_INET);
    if (g_ack_fd4 < 0)
    {
      fprintf(stderr, "Error: could not open the IPv4 delivery-ack socket on port %d: %s\n",
             OTP_FW_ACK_PORT, strerror(errno));
      rc = -1;
    }
    else
    {
      g_ack_fd6 = ack_socket_open(AF_INET6);
      if (g_ack_fd6 < 0)
        fprintf(stderr, "Warning: could not open the IPv6 delivery-ack socket - IPv6 contacts will send without delivery tracking\n");
    }
  }
  if (rc == 0)
  {
    fwconfig_load(OTP_FW_CONFIG_NAME, &g_cfg); /* relative to ~/.otp, per otp_fw_setup_keychain_dir()'s chdir */
    fwconfig_resolve(&g_cfg);
    /* Crash/restart recovery - see ack.h's ack_recover_outstanding() doc
     * comment and Linux's otp_firewalld.c for the identical call. Must
     * run before g_setup_done lets any real traffic through. */
    ack_recover_outstanding(&g_acks, &g_cfg);
    g_setup_done = 1;
  }

  pthread_mutex_unlock(&g_lock);
  return rc;
}

void otp_fw_bridge_reload_config(void)
{
  pthread_mutex_lock(&g_lock);
  if (g_setup_done)
  {
    fwconfig_load(OTP_FW_CONFIG_NAME, &g_cfg);
    fwconfig_resolve(&g_cfg);
    reconcile_pins_with_config_locked();
    reconcile_acks_with_keychain_locked();
  }
  pthread_mutex_unlock(&g_lock);
}

/* No lock needed: pure read-only inspection of the caller's own buffer,
 * touches none of the shared state the mutex protects. */
int otp_fw_bridge_is_icmpv6(const uint8_t *pkt, int pkt_len)
{
  if (pkt_len < (int)sizeof(struct ip6_hdr))
    return 0;
  int version = (pkt[0] >> 4) & 0x0F;
  if (version != 6)
    return 0;
  const struct ip6_hdr *ip6h = (const struct ip6_hdr *)pkt;
  return ip6h->ip6_nxt == IPPROTO_ICMPV6;
}

otp_fw_action_t otp_fw_bridge_process_outbound(const uint8_t *pkt, int pkt_len,
                                               uint8_t *out_buf, int out_cap, int *out_len,
                                               int enforce_mode)
{
  if (!g_setup_done)
    return OTP_FW_ACTION_DROP;

  pthread_mutex_lock(&g_lock);

  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                         dst_ip, sizeof(dst_ip), &dst_port, &proto);

  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r;
  if (!enforce_mode)
  {
    r = otp_fw_classify_egress(g_keychain_dir, &g_cfg, pkt, pkt_len, contact, sizeof(contact));
  }
  else
  {
    /* Free (no key spent) contact resolution first, so the delivery-ack
     * gate (see ack.h) can reject a packet BEFORE ever calling the
     * real, key-spending encrypt - see Linux's otp_firewalld.c for
     * identical reasoning. */
    r = otp_fw_classify_egress(g_keychain_dir, &g_cfg, pkt, pkt_len, contact, sizeof(contact));
    if (r == OTP_FW_OK)
    {
      if (!ack_egress_allowed(&g_acks, contact))
        r = OTP_FW_ACK_PENDING;
      else
        r = otp_fw_encrypt_packet(g_keychain_dir, &g_cfg, pkt, pkt_len, out_buf, out_cap, out_len,
                                  contact, sizeof(contact));
    }
  }

  otp_fw_action_t action;
  if (r == OTP_FW_OK)
  {
    otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    if (enforce_mode)
    {
      /* Track this message for delivery acknowledgment - see Linux's
       * otp_firewalld.c for identical reasoning on why this is
       * enforce-mode-only. */
      int header_len = otp_fw_header_length(pkt, pkt_len);
      Contact *c = find_contact(contact);
      unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN];
      if (header_len > 0 && c &&
         ack_read_source_id_file(contact, c->EncryptedSequence, 1, source_id) == 0)
      {
        int family = strchr(dst_ip, ':') ? AF_INET6 : AF_INET;
        if (ack_mark_outstanding(&g_acks, contact, c->EncryptedSequence, source_id, dst_ip, family, pkt, header_len) != 0)
          fprintf(stderr, "Warning: ack table full - '%s' will send without delivery tracking until a slot frees up\n", contact);
      }
      else
      {
        fprintf(stderr, "Warning: could not capture delivery-ack reference for '%s' - sending without tracking\n", contact);
      }
    }
    action = enforce_mode ? OTP_FW_ACTION_FORWARD_MODIFIED : OTP_FW_ACTION_FORWARD_ORIGINAL;
  }
  else
  {
    otp_fw_log_restricted("egress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                          proto, otp_fw_result_reason(r));
    action = !enforce_mode ? OTP_FW_ACTION_FORWARD_ORIGINAL : OTP_FW_ACTION_DROP;
  }

  pthread_mutex_unlock(&g_lock);
  return action;
}

/* Shared by otp_fw_bridge_process_inbound() (a normal packet from
 * NEPacketTunnelFlow) and the REDELIVER handling inside
 * otp_fw_bridge_ack_tick() - both need exactly the same trial-decrypt/
 * pin/ack-send logic. Must be called with g_lock already held. On
 * OTP_FW_OK, also sends the delivery ack back to `src_ip` - the
 * receiving half of the same mechanism otp_fw_bridge_process_outbound()'s
 * ack_mark_outstanding() call is the sending half of. */
static otp_fw_result_t process_inbound_locked(const uint8_t *pkt, int pkt_len, const char *src_ip,
                                              uint8_t *out_buf, int out_cap, int *out_len,
                                              int enforce_mode, char *contact_out, size_t contact_out_size)
{
  /* static: CandidateList is ~2.5MB (OTP_FW_MAX_CANDIDATES *
   * MAX_NAME_LENGTH) - see the identical comment in Linux's
   * otp_firewalld.c for why this must not be a stack local. */
  static CandidateList candidates;
  trial_select_primary(g_keychain_dir, &g_cfg, &g_pins, src_ip, &candidates);

  otp_fw_result_t r;
  if (!enforce_mode)
    r = otp_fw_classify_ingress(&candidates, contact_out, contact_out_size);
  else
    r = otp_fw_decrypt_packet(g_keychain_dir, &candidates, pkt, pkt_len, out_buf, out_cap, out_len,
                              contact_out, contact_out_size);

  int primary_failed = !enforce_mode ? (r == OTP_FW_NO_CONTACT) : (r != OTP_FW_OK);
  if (primary_failed && !candidates.exclusive)
  {
    trial_add_fallback_scan(g_keychain_dir, &candidates);
    if (!enforce_mode)
      r = otp_fw_classify_ingress(&candidates, contact_out, contact_out_size);
    else
      r = otp_fw_decrypt_packet(g_keychain_dir, &candidates, pkt, pkt_len, out_buf, out_cap, out_len,
                                contact_out, contact_out_size);
  }

  if (r == OTP_FW_OK)
  {
    if (pin_set(&g_pins, src_ip, contact_out) != 0)
      fprintf(stderr, "Warning: pin table full (%d entries) - '%s' will use the slower "
                      "trial path on every packet until a pin frees up\n",
             OTP_FW_MAX_PINS, src_ip);

    if (enforce_mode)
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

otp_fw_action_t otp_fw_bridge_process_inbound(const uint8_t *pkt, int pkt_len,
                                              uint8_t *out_buf, int out_cap, int *out_len,
                                              int enforce_mode)
{
  if (!g_setup_done)
    return OTP_FW_ACTION_DROP;

  pthread_mutex_lock(&g_lock);

  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                         dst_ip, sizeof(dst_ip), &dst_port, &proto);

  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = process_inbound_locked(pkt, pkt_len, src_ip, out_buf, out_cap, out_len,
                                             enforce_mode, contact, sizeof(contact));

  otp_fw_action_t action;
  if (r == OTP_FW_OK)
  {
    otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    action = enforce_mode ? OTP_FW_ACTION_FORWARD_MODIFIED : OTP_FW_ACTION_FORWARD_ORIGINAL;
  }
  else
  {
    otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                          proto, otp_fw_result_reason(r));
    action = !enforce_mode ? OTP_FW_ACTION_FORWARD_ORIGINAL : OTP_FW_ACTION_DROP;
  }

  pthread_mutex_unlock(&g_lock);
  return action;
}

/* See the extended caveat above this function's declaration in
 * OTPFirewallBridge.h - this is the least-confident piece of this whole
 * port. IPv4 (SOCK_RAW + IPPROTO_RAW + IP_HDRINCL, a decades-old and
 * well-documented BSD sockets pattern) is the more solid of the two;
 * IPv6's raw-socket header-inclusion story is far less commonly used in
 * practice and this is a best-effort implementation, not a confirmed
 * one. */
int otp_fw_bridge_send_raw(const uint8_t *pkt, int pkt_len, int family)
{
  if (family == 4)
  {
    if (pkt_len < (int)sizeof(struct ip))
    {
      errno = EINVAL;
      return -1;
    }
    const struct ip *iph = (const struct ip *)pkt;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
      return -1;

    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0)
    {
      close(fd);
      return -1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_len = sizeof(dst);
    memcpy(&dst.sin_addr, &iph->ip_dst, 4);

    ssize_t n = sendto(fd, pkt, (size_t)pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(fd);
    return (n == (ssize_t)pkt_len) ? 0 : -1;
  }

  if (family == 6)
  {
    if (pkt_len < (int)sizeof(struct ip6_hdr))
    {
      errno = EINVAL;
      return -1;
    }
    const struct ip6_hdr *ip6h = (const struct ip6_hdr *)pkt;

    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
      return -1;

#ifdef IPV6_HDRINCL
    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) != 0)
    {
      close(fd);
      return -1;
    }
#endif

    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    dst.sin6_len = sizeof(dst);
    dst.sin6_addr = ip6h->ip6_dst;

    ssize_t n = sendto(fd, pkt, (size_t)pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(fd);
    return (n == (ssize_t)pkt_len) ? 0 : -1;
  }

  errno = EAFNOSUPPORT;
  return -1;
}

/* ack_scan_timeouts() callback (see ack.h) - identical reasoning to
 * Linux's otp_firewalld.c's retry_outstanding_message(): resend the
 * exact kept ciphertext via keychain_recover_last(), never a fresh
 * encrypt. Called with g_lock already held (from
 * otp_fw_bridge_ack_tick() below). */
static void retry_outstanding_message_locked(const AckSlot *slot, void *user_data)
{
  (void)user_data;

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
    ack_touch_retry(&g_acks, slot->contact);
  else
    fprintf(stderr, "Warning: failed to send delivery retry to '%s'\n", slot->contact);

  free(cipherbuf);
}

/* Handles one REDELIVER packet (see ack.h): reconstructed IP+L4 header
 * + ciphertext, run through the same trial-decrypt logic a normal
 * inbound packet would use, always as a real (enforce_mode=1) attempt -
 * a redelivery is finishing what an already-real, already-key-spending
 * send started, never something to merely observe. Must be called with
 * g_lock already held. */
static void handle_redeliver_packet_locked(const uint8_t *pkt, int pkt_len)
{
  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  if (otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                             dst_ip, sizeof(dst_ip), &dst_port, &proto) != 0)
    return; /* malformed reconstruction - nothing sane to log or process */

  static unsigned char outbuf[OTP_FW_BRIDGE_BUF_CAP];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = process_inbound_locked(pkt, pkt_len, src_ip, outbuf, sizeof(outbuf), &out_len,
                                             /*enforce_mode=*/1, contact, sizeof(contact));

  if (r == OTP_FW_OK)
    otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
  else
    otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                          proto, otp_fw_result_reason(r));
}

static void drain_ack_socket_locked(int fd)
{
  /* static: AckRecvResult embeds a 70000-byte reconstruction buffer
   * (OTP_FW_ACK_MAX_REDELIVER) - see Linux's otp_firewalld.c for
   * identical reasoning on why this must not be a stack local. */
  static AckRecvResult res;
  for (;;)
  {
    int rc = ack_socket_recv(fd, &res);
    if (rc <= 0)
      return;

    if (res.type == OTP_FW_ACK_PKT_ACK)
    {
      for (int i = 0; i < g_acks.count; i++)
        if (ack_clear_if_matching(&g_acks, g_acks.slots[i].contact, res.source_id))
          break;
    }
    else if (res.type == OTP_FW_ACK_PKT_REDELIVER)
    {
      handle_redeliver_packet_locked(res.reconstructed, res.reconstructed_len);
    }
  }
}

void otp_fw_bridge_ack_tick(void)
{
  if (!g_setup_done)
    return;

  pthread_mutex_lock(&g_lock);
  if (g_ack_fd4 >= 0)
    drain_ack_socket_locked(g_ack_fd4);
  if (g_ack_fd6 >= 0)
    drain_ack_socket_locked(g_ack_fd6);
  ack_scan_timeouts(&g_acks, OTP_FW_ACK_DEFAULT_TIMEOUT_SECONDS, retry_outstanding_message_locked, NULL);
  pthread_mutex_unlock(&g_lock);
}
