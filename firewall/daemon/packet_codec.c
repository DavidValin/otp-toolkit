#include "packet_codec.h"
#include "checksum.h"

#include "cipher.h"
#include "keychain.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  int family; /* 4 or 6 */
  size_t ip_hlen;
  uint8_t proto;
  const unsigned char *l4;
  size_t l4_hlen;
  const unsigned char *payload;
  size_t payload_len;
  struct in_addr v4_src, v4_dst;
  struct in6_addr v6_src, v6_dst;
} ParsedPacket;

/* Bounds-checks everything: `pkt` is untrusted network input by design
 * (this is the code that decides whether it gets to exist at all). */
static int parse_packet(const unsigned char *pkt, int pkt_len, ParsedPacket *pp)
{
  if (pkt_len < 1)
    return -1;
  memset(pp, 0, sizeof(*pp));

  int version = (pkt[0] >> 4) & 0x0F;
  size_t l4_total_avail;

  if (version == 4)
  {
    if (pkt_len < (int)sizeof(struct iphdr))
      return -1;
    const struct iphdr *iph = (const struct iphdr *)pkt;
    size_t ip_hlen = (size_t)iph->ihl * 4;
    if (iph->ihl < 5 || (int)ip_hlen > pkt_len)
      return -1;
    size_t tot_len = ntohs(iph->tot_len);
    if (tot_len < ip_hlen || (int)tot_len > pkt_len)
      return -1;

    pp->family = 4;
    pp->ip_hlen = ip_hlen;
    pp->proto = iph->protocol;
    memcpy(&pp->v4_src, &iph->saddr, 4);
    memcpy(&pp->v4_dst, &iph->daddr, 4);
    pp->l4 = pkt + ip_hlen;
    l4_total_avail = tot_len - ip_hlen;
  }
  else if (version == 6)
  {
    if (pkt_len < (int)sizeof(struct ip6_hdr))
      return -1;
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)pkt;
    size_t plen = ntohs(ip6->ip6_plen);
    if (sizeof(struct ip6_hdr) + plen > (size_t)pkt_len)
      return -1;

    pp->family = 6;
    pp->ip_hlen = sizeof(struct ip6_hdr);
    /* Extension headers are not walked (documented v1 scope limit in
     * docs/FIREWALL.md): ip6_nxt is trusted to already name the L4
     * protocol directly. */
    pp->proto = ip6->ip6_nxt;
    pp->v6_src = ip6->ip6_src;
    pp->v6_dst = ip6->ip6_dst;
    pp->l4 = pkt + sizeof(struct ip6_hdr);
    l4_total_avail = plen;
  }
  else
  {
    return -1;
  }

  if (pp->proto == IPPROTO_TCP)
  {
    if (l4_total_avail < sizeof(struct tcphdr))
      return -1;
    const struct tcphdr *th = (const struct tcphdr *)pp->l4;
    size_t l4_hlen = (size_t)th->doff * 4;
    if (l4_hlen < sizeof(struct tcphdr) || l4_hlen > l4_total_avail)
      return -1;
    pp->l4_hlen = l4_hlen;
    pp->payload = pp->l4 + l4_hlen;
    pp->payload_len = l4_total_avail - l4_hlen;
  }
  else if (pp->proto == IPPROTO_UDP)
  {
    if (l4_total_avail < sizeof(struct udphdr))
      return -1;
    const struct udphdr *uh = (const struct udphdr *)pp->l4;
    size_t udp_len = ntohs(uh->len);
    if (udp_len < sizeof(struct udphdr) || udp_len > l4_total_avail)
      return -1;
    pp->l4_hlen = sizeof(struct udphdr);
    pp->payload = pp->l4 + pp->l4_hlen;
    pp->payload_len = udp_len - pp->l4_hlen;
  }
  else
  {
    return -1;
  }

  return 0;
}

int otp_fw_describe_packet(const unsigned char *pkt, int pkt_len,
                           char *src_ip, size_t src_ip_size, unsigned *src_port,
                           char *dst_ip, size_t dst_ip_size, unsigned *dst_port,
                           const char **proto_name)
{
  ParsedPacket pp;
  src_ip[0] = '\0';
  dst_ip[0] = '\0';
  *src_port = 0;
  *dst_port = 0;
  *proto_name = "?";

  if (parse_packet(pkt, pkt_len, &pp) != 0)
    return -1;

  if (pp.family == 4)
  {
    inet_ntop(AF_INET, &pp.v4_src, src_ip, src_ip_size);
    inet_ntop(AF_INET, &pp.v4_dst, dst_ip, dst_ip_size);
  }
  else
  {
    inet_ntop(AF_INET6, &pp.v6_src, src_ip, src_ip_size);
    inet_ntop(AF_INET6, &pp.v6_dst, dst_ip, dst_ip_size);
  }

  if (pp.proto == IPPROTO_TCP)
  {
    const struct tcphdr *th = (const struct tcphdr *)pp.l4;
    *src_port = ntohs(th->source);
    *dst_port = ntohs(th->dest);
    *proto_name = "tcp";
  }
  else
  {
    const struct udphdr *uh = (const struct udphdr *)pp.l4;
    *src_port = ntohs(uh->source);
    *dst_port = ntohs(uh->dest);
    *proto_name = "udp";
  }
  return 0;
}

/* fmemopen() rejects a zero-length buffer. Kept for the ingress/decrypt
 * side, which can legitimately be handed a zero-length ciphertext by an
 * unauthenticated sender (a bare zero-length UDP datagram, say) - that
 * has to fail meta-header validation cleanly rather than crash. The
 * egress/encrypt side no longer relies on this for the zero-payload
 * case (see PAYLOAD_PAD_LEN below): it never calls this with len==0. */
static FILE *open_payload_stream(const unsigned char *payload, size_t len)
{
  static unsigned char dummy = 0;
  if (len == 0)
  {
    FILE *f = fmemopen(&dummy, 1, "rb");
    if (f)
      fseek(f, 0, SEEK_END);
    return f;
  }
  return fmemopen((void *)payload, len, "rb");
}

/* cipher.c's encrypt_with_contact() refuses a genuinely empty message
 * ("Error: No input data provided", cipher.c ~line 1379) - so a bare TCP
 * ACK or empty UDP datagram (a zero-length L4 payload, entirely normal
 * on the wire) would otherwise fail to encrypt and get dropped, which
 * would break TCP outright (its handshake and acknowledgments are
 * mostly zero-payload segments). One fixed sentinel byte is appended to
 * every outgoing payload before encryption - regardless of whether it is
 * already non-empty - so the byte stream handed to encrypt_with_contact()
 * is never actually empty; the matching byte is dropped again on
 * successful decrypt (see otp_fw_decrypt_packet()). The sentinel's value
 * is never inspected - only its presence matters. */
#define PAYLOAD_PAD_LEN 1

static FILE *open_padded_payload_stream(const unsigned char *payload, size_t len, unsigned char *scratch)
{
  memcpy(scratch, payload, len);
  scratch[len] = 0;
  return fmemopen(scratch, len + PAYLOAD_PAD_LEN, "rb");
}

static void fix_ipv4_lengths_and_checksums(unsigned char *out, size_t ip_hlen, size_t l4_hlen,
                                           size_t new_payload_len, uint8_t proto)
{
  struct iphdr *iph = (struct iphdr *)out;
  size_t total = ip_hlen + l4_hlen + new_payload_len;
  iph->tot_len = htons((uint16_t)total);
  iph->check = 0;
  iph->check = otp_fw_ipv4_header_checksum(out, ip_hlen);

  unsigned char *l4 = out + ip_hlen;
  size_t l4_len = l4_hlen + new_payload_len;

  if (proto == IPPROTO_UDP)
  {
    struct udphdr *uh = (struct udphdr *)l4;
    uh->len = htons((uint16_t)l4_len);
    uh->check = 0;
    struct in_addr src, dst;
    memcpy(&src, &iph->saddr, 4);
    memcpy(&dst, &iph->daddr, 4);
    uh->check = otp_fw_l4_checksum_v4(src, dst, proto, l4, l4_len);
    if (uh->check == 0)
      uh->check = 0xFFFF;
  }
  else
  {
    struct tcphdr *th = (struct tcphdr *)l4;
    th->check = 0;
    struct in_addr src, dst;
    memcpy(&src, &iph->saddr, 4);
    memcpy(&dst, &iph->daddr, 4);
    th->check = otp_fw_l4_checksum_v4(src, dst, proto, l4, l4_len);
  }
}

static void fix_ipv6_lengths_and_checksums(unsigned char *out, size_t l4_hlen,
                                           size_t new_payload_len, uint8_t proto)
{
  struct ip6_hdr *ip6 = (struct ip6_hdr *)out;
  size_t l4_len = l4_hlen + new_payload_len;
  ip6->ip6_plen = htons((uint16_t)l4_len);

  unsigned char *l4 = out + sizeof(struct ip6_hdr);
  struct in6_addr src = ip6->ip6_src, dst = ip6->ip6_dst;

  if (proto == IPPROTO_UDP)
  {
    struct udphdr *uh = (struct udphdr *)l4;
    uh->len = htons((uint16_t)l4_len);
    uh->check = 0;
    uh->check = otp_fw_l4_checksum_v6(src, dst, proto, l4, l4_len);
    if (uh->check == 0)
      uh->check = 0xFFFF;
  }
  else
  {
    struct tcphdr *th = (struct tcphdr *)l4;
    th->check = 0;
    th->check = otp_fw_l4_checksum_v6(src, dst, proto, l4, l4_len);
  }
}

/* Shared prefix of otp_fw_encrypt_packet() and otp_fw_classify_egress():
 * parse the packet and resolve it to a healthy contact via
 * firewall.config, without touching any key material. Returns OTP_FW_OK
 * with *pp and *contact_out filled on success. */
static otp_fw_result_t resolve_egress_contact(const char *keychain_dir, const FwConfig *cfg,
                                              const unsigned char *pkt, int pkt_len,
                                              ParsedPacket *pp, Contact **contact_out)
{
  if (parse_packet(pkt, pkt_len, pp) != 0)
    return OTP_FW_PARSE_ERROR;

  char dst_ip[OTP_FW_IPSTR_LEN];
  if (pp->family == 4)
    inet_ntop(AF_INET, &pp->v4_dst, dst_ip, sizeof(dst_ip));
  else
    inet_ntop(AF_INET6, &pp->v6_dst, dst_ip, sizeof(dst_ip));

  const char *contact_name = fwconfig_contact_for_ip(cfg, dst_ip);
  if (!contact_name)
    return OTP_FW_NO_CONTACT;

  Contact *c = find_contact(contact_name);
  if (!c)
    return OTP_FW_NO_CONTACT;
  if (c->EncryptionKeySize == 0)
    return OTP_FW_KEY_EXHAUSTED;
  if (!otp_fw_contact_ready(keychain_dir, c, "enc"))
    return OTP_FW_PENDING_RECOVERY;

  *contact_out = c;
  return OTP_FW_OK;
}

/* Classifies an outbound packet exactly as otp_fw_encrypt_packet() would,
 * without ever calling encrypt_with_contact() - so nothing is spent.
 * Used for --mode=log-only, where a real attempt would otherwise
 * irreversibly consume key material for traffic that's only being
 * observed, not actually sent. */
otp_fw_result_t otp_fw_classify_egress(const char *keychain_dir, const FwConfig *cfg,
                                       const unsigned char *pkt, int pkt_len,
                                       char *contact_out, size_t contact_out_size)
{
  ParsedPacket pp;
  Contact *c = NULL;
  otp_fw_result_t r = resolve_egress_contact(keychain_dir, cfg, pkt, pkt_len, &pp, &c);
  if (r == OTP_FW_OK)
    snprintf(contact_out, contact_out_size, "%s", c->Name);
  return r;
}

otp_fw_result_t otp_fw_encrypt_packet(const char *keychain_dir, const FwConfig *cfg,
                                      const unsigned char *pkt, int pkt_len,
                                      unsigned char *out, int out_cap, int *out_len,
                                      char *contact_out, size_t contact_out_size)
{
  ParsedPacket pp;
  Contact *c = NULL;
  otp_fw_result_t resolved = resolve_egress_contact(keychain_dir, cfg, pkt, pkt_len, &pp, &c);
  if (resolved != OTP_FW_OK)
    return resolved;
  const char *contact = c->Name;

  /* Conservative pre-check using the documented worst-case growth bound,
   * BEFORE any key material is spent: encrypt_with_contact() commits real
   * key material on success, and the true grown size isn't known until
   * after it runs. Rejecting an outsized packet only after already
   * encrypting it (as a plain out_cap/65535 check after the call would)
   * would burn key material for a message that never actually gets
   * sent, desyncing this contact's key offset from the receiver's. */
  size_t header_len = pp.ip_hlen + pp.l4_hlen;
  size_t worst_case_total = header_len + pp.payload_len + PAYLOAD_PAD_LEN + OTP_FW_MAX_GROWTH;
  size_t worst_case_l4 = pp.l4_hlen + pp.payload_len + PAYLOAD_PAD_LEN + OTP_FW_MAX_GROWTH;
  size_t worst_case_limit = pp.family == 4 ? worst_case_total : worst_case_l4;
  static unsigned char pad_scratch[70000];
  if (worst_case_total > (size_t)out_cap || worst_case_limit > 65535 ||
     pp.payload_len + PAYLOAD_PAD_LEN > sizeof(pad_scratch))
    return OTP_FW_INTERNAL_ERROR;

  FILE *in = open_padded_payload_stream(pp.payload, pp.payload_len, pad_scratch);
  if (!in)
    return OTP_FW_INTERNAL_ERROR;

  char *cipherbuf = NULL;
  size_t cipherlen = 0;
  FILE *outf = open_memstream(&cipherbuf, &cipherlen);
  if (!outf)
  {
    fclose(in);
    return OTP_FW_INTERNAL_ERROR;
  }

  int rc = encrypt_with_contact(contact, in, outf);
  fclose(in);
  fclose(outf); /* finalizes cipherbuf/cipherlen */

  if (rc != KEYCHAIN_OK)
  {
    free(cipherbuf);
    return rc == KEYCHAIN_REDELIVERED ? OTP_FW_PENDING_RECOVERY : OTP_FW_INTERNAL_ERROR;
  }

  size_t new_total = header_len + cipherlen;
  /* Defensive backstop only: the pre-check above already rejects
   * anything that could exceed these limits using a conservative
   * worst-case growth bound, so this should never actually trigger. It
   * stays because "should never trigger" isn't the same guarantee as
   * "cannot": iph->tot_len (v4) / uh->len (both families) / ip6->ip6_plen
   * are all 16-bit fields, and silently truncating them here would send
   * a corrupted-on-the-wire packet whose header claims fewer bytes than
   * are actually present, rather than failing loudly. */
  size_t l4_len = pp.l4_hlen + cipherlen;
  size_t length_field_limit = pp.family == 4 ? new_total : l4_len;
  if (new_total > (size_t)out_cap || length_field_limit > 65535)
  {
    free(cipherbuf);
    return OTP_FW_INTERNAL_ERROR;
  }

  memcpy(out, pkt, header_len);
  memcpy(out + header_len, cipherbuf, cipherlen);
  free(cipherbuf);

  if (pp.family == 4)
    fix_ipv4_lengths_and_checksums(out, pp.ip_hlen, pp.l4_hlen, cipherlen, pp.proto);
  else
    fix_ipv6_lengths_and_checksums(out, pp.l4_hlen, cipherlen, pp.proto);

  *out_len = (int)new_total;
  snprintf(contact_out, contact_out_size, "%s", contact);
  return OTP_FW_OK;
}

otp_fw_result_t otp_fw_decrypt_packet(const char *keychain_dir, const CandidateList *candidates,
                                      const unsigned char *pkt, int pkt_len,
                                      unsigned char *out, int out_cap, int *out_len,
                                      char *contact_out, size_t contact_out_size)
{
  (void)keychain_dir;
  ParsedPacket pp;
  if (parse_packet(pkt, pkt_len, &pp) != 0)
    return OTP_FW_PARSE_ERROR;

  if (candidates->count == 0)
    return candidates->exclusive ? OTP_FW_PIN_MISMATCH : OTP_FW_NO_CONTACT;

  int saw_pending_recovery = 0;

  for (int i = 0; i < candidates->count; i++)
  {
    const char *contact = candidates->names[i];
    Contact *c = find_contact(contact);
    if (!c)
      continue;
    if (c->DecryptionKeySize == 0)
    {
      /* This specific candidate is exhausted; keep trying the rest of
       * the list unless the caller marked it exclusive (trial.c already
       * leaves an exclusive list with at most one entry). */
      continue;
    }

    FILE *in = open_payload_stream(pp.payload, pp.payload_len);
    if (!in)
      continue;

    char *plainbuf = NULL;
    size_t plainlen = 0;
    FILE *outf = open_memstream(&plainbuf, &plainlen);
    if (!outf)
    {
      fclose(in);
      continue;
    }

    int rc = decrypt_with_contact(contact, in, outf);
    fclose(in);
    fclose(outf);

    if (rc == KEYCHAIN_OK)
    {
      /* Every encrypted payload carries exactly one trailing sentinel
       * byte that was never part of the original packet - see
       * PAYLOAD_PAD_LEN above. cipher.c guarantees at least 1 byte was
       * decrypted on a KEYCHAIN_OK result (it refuses an empty message
       * outright), so plainlen - PAYLOAD_PAD_LEN cannot underflow here. */
      if (plainlen < PAYLOAD_PAD_LEN)
      {
        free(plainbuf);
        return OTP_FW_INTERNAL_ERROR;
      }
      size_t real_len = plainlen - PAYLOAD_PAD_LEN;
      size_t header_len = pp.ip_hlen + pp.l4_hlen;
      size_t new_total = header_len + real_len;
      if (new_total > (size_t)out_cap)
      {
        free(plainbuf);
        return OTP_FW_INTERNAL_ERROR;
      }
      memcpy(out, pkt, header_len);
      memcpy(out + header_len, plainbuf, real_len);
      free(plainbuf);

      if (pp.family == 4)
        fix_ipv4_lengths_and_checksums(out, pp.ip_hlen, pp.l4_hlen, real_len, pp.proto);
      else
        fix_ipv6_lengths_and_checksums(out, pp.l4_hlen, real_len, pp.proto);

      *out_len = (int)new_total;
      snprintf(contact_out, contact_out_size, "%s", contact);
      return OTP_FW_OK;
    }

    free(plainbuf);
    /* Any non-OK result means this candidate did not produce this
     * packet; try the next one (an exclusive/pinned list has only one
     * candidate, so this simply falls through below). REDELIVERED is
     * tracked separately: it means this candidate has an interrupted
     * operation left over from elsewhere (see otp_fw_contact_ready()) -
     * trial.c's readiness filter should already exclude such contacts,
     * so hitting it here means that state appeared in the narrow window
     * between the filter and this call. The current packet's input was
     * never consumed by that redelivery (KEYCHAIN_REDELIVERED leaves the
     * input untouched), so it's still safe to try the next candidate,
     * but if nothing else validates either, "pending-recovery" is a far
     * more actionable answer than the generic "meta-mismatch". */
    if (rc == KEYCHAIN_REDELIVERED)
      saw_pending_recovery = 1;
  }

  if (saw_pending_recovery)
    return OTP_FW_PENDING_RECOVERY;
  return candidates->exclusive ? OTP_FW_PIN_MISMATCH : OTP_FW_AUTH_FAIL;
}

/* Classifies an inbound packet's candidate list without ever calling
 * decrypt_with_contact(): unlike the egress side, whether an inbound
 * packet WOULD validate can only be known by actually decrypting it, and
 * a genuine successful decrypt is not reversible - it commits real key
 * material the same as a live decrypt would (see otp_fw_decrypt_packet()
 * above). So --mode=log-only only ever reports the two outcomes that are
 * free to determine: no candidate at all (OTP_FW_NO_CONTACT /
 * OTP_FW_PIN_MISMATCH), or OTP_FW_NOT_EVALUATED when there's at least
 * one candidate that a real attempt would have been tried against - an
 * honest "would have tried this, didn't check", not a claim of success. */
otp_fw_result_t otp_fw_classify_ingress(const CandidateList *candidates,
                                        char *contact_out, size_t contact_out_size)
{
  if (candidates->count == 0)
    return candidates->exclusive ? OTP_FW_PIN_MISMATCH : OTP_FW_NO_CONTACT;
  snprintf(contact_out, contact_out_size, "%s", candidates->names[0]);
  return OTP_FW_NOT_EVALUATED;
}
