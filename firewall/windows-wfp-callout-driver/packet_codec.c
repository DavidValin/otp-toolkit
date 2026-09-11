/*
 * packet_codec.c - Windows port of firewall/linux-kernel-module/packet_codec.c.
 *
 * UNVERIFIED: written without access to a Windows toolchain (MSVC/MinGW)
 * to compile it against - see README.md.
 *
 * Unlike the macOS port (which reuses Darwin's own native BSD
 * <netinet/*.h> structs), this file defines its own byte-exact,
 * #pragma pack(push,1) wire-format structs for the IPv4/IPv6/TCP/UDP
 * headers rather than relying on any OS-provided ones: Windows doesn't
 * ship a standard "struct iphdr"/"struct ip" the way POSIX systems do,
 * and inventing this project's own portable structs sidesteps that
 * entirely rather than fighting with WinSock's more limited/differently
 * shaped header definitions. Only struct in_addr/in6_addr (used for the
 * checksum.h calls, which every platform's port shares unmodified) come
 * from an OS header (<winsock2.h>/<ws2tcpip.h> here) - those are
 * standard, portable 4-byte/16-byte address containers, not something
 * that needs reinventing.
 *
 * Every function below that doesn't touch these header structs directly
 * (resolve_egress_contact, otp_fw_classify_egress/_ingress,
 * otp_fw_encrypt_packet, otp_fw_decrypt_packet, the payload-stream
 * helpers) is otherwise identical in logic to the Linux/macOS versions -
 * only parse_packet() and the two fix_ipv{4,6}_lengths_and_checksums()
 * helpers differ, because those are the only places touching header
 * bytes directly.
 *
 * Declares the exact same public API as packet_codec.h (reused
 * unmodified from firewall/linux-kernel-module/ - it declares no platform-specific
 * types), so this is a drop-in replacement: the Windows service project
 * compiles this file instead of firewall/linux-kernel-module/packet_codec.c.
 */

#include "packet_codec.h"
#include "checksum.h"

#include "cipher.h"
#include "keychain.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
/* Allows this file to at least be syntax-reasoned-about/partially
 * exercised on a POSIX box during development, even though it's only
 * ever meant to be built for Windows in practice. */
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct
{
  uint8_t ver_ihl; /* version:4 (high nibble), IHL in 32-bit words:4 (low nibble) */
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src;
  uint32_t dst;
} WinIPv4Header;

typedef struct
{
  uint8_t ver_tc_hi;     /* version:4, top 4 bits of traffic class */
  uint8_t tc_lo_flow_hi; /* bottom 4 bits of traffic class, top 4 bits of flow label */
  uint16_t flow_lo;      /* remaining 16 bits of flow label */
  uint16_t payload_len;
  uint8_t next_header;
  uint8_t hop_limit;
  uint8_t src[16];
  uint8_t dst[16];
} WinIPv6Header;

typedef struct
{
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_off_reserved; /* data offset in 32-bit words:4 (high nibble), reserved:4 */
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;
} WinTCPHeader;

typedef struct
{
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
} WinUDPHeader;
#pragma pack(pop)

#define WIN_IPPROTO_TCP 6
#define WIN_IPPROTO_UDP 17
#define WIN_IPPROTO_ICMPV6 58

typedef struct
{
  int family; /* 4 or 6 */
  size_t ip_hlen;
  uint8_t proto;
  const unsigned char *l4;
  size_t l4_hlen;
  const unsigned char *payload;
  size_t payload_len;
  uint8_t v4_src[4], v4_dst[4];
  uint8_t v6_src[16], v6_dst[16];
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
    if (pkt_len < (int)sizeof(WinIPv4Header))
      return -1;
    const WinIPv4Header *iph = (const WinIPv4Header *)pkt;
    size_t ihl = iph->ver_ihl & 0x0F;
    size_t ip_hlen = ihl * 4;
    if (ihl < 5 || (int)ip_hlen > pkt_len)
      return -1;
    size_t tot_len = ntohs(iph->tot_len);
    if (tot_len < ip_hlen || (int)tot_len > pkt_len)
      return -1;

    pp->family = 4;
    pp->ip_hlen = ip_hlen;
    pp->proto = iph->protocol;
    memcpy(pp->v4_src, &iph->src, 4);
    memcpy(pp->v4_dst, &iph->dst, 4);
    pp->l4 = pkt + ip_hlen;
    l4_total_avail = tot_len - ip_hlen;
  }
  else if (version == 6)
  {
    if (pkt_len < (int)sizeof(WinIPv6Header))
      return -1;
    const WinIPv6Header *ip6h = (const WinIPv6Header *)pkt;
    size_t plen = ntohs(ip6h->payload_len);
    if (sizeof(WinIPv6Header) + plen > (size_t)pkt_len)
      return -1;

    pp->family = 6;
    pp->ip_hlen = sizeof(WinIPv6Header);
    /* Extension headers are not walked (documented v1 scope limit, same
     * as the other two platforms): next_header is trusted to already
     * name the L4 protocol directly. */
    pp->proto = ip6h->next_header;
    memcpy(pp->v6_src, ip6h->src, 16);
    memcpy(pp->v6_dst, ip6h->dst, 16);
    pp->l4 = pkt + sizeof(WinIPv6Header);
    l4_total_avail = plen;
  }
  else
  {
    return -1;
  }

  if (pp->proto == WIN_IPPROTO_TCP)
  {
    if (l4_total_avail < sizeof(WinTCPHeader))
      return -1;
    const WinTCPHeader *th = (const WinTCPHeader *)pp->l4;
    size_t l4_hlen = ((size_t)(th->data_off_reserved >> 4)) * 4;
    if (l4_hlen < sizeof(WinTCPHeader) || l4_hlen > l4_total_avail)
      return -1;
    pp->l4_hlen = l4_hlen;
    pp->payload = pp->l4 + l4_hlen;
    pp->payload_len = l4_total_avail - l4_hlen;
  }
  else if (pp->proto == WIN_IPPROTO_UDP)
  {
    if (l4_total_avail < sizeof(WinUDPHeader))
      return -1;
    const WinUDPHeader *uh = (const WinUDPHeader *)pp->l4;
    size_t udp_len = ntohs(uh->length);
    if (udp_len < sizeof(WinUDPHeader) || udp_len > l4_total_avail)
      return -1;
    pp->l4_hlen = sizeof(WinUDPHeader);
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
    inet_ntop(AF_INET, pp.v4_src, src_ip, (socklen_t)src_ip_size);
    inet_ntop(AF_INET, pp.v4_dst, dst_ip, (socklen_t)dst_ip_size);
  }
  else
  {
    inet_ntop(AF_INET6, pp.v6_src, src_ip, (socklen_t)src_ip_size);
    inet_ntop(AF_INET6, pp.v6_dst, dst_ip, (socklen_t)dst_ip_size);
  }

  if (pp.proto == WIN_IPPROTO_TCP)
  {
    const WinTCPHeader *th = (const WinTCPHeader *)pp.l4;
    *src_port = ntohs(th->src_port);
    *dst_port = ntohs(th->dst_port);
    *proto_name = "tcp";
  }
  else
  {
    const WinUDPHeader *uh = (const WinUDPHeader *)pp.l4;
    *src_port = ntohs(uh->src_port);
    *dst_port = ntohs(uh->dst_port);
    *proto_name = "udp";
  }
  return 0;
}

int otp_fw_header_length(const unsigned char *pkt, int pkt_len)
{
  ParsedPacket pp;
  if (parse_packet(pkt, pkt_len, &pp) != 0)
    return -1;
  return (int)(pp.ip_hlen + pp.l4_hlen);
}

/* No ICMPv6 check lives in this file: the kernel driver exempts ICMPv6
 * entirely at its own fast-path candidate check (see
 * Driver/otp_firewall_driver.c's otp_fw_driver_is_icmpv6()) before an
 * ICMPv6 packet is ever queued to this userspace service at all - the
 * same reason firewall/linux-kernel-module/otp_firewall.c's exemption
 * lives only in the kernel module, with no matching logic in
 * firewall/linux-kernel-module/packet_codec.c either. */

/* fmemopen() rejects a zero-length buffer. Kept for the ingress/decrypt
 * side, which can legitimately be handed a zero-length ciphertext by an
 * unauthenticated sender - that has to fail meta-header validation
 * cleanly rather than crash. The egress/encrypt side no longer relies on
 * this for the zero-payload case (see PAYLOAD_PAD_LEN below).
 *
 * fmemopen()/open_memstream() are POSIX.1-2008, not part of the Windows
 * CRT - MinGW-w64 (this project's existing Windows toolchain, see
 * src/compat.h and `make mingw`) does provide them, so building this
 * Windows service with MinGW rather than raw MSVC is assumed throughout
 * this file. */
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
 * ("Error: No input data provided") - a bare TCP ACK or empty UDP
 * datagram would otherwise fail to encrypt and get dropped, breaking TCP
 * outright. One fixed sentinel byte is appended to every outgoing
 * payload before encryption so the byte stream handed to
 * encrypt_with_contact() is never actually empty; dropped again on
 * successful decrypt. */
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
  WinIPv4Header *iph = (WinIPv4Header *)out;
  size_t total = ip_hlen + l4_hlen + new_payload_len;
  iph->tot_len = htons((uint16_t)total);
  iph->checksum = 0;
  iph->checksum = otp_fw_ipv4_header_checksum(out, ip_hlen);

  unsigned char *l4 = out + ip_hlen;
  size_t l4_len = l4_hlen + new_payload_len;

  struct in_addr src, dst;
  memcpy(&src, &iph->src, 4);
  memcpy(&dst, &iph->dst, 4);

  if (proto == WIN_IPPROTO_UDP)
  {
    WinUDPHeader *uh = (WinUDPHeader *)l4;
    uh->length = htons((uint16_t)l4_len);
    uh->checksum = 0;
    uh->checksum = otp_fw_l4_checksum_v4(src, dst, proto, l4, l4_len);
    if (uh->checksum == 0)
      uh->checksum = 0xFFFF;
  }
  else
  {
    WinTCPHeader *th = (WinTCPHeader *)l4;
    th->checksum = 0;
    th->checksum = otp_fw_l4_checksum_v4(src, dst, proto, l4, l4_len);
  }
}

static void fix_ipv6_lengths_and_checksums(unsigned char *out, size_t l4_hlen,
                                           size_t new_payload_len, uint8_t proto)
{
  WinIPv6Header *ip6h = (WinIPv6Header *)out;
  size_t l4_len = l4_hlen + new_payload_len;
  ip6h->payload_len = htons((uint16_t)l4_len);

  unsigned char *l4 = out + sizeof(WinIPv6Header);
  struct in6_addr src, dst;
  memcpy(&src, ip6h->src, 16);
  memcpy(&dst, ip6h->dst, 16);

  if (proto == WIN_IPPROTO_UDP)
  {
    WinUDPHeader *uh = (WinUDPHeader *)l4;
    uh->length = htons((uint16_t)l4_len);
    uh->checksum = 0;
    uh->checksum = otp_fw_l4_checksum_v6(src, dst, proto, l4, l4_len);
    if (uh->checksum == 0)
      uh->checksum = 0xFFFF;
  }
  else
  {
    WinTCPHeader *th = (WinTCPHeader *)l4;
    th->checksum = 0;
    th->checksum = otp_fw_l4_checksum_v6(src, dst, proto, l4, l4_len);
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
    inet_ntop(AF_INET, pp->v4_dst, dst_ip, (socklen_t)sizeof(dst_ip));
  else
    inet_ntop(AF_INET6, pp->v6_dst, dst_ip, (socklen_t)sizeof(dst_ip));

  const char *contact_name = fwconfig_contact_for_ip(cfg, dst_ip);
  if (!contact_name)
    return OTP_FW_NO_CONTACT;

  Contact *c = find_contact(contact_name);
  if (!c)
    return OTP_FW_NO_CONTACT;

  *contact_out = c;

  if (c->EncryptionKeySize == 0)
    return OTP_FW_KEY_EXHAUSTED;
  if (!otp_fw_contact_ready(keychain_dir, c, "enc"))
    return OTP_FW_PENDING_RECOVERY;

  return OTP_FW_OK;
}

otp_fw_result_t otp_fw_classify_egress(const char *keychain_dir, const FwConfig *cfg,
                                       const unsigned char *pkt, int pkt_len,
                                       char *contact_out, size_t contact_out_size)
{
  ParsedPacket pp;
  Contact *c = NULL;
  otp_fw_result_t r = resolve_egress_contact(keychain_dir, cfg, pkt, pkt_len, &pp, &c);
  if (c)
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
  if (c)
    snprintf(contact_out, contact_out_size, "%s", c->Name);
  if (resolved != OTP_FW_OK)
    return resolved;
  const char *contact = c->Name;

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
  fclose(outf);

  if (rc != KEYCHAIN_OK)
  {
    free(cipherbuf);
    return rc == KEYCHAIN_REDELIVERED ? OTP_FW_PENDING_RECOVERY : OTP_FW_INTERNAL_ERROR;
  }

  size_t new_total = header_len + cipherlen;
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
      continue;

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
      if (plainlen < PAYLOAD_PAD_LEN)
      {
        free(plainbuf);
        return OTP_FW_INTERNAL_ERROR;
      }
      size_t real_len = plainlen - PAYLOAD_PAD_LEN;
      size_t header_len = pp.ip_hlen + pp.l4_hlen;
      size_t new_total = header_len + real_len;
      size_t decrypted_l4_len = pp.l4_hlen + real_len;
      size_t length_field_limit = pp.family == 4 ? new_total : decrypted_l4_len;
      if (new_total > (size_t)out_cap || length_field_limit > 65535)
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
    if (rc == KEYCHAIN_REDELIVERED)
      saw_pending_recovery = 1;
  }

  if (saw_pending_recovery)
    return OTP_FW_PENDING_RECOVERY;
  return candidates->exclusive ? OTP_FW_PIN_MISMATCH : OTP_FW_AUTH_FAIL;
}

otp_fw_result_t otp_fw_classify_ingress(const CandidateList *candidates,
                                        char *contact_out, size_t contact_out_size)
{
  if (candidates->count == 0)
    return candidates->exclusive ? OTP_FW_PIN_MISMATCH : OTP_FW_NO_CONTACT;
  snprintf(contact_out, contact_out_size, "%s", candidates->names[0]);
  return OTP_FW_NOT_EVALUATED;
}
