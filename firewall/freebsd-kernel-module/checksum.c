#include "checksum.h"

#include <string.h>
/* htons()/htonl() live in <winsock2.h> on Windows (linking ws2_32.lib -
 * standard for any Windows networking code) instead of POSIX's
 * <arpa/inet.h>; identical signatures/semantics either way, so this is
 * the only change this file needs to build for Windows too. */
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

/* Byte-shift accumulation (rather than reinterpreting the buffer as an
 * array of uint16_t) is deliberate: it gives the same result regardless
 * of host endianness, with no unaligned-access or strict-aliasing
 * concerns on the raw packet buffer. */
uint32_t otp_fw_checksum_add(uint32_t sum, const void *data, size_t len)
{
  const uint8_t *p = (const uint8_t *)data;
  size_t i = 0;
  for (; i + 1 < len; i += 2)
    sum += ((uint32_t)p[i] << 8) | p[i + 1];
  if (i < len)
    sum += ((uint32_t)p[i] << 8);
  return sum;
}

uint16_t otp_fw_checksum_fold(uint32_t sum)
{
  while (sum >> 16)
    sum = (sum & 0xFFFFu) + (sum >> 16);
  uint16_t host_order = (uint16_t)~sum;
  return htons(host_order);
}

uint16_t otp_fw_ipv4_header_checksum(const void *iphdr, size_t ip_hlen)
{
  uint32_t sum = otp_fw_checksum_add(0, iphdr, ip_hlen);
  return otp_fw_checksum_fold(sum);
}

uint16_t otp_fw_l4_checksum_v4(struct in_addr src, struct in_addr dst, uint8_t proto,
                               const void *l4, size_t l4_len)
{
  uint8_t pseudo[12];
  memcpy(pseudo, &src, 4);
  memcpy(pseudo + 4, &dst, 4);
  pseudo[8] = 0;
  pseudo[9] = proto;
  uint16_t len_be = htons((uint16_t)l4_len);
  memcpy(pseudo + 10, &len_be, 2);

  uint32_t sum = otp_fw_checksum_add(0, pseudo, sizeof(pseudo));
  sum = otp_fw_checksum_add(sum, l4, l4_len);
  return otp_fw_checksum_fold(sum);
}

uint16_t otp_fw_l4_checksum_v6(struct in6_addr src, struct in6_addr dst, uint8_t proto,
                               const void *l4, size_t l4_len)
{
  uint8_t pseudo[40];
  memcpy(pseudo, &src, 16);
  memcpy(pseudo + 16, &dst, 16);
  uint32_t len_be = htonl((uint32_t)l4_len);
  memcpy(pseudo + 32, &len_be, 4);
  pseudo[36] = 0;
  pseudo[37] = 0;
  pseudo[38] = 0;
  pseudo[39] = proto;

  uint32_t sum = otp_fw_checksum_add(0, pseudo, sizeof(pseudo));
  sum = otp_fw_checksum_add(sum, l4, l4_len);
  return otp_fw_checksum_fold(sum);
}
