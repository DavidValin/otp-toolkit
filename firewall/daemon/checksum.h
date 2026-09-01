#ifndef OTP_FW_CHECKSUM_H
#define OTP_FW_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/* RFC 1071 one's-complement checksum over `len` bytes. `initial` lets
 * callers fold a pseudo-header sum in before the real header/data. */
uint16_t otp_fw_checksum_fold(uint32_t sum);
uint32_t otp_fw_checksum_add(uint32_t initial, const void *data, size_t len);

/* IPv4 header checksum (assumes the checksum field is already zeroed by
 * the caller before summing). */
uint16_t otp_fw_ipv4_header_checksum(const void *iphdr, size_t ip_hlen);

/* TCP/UDP checksum including the IPv4 pseudo-header (RFC 793 / RFC 768). */
uint16_t otp_fw_l4_checksum_v4(struct in_addr src, struct in_addr dst, uint8_t proto,
                               const void *l4, size_t l4_len);

/* TCP/UDP checksum including the IPv6 pseudo-header (RFC 2460 8.1). */
uint16_t otp_fw_l4_checksum_v6(struct in6_addr src, struct in6_addr dst, uint8_t proto,
                               const void *l4, size_t l4_len);

#endif /* OTP_FW_CHECKSUM_H */
