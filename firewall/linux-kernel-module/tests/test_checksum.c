#include "test_harness.h"
#include "checksum.h"

#include <arpa/inet.h>
#include <string.h>

/* RFC 1071 section 3's own worked example: summing
 * 0x0001 0xf203 0xf4f5 0xf6f7 folds to 0xddf2; the transmitted checksum
 * is that sum's one's-complement, 0x220d. */
static void test_rfc1071_example(void)
{
  unsigned char data[8] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  uint32_t sum = otp_fw_checksum_add(0, data, sizeof(data));
  uint16_t csum = otp_fw_checksum_fold(sum);
  /* otp_fw_checksum_fold() returns network byte order; the RFC's answer
   * is stated as the two bytes 0x22,0x0d on the wire. */
  unsigned char wire[2];
  memcpy(wire, &csum, 2);
  TEST_CHECK(wire[0] == 0x22 && wire[1] == 0x0d,
            "RFC1071 worked example: expected wire bytes 22 0d, got %02x %02x",
            wire[0], wire[1]);
}

/* A correctly computed checksum, folded back in with the rest of the
 * data, must sum to exactly 0xFFFF (all one bits) - the standard
 * self-verification property of the one's-complement checksum. */
static void test_self_verifies(void)
{
  unsigned char data[8] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  uint32_t sum = otp_fw_checksum_add(0, data, sizeof(data));
  uint16_t csum_be = otp_fw_checksum_fold(sum);

  uint32_t verify = otp_fw_checksum_add(0, data, sizeof(data));
  verify = otp_fw_checksum_add(verify, &csum_be, 2);
  uint16_t result = otp_fw_checksum_fold(verify);
  /* fold(0xFFFF's complement) is 0x0000 in both byte orders. */
  TEST_CHECK(result == 0, "checksum does not self-verify: fold=0x%04x", result);
}

static void test_odd_length_padding(void)
{
  unsigned char a[3] = {0x12, 0x34, 0x56};
  unsigned char b[4] = {0x12, 0x34, 0x56, 0x00};
  uint16_t csum_a = otp_fw_checksum_fold(otp_fw_checksum_add(0, a, 3));
  uint16_t csum_b = otp_fw_checksum_fold(otp_fw_checksum_add(0, b, 4));
  TEST_CHECK(csum_a == csum_b,
            "odd-length input should implicitly zero-pad like an explicit trailing zero byte");
}

static void test_ipv4_header_checksum_self_verifies(void)
{
  /* A minimal, plausible 20-byte IPv4 header with the checksum field
   * zeroed, as the codec always does before computing it. */
  unsigned char hdr[20] = {
     0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
     0x40, 0x06, 0x00, 0x00, /* checksum field: bytes 10-11, zeroed */
     0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
  uint16_t csum = otp_fw_ipv4_header_checksum(hdr, sizeof(hdr));
  memcpy(hdr + 10, &csum, 2);

  uint32_t verify = otp_fw_checksum_add(0, hdr, sizeof(hdr));
  TEST_CHECK(otp_fw_checksum_fold(verify) == 0,
            "IPv4 header checksum does not self-verify once written back into the header");
}

static void test_l4_checksum_v4_changes_with_payload(void)
{
  struct in_addr src, dst;
  src.s_addr = htonl(0xC0A80001);
  dst.s_addr = htonl(0xC0A800C7);
  unsigned char l4_a[12] = "hello world!";
  unsigned char l4_b[12] = "hellO world!"; /* one byte flipped */

  uint16_t csum_a = otp_fw_l4_checksum_v4(src, dst, 17 /* UDP */, l4_a, sizeof(l4_a));
  uint16_t csum_b = otp_fw_l4_checksum_v4(src, dst, 17, l4_b, sizeof(l4_b));
  TEST_CHECK(csum_a != csum_b, "changing a payload byte should change the checksum");

  uint16_t csum_a_again = otp_fw_l4_checksum_v4(src, dst, 17, l4_a, sizeof(l4_a));
  TEST_CHECK(csum_a == csum_a_again, "checksum must be deterministic for identical input");
}

static void test_l4_checksum_v6_changes_with_address(void)
{
  struct in6_addr src, dst1, dst2;
  memset(&src, 0x11, sizeof(src));
  memset(&dst1, 0x22, sizeof(dst1));
  memset(&dst2, 0x33, sizeof(dst2));
  unsigned char l4[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  uint16_t csum1 = otp_fw_l4_checksum_v6(src, dst1, 17, l4, sizeof(l4));
  uint16_t csum2 = otp_fw_l4_checksum_v6(src, dst2, 17, l4, sizeof(l4));
  TEST_CHECK(csum1 != csum2,
            "IPv6 pseudo-header must fold the destination address into the checksum");
}

int main(void)
{
  test_rfc1071_example();
  test_self_verifies();
  test_odd_length_padding();
  test_ipv4_header_checksum_self_verifies();
  test_l4_checksum_v4_changes_with_payload();
  test_l4_checksum_v6_changes_with_address();
  return TEST_REPORT();
}
