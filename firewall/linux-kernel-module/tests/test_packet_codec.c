#define _DEFAULT_SOURCE /* mkstemp()/mkdtemp() */

#include "test_harness.h"
#include "packet_codec.h"
#include "checksum.h"
#include "config.h"
#include "trial.h"

#include "keychain.h"
#include "cipher.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- test keychain setup -------------------------------------------------
 *
 * alice and bob are the "mirrored pair, one machine playing both
 * endpoints" case the core library explicitly supports for loopback
 * testing (see the comment above add_contact_with_keys_locked() in
 * src/keychain.c): alice's encryption key and bob's decryption key are
 * copies of the same underlying bytes, and vice versa, so
 *   encrypt_with_contact("alice", ...) then decrypt_with_contact("bob", ...)
 * on the result is a genuine, correct round trip - not a test-only
 * shortcut - even though both contacts live in one local test keychain.
 */

static void write_random_key_file(const char *path, size_t size, unsigned seed)
{
  FILE *f = fopen(path, "wb");
  TEST_CHECK(f != NULL, "creating a test key file");
  unsigned state = seed;
  for (size_t i = 0; i < size; i++)
  {
    state = state * 1103515245u + 12345u;
    unsigned char byte = (unsigned char)(state >> 16);
    fwrite(&byte, 1, 1, f);
  }
  fclose(f);
}

static void setup_test_keychain(const char *dir)
{
  TEST_CHECK(mkdir(dir, 0700) == 0 || errno == EEXIST, "creating the test keychain scratch dir");
  TEST_CHECK(chdir(dir) == 0, "chdir into the test keychain scratch dir");

  write_random_key_file("keyA", 8192, 1);
  write_random_key_file("keyB", 8192, 2);

  init_keychain();
  TEST_CHECK(load_keychain() == 0, "load_keychain on a fresh directory");
  keychain_set_assume_delivered(1);

  TEST_CHECK(add_contact_with_keys("alice", "keyA", "keyB") == 0,
            "adding alice (enc=keyA, dec=keyB)");
  TEST_CHECK(add_contact_with_keys("bob", "keyB", "keyA") == 0,
            "adding bob (enc=keyB, dec=keyA) - the mirror");
}

/* Builds a FwConfig mapping `contact` to `ip` via the real public API
 * (a temp config file + fwconfig_load + fwconfig_resolve), rather than
 * reaching into FwConfig's internals: fwconfig_append() is private to
 * config.c, and going through the same file-based path production code
 * uses keeps this fixture honest. The IP is a literal, so resolution
 * never touches DNS. */
static void build_single_entry_config(FwConfig *cfg, const char *contact, const char *ip)
{
  char path[] = "/tmp/otp_fw_test_codec_config.XXXXXX";
  int fd = mkstemp(path);
  TEST_CHECK(fd >= 0, "mkstemp for the packet_codec test config");
  FILE *f = fdopen(fd, "w");
  fprintf(f, "%s %s\n", contact, ip);
  fclose(f);

  fwconfig_init(cfg);
  TEST_CHECK(fwconfig_load(path, cfg) == 0, "loading the single-entry test config");
  fwconfig_resolve(cfg);
  unlink(path);
}

/* ---- raw packet construction ----------------------------------------------
 * These fixtures carry correct checksums themselves (parse_packet() never
 * validates them, but computing them properly keeps the fixtures
 * realistic and lets the round-trip tests below compare against the
 * original bytes meaningfully). */

static int build_ipv4_udp(unsigned char *buf, const char *src_ip, unsigned src_port,
                          const char *dst_ip, unsigned dst_port,
                          const unsigned char *payload, size_t payload_len)
{
  struct iphdr *iph = (struct iphdr *)buf;
  struct udphdr *uh = (struct udphdr *)(buf + 20);
  size_t total = 20 + 8 + payload_len;

  memset(iph, 0, 20);
  iph->version = 4;
  iph->ihl = 5;
  iph->tot_len = htons((uint16_t)total);
  iph->ttl = 64;
  iph->protocol = IPPROTO_UDP;
  inet_pton(AF_INET, src_ip, &iph->saddr);
  inet_pton(AF_INET, dst_ip, &iph->daddr);
  iph->check = otp_fw_ipv4_header_checksum(iph, 20);

  uh->source = htons((uint16_t)src_port);
  uh->dest = htons((uint16_t)dst_port);
  uh->len = htons((uint16_t)(8 + payload_len));
  memcpy(buf + 28, payload, payload_len);
  uh->check = 0;
  struct in_addr s, d;
  memcpy(&s, &iph->saddr, 4);
  memcpy(&d, &iph->daddr, 4);
  uh->check = otp_fw_l4_checksum_v4(s, d, IPPROTO_UDP, uh, 8 + payload_len);

  return (int)total;
}

static int build_ipv4_tcp(unsigned char *buf, const char *src_ip, unsigned src_port,
                          const char *dst_ip, unsigned dst_port,
                          const unsigned char *payload, size_t payload_len)
{
  struct iphdr *iph = (struct iphdr *)buf;
  struct tcphdr *th = (struct tcphdr *)(buf + 20);
  size_t total = 20 + 20 + payload_len;

  memset(iph, 0, 20);
  iph->version = 4;
  iph->ihl = 5;
  iph->tot_len = htons((uint16_t)total);
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  inet_pton(AF_INET, src_ip, &iph->saddr);
  inet_pton(AF_INET, dst_ip, &iph->daddr);
  iph->check = otp_fw_ipv4_header_checksum(iph, 20);

  memset(th, 0, 20);
  th->source = htons((uint16_t)src_port);
  th->dest = htons((uint16_t)dst_port);
  th->seq = htonl(1000);
  th->doff = 5;
  th->ack = 1;
  th->window = htons(65535);
  memcpy(buf + 40, payload, payload_len);
  th->check = 0;
  struct in_addr s, d;
  memcpy(&s, &iph->saddr, 4);
  memcpy(&d, &iph->daddr, 4);
  th->check = otp_fw_l4_checksum_v4(s, d, IPPROTO_TCP, th, 20 + payload_len);

  return (int)total;
}

static int build_ipv6_udp(unsigned char *buf, const char *src_ip, unsigned src_port,
                          const char *dst_ip, unsigned dst_port,
                          const unsigned char *payload, size_t payload_len)
{
  struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
  struct udphdr *uh = (struct udphdr *)(buf + 40);
  size_t l4_len = 8 + payload_len;

  memset(ip6, 0, 40);
  ip6->ip6_vfc = 0x60;
  ip6->ip6_plen = htons((uint16_t)l4_len);
  ip6->ip6_nxt = IPPROTO_UDP;
  ip6->ip6_hlim = 64;
  inet_pton(AF_INET6, src_ip, &ip6->ip6_src);
  inet_pton(AF_INET6, dst_ip, &ip6->ip6_dst);

  uh->source = htons((uint16_t)src_port);
  uh->dest = htons((uint16_t)dst_port);
  uh->len = htons((uint16_t)l4_len);
  memcpy(buf + 48, payload, payload_len);
  uh->check = 0;
  uh->check = otp_fw_l4_checksum_v6(ip6->ip6_src, ip6->ip6_dst, IPPROTO_UDP, uh, l4_len);

  return (int)(40 + l4_len);
}

/* ---- tests ----------------------------------------------------------------- */

static const unsigned char PAYLOAD[] = "hello from the otp-toolkit firewall test suite";
#define PAYLOAD_LEN (sizeof(PAYLOAD) - 1)

static void roundtrip(const char *keychain_dir, const char *dst_ip,
                      unsigned char *pkt, int pkt_len, const char *label)
{
  FwConfig cfg;
  build_single_entry_config(&cfg, "alice", dst_ip);

  unsigned char out[2048];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = otp_fw_encrypt_packet(keychain_dir, &cfg, pkt, pkt_len,
                                            out, sizeof(out), &out_len, contact, sizeof(contact));
  TEST_CHECK(r == OTP_FW_OK, "%s: encrypt_packet should succeed", label);
  TEST_CHECK_EQ_STR(contact, "alice", "encrypted contact");
  TEST_CHECK(out_len > pkt_len, "%s: an OTP-wrapped packet must grow", label);

  CandidateList candidates;
  candidates.count = 1;
  candidates.exclusive = 0;
  snprintf(candidates.names[0], sizeof(candidates.names[0]), "bob");

  unsigned char plain[2048];
  int plain_len = 0;
  char dec_contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t dr = otp_fw_decrypt_packet(keychain_dir, &candidates, out, out_len,
                                             plain, sizeof(plain), &plain_len,
                                             dec_contact, sizeof(dec_contact));
  TEST_CHECK(dr == OTP_FW_OK, "%s: decrypt_packet against the mirrored contact should succeed", label);
  TEST_CHECK_EQ_STR(dec_contact, "bob", "decrypted contact");
  char size_label[128];
  snprintf(size_label, sizeof(size_label), "%s: round-tripped packet size", label);
  TEST_CHECK_EQ_INT(plain_len, pkt_len, size_label);
  TEST_CHECK(memcmp(plain, pkt, (size_t)pkt_len) == 0,
            "%s: round-tripped packet must be byte-identical to the original", label);

  fwconfig_free(&cfg);
}

static void test_roundtrip_ipv4_udp(const char *keychain_dir)
{
  unsigned char pkt[512];
  int len = build_ipv4_udp(pkt, "203.0.113.7", 5000, "198.51.100.50", 53, PAYLOAD, PAYLOAD_LEN);
  roundtrip(keychain_dir, "198.51.100.50", pkt, len, "ipv4/udp");
}

static void test_roundtrip_ipv4_tcp(const char *keychain_dir)
{
  unsigned char pkt[512];
  int len = build_ipv4_tcp(pkt, "203.0.113.7", 5000, "198.51.100.50", 443, PAYLOAD, PAYLOAD_LEN);
  roundtrip(keychain_dir, "198.51.100.50", pkt, len, "ipv4/tcp");
}

static void test_roundtrip_ipv4_tcp_empty_payload(const char *keychain_dir)
{
  /* A bare ACK: zero-length payload. cipher.c refuses to encrypt a
   * genuinely empty message ("No input data provided") - see the
   * sentinel-byte padding in otp_fw_encrypt_packet()/otp_fw_decrypt_packet()
   * that exists specifically so this case still works. */
  unsigned char pkt[512];
  int len = build_ipv4_tcp(pkt, "203.0.113.7", 5000, "198.51.100.50", 443, PAYLOAD, 0);
  roundtrip(keychain_dir, "198.51.100.50", pkt, len, "ipv4/tcp empty payload");
}

static void test_roundtrip_ipv6_udp(const char *keychain_dir)
{
  unsigned char pkt[512];
  int len = build_ipv6_udp(pkt, "2001:db8::7", 5000, "2001:db8::50", 53, PAYLOAD, PAYLOAD_LEN);
  roundtrip(keychain_dir, "2001:db8::50", pkt, len, "ipv6/udp");
}

/* Regression test: --mode=log-only must never spend key material.
 * otp_fw_classify_egress() has to report the same verdict as a real
 * encrypt without ever touching the contact's key offset/size. */
static void test_classify_egress_does_not_spend_key(const char *keychain_dir)
{
  FwConfig cfg;
  build_single_entry_config(&cfg, "alice", "198.51.100.51");

  Contact *before = find_contact("alice");
  size_t offset_before = before->EncryptionKeyOffset;
  size_t size_before = before->EncryptionKeySize;
  size_t seq_before = before->EncryptedSequence;

  unsigned char pkt[512];
  int len = build_ipv4_udp(pkt, "203.0.113.7", 5000, "198.51.100.51", 53, PAYLOAD, PAYLOAD_LEN);

  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = otp_fw_classify_egress(keychain_dir, &cfg, pkt, len, contact, sizeof(contact));
  TEST_CHECK(r == OTP_FW_OK, "classify_egress should report a match for a configured destination");
  TEST_CHECK_EQ_STR(contact, "alice", "classify_egress contact");

  Contact *after = find_contact("alice");
  TEST_CHECK_EQ_INT(after->EncryptionKeyOffset, offset_before,
                    "classify_egress must not advance the encryption key offset");
  TEST_CHECK_EQ_INT(after->EncryptionKeySize, size_before,
                    "classify_egress must not shrink the encryption key");
  TEST_CHECK_EQ_INT(after->EncryptedSequence, seq_before,
                    "classify_egress must not advance the encrypted-message sequence");

  fwconfig_free(&cfg);
}

/* Same regression, ingress side: otp_fw_classify_ingress() must never
 * call decrypt_with_contact(), so it must never touch bob's key either -
 * and per its documented contract, it must never report OTP_FW_OK, since
 * that would be an unearned claim of a validation it didn't perform. */
static void test_classify_ingress_does_not_spend_key(void)
{
  Contact *before = find_contact("bob");
  size_t offset_before = before->DecryptionKeyOffset;
  size_t size_before = before->DecryptionKeySize;

  CandidateList candidates;
  candidates.count = 1;
  candidates.exclusive = 0;
  snprintf(candidates.names[0], sizeof(candidates.names[0]), "bob");

  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = otp_fw_classify_ingress(&candidates, contact, sizeof(contact));
  TEST_CHECK(r == OTP_FW_NOT_EVALUATED,
            "classify_ingress with a nonempty candidate list must report NOT_EVALUATED, never OK");
  TEST_CHECK_EQ_STR(contact, "bob", "classify_ingress should still report the top candidate as a hint");

  Contact *after = find_contact("bob");
  TEST_CHECK_EQ_INT(after->DecryptionKeyOffset, offset_before,
                    "classify_ingress must not advance the decryption key offset");
  TEST_CHECK_EQ_INT(after->DecryptionKeySize, size_before,
                    "classify_ingress must not shrink the decryption key");
}

static void test_classify_ingress_empty_candidates(void)
{
  CandidateList empty;
  empty.count = 0;
  empty.exclusive = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  TEST_CHECK(otp_fw_classify_ingress(&empty, contact, sizeof(contact)) == OTP_FW_NO_CONTACT,
            "an empty, non-exclusive candidate list classifies as no-matching-contact");

  CandidateList exclusive_empty;
  exclusive_empty.count = 0;
  exclusive_empty.exclusive = 1;
  TEST_CHECK(otp_fw_classify_ingress(&exclusive_empty, contact, sizeof(contact)) == OTP_FW_PIN_MISMATCH,
            "an empty, exclusive (pinned) candidate list classifies as pin-mismatch");
}

/* Regression test: encrypt_packet's own pre-check (the 65535-byte
 * length-field ceiling, checked BEFORE calling encrypt_with_contact())
 * must be what rejects this packet - not cipher.c running out of key
 * material first, which would exercise a different rejection path and
 * prove nothing about the pre-check itself. That needs a key file large
 * enough that key size was never going to be the limiting factor. */
static void test_length_field_ceiling_rejected_before_encrypting(const char *keychain_dir)
{
  write_random_key_file("keyHuge", 100000, 99);
  write_random_key_file("keyHugeDec", 4096, 100);
  TEST_CHECK(add_contact_with_keys("dave", "keyHuge", "keyHugeDec") == 0,
            "adding a contact with a key large enough that size alone can't explain a rejection");

  FwConfig cfg;
  build_single_entry_config(&cfg, "dave", "198.51.100.54");

  Contact *before = find_contact("dave");
  size_t offset_before = before->EncryptionKeyOffset;

  /* header(28) + payload + PAYLOAD_PAD_LEN(1) + OTP_FW_MAX_GROWTH(128)
   * must exceed 65535 while staying under out_cap, so it's specifically
   * the length-field check that fires. */
  static unsigned char huge_payload[65500];
  memset(huge_payload, 'A', sizeof(huge_payload));
  unsigned char pkt[65600];
  int len = build_ipv4_udp(pkt, "203.0.113.7", 5000, "198.51.100.54", 53,
                           huge_payload, sizeof(huge_payload));

  unsigned char out[70000];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r = otp_fw_encrypt_packet(keychain_dir, &cfg, pkt, len,
                                            out, sizeof(out), &out_len, contact, sizeof(contact));
  TEST_CHECK(r == OTP_FW_INTERNAL_ERROR, "a packet that would exceed the 65535-byte length field must be rejected");

  Contact *after = find_contact("dave");
  TEST_CHECK_EQ_INT(after->EncryptionKeyOffset, offset_before,
                    "rejecting it must not have spent any key material - the pre-check runs before encrypting");

  fwconfig_free(&cfg);
}

static void test_key_exhausted(const char *keychain_dir)
{
  FwConfig cfg;
  build_single_entry_config(&cfg, "alice", "198.51.100.53");

  Contact *c = find_contact("alice");
  size_t saved_size = c->EncryptionKeySize;
  c->EncryptionKeySize = 0; /* simulate exhaustion without actually draining 8KB of test key */

  unsigned char pkt[512];
  int len = build_ipv4_udp(pkt, "203.0.113.7", 5000, "198.51.100.53", 53, PAYLOAD, PAYLOAD_LEN);
  unsigned char out[1024];
  int out_len = 0;
  char contact[MAX_NAME_LENGTH] = {0};

  TEST_CHECK(otp_fw_encrypt_packet(keychain_dir, &cfg, pkt, len, out, sizeof(out), &out_len,
                                   contact, sizeof(contact)) == OTP_FW_KEY_EXHAUSTED,
            "encrypt_packet must report key exhaustion rather than attempt anything");
  /* Regression: the contact must be named in the log even on a failure
   * for an already-identified contact - "run otp --status <contact>"
   * (the documented remediation) isn't actionable from a log line that
   * just says "-" because contact_out was never populated. */
  TEST_CHECK_EQ_STR(contact, "alice",
                    "encrypt_packet must still report which contact was exhausted");

  memset(contact, 0, sizeof(contact));
  TEST_CHECK(otp_fw_classify_egress(keychain_dir, &cfg, pkt, len, contact, sizeof(contact)) ==
                OTP_FW_KEY_EXHAUSTED,
            "classify_egress must agree with encrypt_packet about key exhaustion");
  TEST_CHECK_EQ_STR(contact, "alice",
                    "classify_egress must also report which contact was exhausted");

  c->EncryptionKeySize = saved_size;
  fwconfig_free(&cfg);
}

static void test_describe_packet(void)
{
  unsigned char pkt[512];
  int len = build_ipv4_udp(pkt, "203.0.113.7", 5000, "198.51.100.50", 53, PAYLOAD, PAYLOAD_LEN);

  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  TEST_CHECK(otp_fw_describe_packet(pkt, len, src_ip, sizeof(src_ip), &src_port,
                                    dst_ip, sizeof(dst_ip), &dst_port, &proto) == 0,
            "describe_packet on a well-formed packet");
  TEST_CHECK_EQ_STR(src_ip, "203.0.113.7", "described source IP");
  TEST_CHECK_EQ_STR(dst_ip, "198.51.100.50", "described destination IP");
  TEST_CHECK_EQ_INT(src_port, 5000, "described source port");
  TEST_CHECK_EQ_INT(dst_port, 53, "described destination port");
  TEST_CHECK_EQ_STR(proto, "udp", "described protocol");

  char garbage[4] = {0x00, 0x01, 0x02, 0x03};
  TEST_CHECK(otp_fw_describe_packet((unsigned char *)garbage, sizeof(garbage), src_ip, sizeof(src_ip),
                                    &src_port, dst_ip, sizeof(dst_ip), &dst_port, &proto) == -1,
            "describe_packet on unparsable garbage must fail cleanly, not crash");
}

int main(void)
{
  char scratch[] = "/tmp/otp_fw_test_codec.XXXXXX";
  TEST_CHECK(mkdtemp(scratch) != NULL, "mkdtemp for the test keychain scratch dir");
  setup_test_keychain(scratch);

  char keychain_dir[512];
  TEST_CHECK(get_keychain_dir(keychain_dir, sizeof(keychain_dir)) == 0, "get_keychain_dir");

  test_roundtrip_ipv4_udp(keychain_dir);
  test_roundtrip_ipv4_tcp(keychain_dir);
  test_roundtrip_ipv4_tcp_empty_payload(keychain_dir);
  test_roundtrip_ipv6_udp(keychain_dir);
  test_classify_egress_does_not_spend_key(keychain_dir);
  test_classify_ingress_does_not_spend_key();
  test_classify_ingress_empty_candidates();
  test_length_field_ceiling_rejected_before_encrypting(keychain_dir);
  test_key_exhausted(keychain_dir);
  test_describe_packet();

  cleanup_keychain();
  return TEST_REPORT();
}
