// SPDX-License-Identifier: Dual BSD/GPL
/*
 * KUnit test for otp_fw_is_candidate() in ../../otp_firewall.c - the
 * in-kernel IP-matching lookup the netfilter hooks use to decide
 * whether a packet is even worth queuing to userspace.
 *
 * NOT verified in the environment this was written in: no linux-headers
 * package was installed there (see ../README.md), so this could not be
 * built or run against a real kernel/KUnit tree. Written carefully
 * against documented, long-stable KUnit API, but treat it as
 * reviewed-but-unverified - read it before trusting it, the same way
 * you would the kernel module itself.
 *
 * This #includes the module's .c file directly rather than linking
 * against it, which is the standard KUnit idiom for testing functions
 * that are `static` (otp_fw_is_candidate(), and the module-global
 * g_candidates/g_candidate_count/g_candidates_lock it reads, are all
 * private to otp_firewall.c). Build and load THIS test module on its
 * own to run it - never alongside a separately loaded otp_firewall.ko,
 * since both would define the same module_init/module_exit and struct
 * proc_ops names.
 */

#include <kunit/test.h>
#include "../../otp_firewall.c"

/* Builds a __be32 from four octets explicitly, network byte order -
 * there's no standard kernel helper for this literal construction. */
#define V4(a, b, c, d) \
  htonl(((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | (u32)(d))

static void reset_candidates(void)
{
  write_lock_bh(&g_candidates_lock);
  g_candidate_count = 0;
  write_unlock_bh(&g_candidates_lock);
}

static int otp_fw_test_init(struct kunit *test)
{
  reset_candidates();
  return 0;
}

static void otp_fw_test_empty_table_never_matches(struct kunit *test)
{
  __be32 v4 = V4(203, 0, 113, 5);
  struct in6_addr v6;
  memset(&v6, 0x11, sizeof(v6));

  KUNIT_EXPECT_FALSE(test, otp_fw_is_candidate(AF_INET, v4, &v6));
  KUNIT_EXPECT_FALSE(test, otp_fw_is_candidate(AF_INET6, v4, &v6));
}

static void otp_fw_test_v4_exact_match(struct kunit *test)
{
  __be32 target = V4(203, 0, 113, 5);
  __be32 other = V4(203, 0, 113, 6);
  struct in6_addr unused;
  memset(&unused, 0, sizeof(unused));

  g_candidates[0].family = AF_INET;
  g_candidates[0].addr.v4 = target;
  g_candidate_count = 1;

  KUNIT_EXPECT_TRUE(test, otp_fw_is_candidate(AF_INET, target, &unused));
  KUNIT_EXPECT_FALSE(test, otp_fw_is_candidate(AF_INET, other, &unused));
}

static void otp_fw_test_v6_exact_match(struct kunit *test)
{
  struct in6_addr target, other;
  __be32 unused_v4 = 0;
  memset(&target, 0xAA, sizeof(target));
  memset(&other, 0xBB, sizeof(other));

  g_candidates[0].family = AF_INET6;
  g_candidates[0].addr.v6 = target;
  g_candidate_count = 1;

  KUNIT_EXPECT_TRUE(test, otp_fw_is_candidate(AF_INET6, unused_v4, &target));
  KUNIT_EXPECT_FALSE(test, otp_fw_is_candidate(AF_INET6, unused_v4, &other));
}

/* A v4 candidate must never match a v6 query carrying the same raw
 * bytes, and vice versa - family has to gate the comparison, not just
 * the address bytes. */
static void otp_fw_test_family_is_not_ignored(struct kunit *test)
{
  __be32 v4 = V4(0, 0, 0, 0);
  struct in6_addr v6;
  memset(&v6, 0, sizeof(v6));

  g_candidates[0].family = AF_INET;
  g_candidates[0].addr.v4 = v4;
  g_candidate_count = 1;

  KUNIT_EXPECT_FALSE(test, otp_fw_is_candidate(AF_INET6, v4, &v6));
}

static void otp_fw_test_replace_on_write_drops_stale_entries(struct kunit *test)
{
  __be32 stale = V4(203, 0, 113, 5);
  __be32 fresh = V4(198, 51, 100, 9);
  struct in6_addr unused;
  memset(&unused, 0, sizeof(unused));

  g_candidates[0].family = AF_INET;
  g_candidates[0].addr.v4 = stale;
  g_candidate_count = 1;
  KUNIT_EXPECT_TRUE(test, otp_fw_is_candidate(AF_INET, stale, &unused));

  /* Simulates what candidates_write() does on each push: replace the
   * whole table rather than append to it. */
  write_lock_bh(&g_candidates_lock);
  g_candidates[0].addr.v4 = fresh;
  g_candidate_count = 1;
  write_unlock_bh(&g_candidates_lock);

  KUNIT_EXPECT_FALSE(test, otp_fw_is_candidate(AF_INET, stale, &unused));
  KUNIT_EXPECT_TRUE(test, otp_fw_is_candidate(AF_INET, fresh, &unused));
}

static struct kunit_case otp_fw_test_cases[] = {
   KUNIT_CASE(otp_fw_test_empty_table_never_matches),
   KUNIT_CASE(otp_fw_test_v4_exact_match),
   KUNIT_CASE(otp_fw_test_v6_exact_match),
   KUNIT_CASE(otp_fw_test_family_is_not_ignored),
   KUNIT_CASE(otp_fw_test_replace_on_write_drops_stale_entries),
   {}
};

static struct kunit_suite otp_fw_test_suite = {
   .name = "otp_firewall_candidates",
   .init = otp_fw_test_init,
   .test_cases = otp_fw_test_cases,
};

kunit_test_suite(otp_fw_test_suite);

MODULE_LICENSE("Dual BSD/GPL");
