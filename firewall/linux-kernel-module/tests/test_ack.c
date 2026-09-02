#define _DEFAULT_SOURCE /* mkdtemp() */

#include "test_harness.h"
#include "ack.h"
#include "config.h"

#include "keychain.h"
#include "cipher.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char SID_A[OTP_FW_ACK_SOURCE_ID_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const unsigned char SID_B[OTP_FW_ACK_SOURCE_ID_LEN] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
static const unsigned char HDR[20] = {0}; /* stand-in IPv4+UDP-ish header bytes - content is irrelevant to these tests, only that mark_outstanding accepts and stores it */

static void test_allowed_on_empty_table(void)
{
  AckTable t;
  ack_table_init(&t);
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 1, "a contact with no tracked slot must be allowed to send");
}

static void test_mark_outstanding_blocks_egress(void)
{
  AckTable t;
  ack_table_init(&t);
  TEST_CHECK(ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2 /*AF_INET*/, HDR, sizeof(HDR)) == 0,
            "mark_outstanding should succeed");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 0, "alice must be blocked while a message is outstanding");
  TEST_CHECK(ack_egress_allowed(&t, "bob") == 1, "an unrelated contact must be unaffected");
}

static void test_matching_ack_clears_and_unblocks(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR));
  TEST_CHECK(ack_clear_if_matching(&t, "alice", SID_A) == 1, "a matching source_id must clear the slot");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 1, "alice must be unblocked after a matching ack");
}

static void test_mismatched_ack_is_ignored(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR));
  TEST_CHECK(ack_clear_if_matching(&t, "alice", SID_B) == 0, "a mismatched source_id must not clear the slot");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 0, "alice must remain blocked after a mismatched ack");

  /* An ack for a contact with no outstanding slot at all (stale/unknown/
   * never-tracked) must also be a harmless no-op, never a crash. */
  TEST_CHECK(ack_clear_if_matching(&t, "carol", SID_A) == 0, "an ack for an untracked contact must be ignored");
}

static void test_second_message_reuses_slot(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR));
  ack_clear_if_matching(&t, "alice", SID_A);
  TEST_CHECK_EQ_INT(t.count, 1, "acking a message must not remove the slot, just clear it");

  /* alice sends a second message: same slot, new expected source_id */
  TEST_CHECK(ack_mark_outstanding(&t, "alice", 1, SID_B, "203.0.113.5", 2, HDR, sizeof(HDR)) == 0, "re-marking an existing contact should succeed");
  TEST_CHECK_EQ_INT(t.count, 1, "re-marking an existing contact must not grow the table");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 0, "alice must be blocked again for the new outstanding message");
  TEST_CHECK(ack_clear_if_matching(&t, "alice", SID_A) == 0, "the old source_id must no longer match");
  TEST_CHECK(ack_clear_if_matching(&t, "alice", SID_B) == 1, "the new source_id must match");
}

static void test_clear_contact(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR));
  ack_mark_outstanding(&t, "bob", 1, SID_B, "203.0.113.6", 2, HDR, sizeof(HDR));
  ack_clear_contact(&t, "alice");
  TEST_CHECK_EQ_INT(t.count, 1, "removing one contact's slot should leave exactly one");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 1, "a removed contact has no tracked state, so it reads as allowed again");
  TEST_CHECK(ack_egress_allowed(&t, "bob") == 0, "bob's slot must survive alice's removal");

  /* removing something absent must be a harmless no-op */
  ack_clear_contact(&t, "carol");
  TEST_CHECK_EQ_INT(t.count, 1, "clearing a nonexistent contact must not change the count");
}

typedef struct
{
  int calls;
  char last_contact[MAX_NAME_LENGTH];
} RetryCapture;

static void capture_retry(const AckSlot *slot, void *user_data)
{
  RetryCapture *cap = (RetryCapture *)user_data;
  cap->calls++;
  snprintf(cap->last_contact, sizeof(cap->last_contact), "%s", slot->contact);
}

static void test_scan_timeouts_fires_past_deadline_only(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR));

  RetryCapture cap = {0};
  /* A generous timeout: the slot was just marked, so "now - sent_at" is
   * ~0 seconds - must NOT fire yet. */
  ack_scan_timeouts(&t, 3600, capture_retry, &cap);
  TEST_CHECK_EQ_INT(cap.calls, 0, "a fresh slot must not be retried before its timeout elapses");

  /* timeout_seconds=0: "now - sent_at >= 0" is always true, so this
   * must fire immediately regardless of real elapsed time - proves the
   * comparison itself is wired correctly without needing to sleep(). */
  ack_scan_timeouts(&t, 0, capture_retry, &cap);
  TEST_CHECK_EQ_INT(cap.calls, 1, "a zero-second timeout must fire on the very next scan");
  TEST_CHECK_EQ_STR(cap.last_contact, "alice", "the retry callback must name the right contact");
}

static void test_scan_timeouts_skips_non_outstanding(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR));
  ack_clear_if_matching(&t, "alice", SID_A); /* already acked - nothing to retry */

  RetryCapture cap = {0};
  ack_scan_timeouts(&t, 0, capture_retry, &cap);
  TEST_CHECK_EQ_INT(cap.calls, 0, "an already-acked slot must never be retried");
}

static void test_touch_retry_resets_clock(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR));
  ack_touch_retry(&t, "alice");

  RetryCapture cap = {0};
  /* Right after touch_retry(), a generous timeout must not fire - same
   * check as the fresh-slot case, confirming touch_retry() actually
   * moved sent_at forward rather than being a no-op. */
  ack_scan_timeouts(&t, 3600, capture_retry, &cap);
  TEST_CHECK_EQ_INT(cap.calls, 0, "touch_retry must reset the timeout clock");

  /* touching an untracked contact must be a harmless no-op */
  ack_touch_retry(&t, "carol");
}

/* Recovered-at-startup case (see main.c's recover_outstanding_acks()):
 * a message that was sent before the daemon last restarted, whose
 * ack-ref file (and thus real source_id) could not be found - passing
 * NULL for source_id must still correctly block egress, but must never
 * let ANY incoming ack clear the slot (failing closed rather than
 * accepting an unverified one). */
static void test_recovered_slot_without_source_id_never_clears(void)
{
  AckTable t;
  ack_table_init(&t);
  TEST_CHECK(ack_mark_outstanding(&t, "alice", 3, NULL, "203.0.113.5", 2, HDR, sizeof(HDR)) == 0,
            "mark_outstanding with source_id=NULL should still succeed");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 0, "a recovered slot must still block new egress");

  /* Not even an all-zero source_id (the one value that might
   * accidentally look "unset") may clear it. */
  unsigned char zero_sid[OTP_FW_ACK_SOURCE_ID_LEN] = {0};
  TEST_CHECK(ack_clear_if_matching(&t, "alice", zero_sid) == 0,
            "an all-zero source_id must not clear a slot with no known expected value");
  TEST_CHECK(ack_clear_if_matching(&t, "alice", SID_A) == 0,
            "no source_id at all can clear a slot recovered without one");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 0, "the slot must remain blocked");
}

/* Recovered-at-startup slots also have no header (never persisted) -
 * ack_scan_timeouts() must still surface them to the retry callback
 * (the caller is expected to check slot->header_len itself and skip
 * the actual redeliver - ack.c has no opinion on that, it just reports
 * the slot honestly). */
static void test_recovered_slot_has_zero_header_len(void)
{
  AckTable t;
  ack_table_init(&t);
  ack_mark_outstanding(&t, "alice", 3, NULL, "203.0.113.5", 2, NULL, 0);

  TEST_CHECK_EQ_INT(t.count, 1, "one slot should exist");
  TEST_CHECK_EQ_INT(t.slots[0].header_len, 0, "a slot recovered without a header must report header_len == 0");

  RetryCapture cap = {0};
  ack_scan_timeouts(&t, 0, capture_retry, &cap);
  TEST_CHECK_EQ_INT(cap.calls, 1, "a recovered slot must still be surfaced to the retry callback - the "
                                 "caller, not ack.c, decides to skip the actual redeliver based on header_len");
}

static void test_mark_outstanding_rejects_bad_header_len(void)
{
  AckTable t;
  ack_table_init(&t);
  TEST_CHECK(ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, -1) == -1,
            "a negative header_len must be rejected");
  TEST_CHECK(ack_mark_outstanding(&t, "alice", 1, SID_A, "203.0.113.5", 2, HDR, OTP_FW_ACK_HEADER_CAP + 1) == -1,
            "a header_len beyond OTP_FW_ACK_HEADER_CAP must be rejected");
}

/* ack_clear_if_matching() must discard the ack-ref file on a real match
 * (see ack.h) - exercised here via the real filesystem, matching how
 * ack_read_source_id_file()/ack_discard_source_id_file() themselves are
 * tested implicitly through this round trip. */
static void test_clear_if_matching_discards_ack_ref_file(void)
{
  AckTable t;
  ack_table_init(&t);

  const char *path = "acktestcontact_7_ack_ref.sent.txt";
  FILE *f = fopen(path, "w");
  TEST_CHECK(f != NULL, "test setup: creating a scratch ack-ref file should succeed");
  if (f)
  {
    fputs("0102030405060708090a0b0c0d0e0f10\n", f);
    fclose(f);
  }

  unsigned char sid[OTP_FW_ACK_SOURCE_ID_LEN];
  TEST_CHECK(ack_read_source_id_file("acktestcontact", 7, 1, sid) == 0,
            "reading a well-formed ack-ref file should succeed");
  TEST_CHECK(sid[0] == 0x01 && sid[15] == 0x10, "the parsed source_id bytes should match the file's hex content");

  /* Must NOT have been deleted by the read itself. */
  FILE *still_there = fopen(path, "r");
  TEST_CHECK(still_there != NULL, "ack_read_source_id_file() must not delete the file it read");
  if (still_there)
    fclose(still_there);

  ack_mark_outstanding(&t, "acktestcontact", 7, sid, "203.0.113.5", 2, HDR, sizeof(HDR));
  TEST_CHECK(ack_clear_if_matching(&t, "acktestcontact", sid) == 1, "the real source_id should clear the slot");

  FILE *gone = fopen(path, "r");
  TEST_CHECK(gone == NULL, "a confirmed slot's ack-ref file must be discarded");
  if (gone)
    fclose(gone);

  /* Discarding an already-gone file must be a harmless no-op. */
  ack_discard_source_id_file("acktestcontact", 7, 1);
}

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

/* Real end-to-end exercise of ack_recover_outstanding(), the fix for the
 * crash/restart durability gap (see ack.h's doc comment on it): a real
 * encrypt_with_contact() call (mirrored alice/bob pair, same pattern as
 * test_packet_codec.c) with cipher_set_ack_file(1) produces the exact
 * on-disk state a real daemon leaves behind before a crash - a kept
 * "last sent" copy (src/cipher.c's own keep_last_copy()) plus an
 * ack-ref file - with nothing simulated. */
static void test_recover_outstanding_finds_real_unconfirmed_send(void)
{
  char scratch[] = "/tmp/otp_fw_test_ack_recover.XXXXXX";
  TEST_CHECK(mkdtemp(scratch) != NULL, "mkdtemp for the ack-recovery test scratch dir");
  TEST_CHECK(chdir(scratch) == 0, "chdir into the scratch dir");

  write_random_key_file("keyA", 8192, 11);
  write_random_key_file("keyB", 8192, 22);

  init_keychain();
  TEST_CHECK(load_keychain() == 0, "load_keychain on a fresh directory");
  keychain_set_assume_delivered(1);
  cipher_set_ack_file(1);

  TEST_CHECK(add_contact_with_keys("alice", "keyA", "keyB") == 0, "adding alice (enc=keyA, dec=keyB)");
  TEST_CHECK(add_contact_with_keys("bob", "keyB", "keyA") == 0, "adding bob (enc=keyB, dec=keyA) - the mirror, unused here");

  /* A real encrypt with no matching ack having arrived yet - exactly
   * what's on disk right before an unclean daemon exit. */
  FILE *in = fmemopen((void *)"outstanding message payload", 28, "rb");
  TEST_CHECK(in != NULL, "fmemopen for the plaintext");
  char *cipherbuf = NULL;
  size_t cipherlen = 0;
  FILE *outf = open_memstream(&cipherbuf, &cipherlen);
  TEST_CHECK(outf != NULL, "open_memstream for the ciphertext");
  int rc = encrypt_with_contact("alice", in, outf);
  fclose(in);
  fclose(outf);
  TEST_CHECK_EQ_INT(rc, KEYCHAIN_OK, "the real encrypt_with_contact() call should succeed");
  free(cipherbuf);

  Contact *c = find_contact("alice");
  TEST_CHECK(c != NULL, "alice should be findable after encrypting");
  unsigned char expected_sid[OTP_FW_ACK_SOURCE_ID_LEN];
  int have_expected = c && ack_read_source_id_file("alice", c->EncryptedSequence, 1, expected_sid) == 0;
  TEST_CHECK(have_expected, "a real encrypt with cipher_set_ack_file(1) should leave a readable ack-ref file");

  /* A contact (bob) with nothing ever sent must be left completely
   * alone - the common, non-crash case for most contacts most of the
   * time. */
  AckTable t;
  ack_table_init(&t);
  FwConfig cfg;
  fwconfig_init(&cfg);
  ack_recover_outstanding(&t, &cfg);

  TEST_CHECK(ack_egress_allowed(&t, "alice") == 0,
            "alice's unconfirmed real send must be recovered as outstanding, blocking new egress");
  TEST_CHECK(ack_egress_allowed(&t, "bob") == 1, "bob, who never sent anything, must be left untouched");

  /* The exact real source_id must have been recovered from disk - a
   * genuine ack for this message must now be able to clear it. */
  TEST_CHECK(ack_clear_if_matching(&t, "alice", expected_sid) == 1,
            "the real recovered source_id should clear the slot on a matching ack");
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 1, "alice should be unblocked after the recovered slot is acked");

  fwconfig_free(&cfg);

  /* Confirm src/cipher.c's kept "last sent" copy for alice is STILL on
   * disk - it's only discarded by confirm_previous_delivery() on the
   * NEXT encrypt_with_contact() call for this contact (cipher.c's own
   * internal bookkeeping, unrelated to the real ack above), which
   * hasn't happened. This is the actual, observed library behavior this
   * test relies on, not an assumption. */
  char *drainbuf = NULL;
  size_t drainlen = 0;
  FILE *drain = open_memstream(&drainbuf, &drainlen);
  TEST_CHECK(drain != NULL, "open_memstream for draining the kept copy");
  int drc = keychain_recover_last("alice", 1, drain);
  fclose(drain);
  free(drainbuf);
  TEST_CHECK_EQ_INT(drc, 0, "cipher.c's kept copy for alice must still be present - only a later encrypt call discards it");

  /* The critical case this whole marker mechanism exists for: with the
   * kept copy still present, keychain_recover_last() ALONE cannot tell
   * "confirmed via a real ack, just not yet superseded" apart from
   * "genuinely still outstanding". A second, completely fresh recovery
   * pass (simulating a SECOND restart, immediately after the first) must
   * NOT re-block alice - the durable confirmed-marker written by
   * ack_clear_if_matching()/ack_discard_source_id_file() during the
   * first pass is what makes that possible. Getting this wrong would
   * mean any daemon restart after a contact's last message was
   * successfully delivered permanently blocks that contact until manual
   * intervention - not a rare crash edge case, but the ordinary case.
   *
   * Reuses `t`/`cfg` (re-initialized) rather than declaring a second
   * AckTable local: AckTable is sized for OTP_FW_MAX_ACK_SLOTS
   * (~10000) slots (several MB) - two of those as locals in one stack
   * frame overflows the default stack. */
  ack_table_init(&t);
  fwconfig_init(&cfg);
  ack_recover_outstanding(&t, &cfg);
  TEST_CHECK(ack_egress_allowed(&t, "alice") == 1,
            "a contact whose last message was already confirmed via a real ack must NOT be re-blocked by a later recovery pass");
  fwconfig_free(&cfg);
}

/* The genuinely ambiguous crash case: the message is truly still
 * unconfirmed (no ack was ever received, so no confirmed-marker exists
 * either), but the per-message ack-ref file itself failed to survive
 * the crash (simulated here by deleting it directly, bypassing
 * ack_clear_if_matching() entirely so no confirmed-marker gets
 * written). Recovery must still correctly fail closed: outstanding,
 * source_id unknown, blocking egress until an operator resolves it. */
static void test_recover_outstanding_fails_closed_when_ack_ref_lost(void)
{
  char scratch[] = "/tmp/otp_fw_test_ack_recover_lost.XXXXXX";
  TEST_CHECK(mkdtemp(scratch) != NULL, "mkdtemp for the ack-ref-lost test scratch dir");
  TEST_CHECK(chdir(scratch) == 0, "chdir into the scratch dir");

  write_random_key_file("keyA", 8192, 33);
  write_random_key_file("keyB", 8192, 44);

  init_keychain();
  TEST_CHECK(load_keychain() == 0, "load_keychain on a fresh directory");
  keychain_set_assume_delivered(1);
  cipher_set_ack_file(1);
  TEST_CHECK(add_contact_with_keys("alice", "keyA", "keyB") == 0, "adding alice");

  FILE *in = fmemopen((void *)"a message whose ack-ref gets lost", 34, "rb");
  TEST_CHECK(in != NULL, "fmemopen for the plaintext");
  char *cipherbuf = NULL;
  size_t cipherlen = 0;
  FILE *outf = open_memstream(&cipherbuf, &cipherlen);
  TEST_CHECK(outf != NULL, "open_memstream for the ciphertext");
  int rc = encrypt_with_contact("alice", in, outf);
  fclose(in);
  fclose(outf);
  TEST_CHECK_EQ_INT(rc, KEYCHAIN_OK, "the real encrypt_with_contact() call should succeed");
  free(cipherbuf);

  Contact *c = find_contact("alice");
  TEST_CHECK(c != NULL, "alice should be findable after encrypting");
  if (c)
  {
    char path[700];
    snprintf(path, sizeof(path), "alice_%zu_ack_ref.sent.txt", c->EncryptedSequence);
    TEST_CHECK(remove(path) == 0, "test setup: the ack-ref file should exist and be removable, simulating crash loss");
  }

  AckTable t;
  ack_table_init(&t);
  FwConfig cfg;
  fwconfig_init(&cfg);
  ack_recover_outstanding(&t, &cfg);
  fwconfig_free(&cfg);

  TEST_CHECK(ack_egress_allowed(&t, "alice") == 0,
            "a message with no confirmed-marker and a lost ack-ref file must still fail closed");
  if (c)
  {
    unsigned char zero_sid[OTP_FW_ACK_SOURCE_ID_LEN] = {0};
    TEST_CHECK(ack_clear_if_matching(&t, "alice", zero_sid) == 0,
              "with no known source_id recovered, not even an all-zero ack may clear it");
  }
}

static void test_table_full(void)
{
  AckTable t;
  ack_table_init(&t);
  char contact[MAX_NAME_LENGTH];
  int i;
  for (i = 0; i < OTP_FW_MAX_ACK_SLOTS; i++)
  {
    snprintf(contact, sizeof(contact), "contact-%d", i);
    TEST_CHECK(ack_mark_outstanding(&t, contact, 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR)) == 0,
              "mark_outstanding should succeed while under capacity");
  }
  TEST_CHECK_EQ_INT(t.count, OTP_FW_MAX_ACK_SLOTS, "table should be exactly full");
  TEST_CHECK(ack_mark_outstanding(&t, "one-too-many", 1, SID_A, "203.0.113.5", 2, HDR, sizeof(HDR)) == -1,
            "mark_outstanding on a full table must fail rather than overflow");
}

int main(void)
{
  /* Several tests below use plain in-memory-looking contact names
   * ("alice", "bob", "acktestcontact", ...) purely as AckTable keys, but
   * ack_clear_if_matching()/ack_discard_source_id_file() also has a real
   * disk side effect now (the per-contact confirmed-marker file - see
   * ack.h) wherever it's called with a matching source_id, regardless of
   * whether the test cares about files at all. Running the whole binary
   * from a throwaway scratch directory keeps every test's file activity
   * (this one included) out of the source tree, without having to audit
   * every test individually for what it might touch. */
  char scratch[] = "/tmp/otp_fw_test_ack_main.XXXXXX";
  TEST_CHECK(mkdtemp(scratch) != NULL, "mkdtemp for the whole test binary's scratch dir");
  TEST_CHECK(chdir(scratch) == 0, "chdir into the whole test binary's scratch dir");

  test_allowed_on_empty_table();
  test_mark_outstanding_blocks_egress();
  test_matching_ack_clears_and_unblocks();
  test_mismatched_ack_is_ignored();
  test_second_message_reuses_slot();
  test_clear_contact();
  test_scan_timeouts_fires_past_deadline_only();
  test_scan_timeouts_skips_non_outstanding();
  test_touch_retry_resets_clock();
  test_recovered_slot_without_source_id_never_clears();
  test_recovered_slot_has_zero_header_len();
  test_mark_outstanding_rejects_bad_header_len();
  test_clear_if_matching_discards_ack_ref_file();
  test_recover_outstanding_finds_real_unconfirmed_send();
  test_recover_outstanding_fails_closed_when_ack_ref_lost();
  test_table_full();
  return TEST_REPORT();
}
