#define _DEFAULT_SOURCE /* mkstemp()/mkdtemp() */

#include "test_harness.h"
#include "trial.h"
#include "config.h"
#include "pin.h"

#include "keychain.h"
#include "cipher.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* Three independent (non-mirrored) contacts: candidate-selection order
 * only needs them to exist with valid key material, not to actually
 * decrypt anything for each other. */
static void setup_three_contacts(const char *dir)
{
  TEST_CHECK(mkdir(dir, 0700) == 0 || errno == EEXIST, "creating the test keychain scratch dir");
  TEST_CHECK(chdir(dir) == 0, "chdir into the test keychain scratch dir");

  const char *names[] = {"alice", "bob", "carol"};
  for (int i = 0; i < 3; i++)
  {
    char enc[32], dec[32];
    snprintf(enc, sizeof(enc), "%s_enc_src", names[i]);
    snprintf(dec, sizeof(dec), "%s_dec_src", names[i]);
    write_random_key_file(enc, 4096, (unsigned)(i * 2 + 1));
    write_random_key_file(dec, 4096, (unsigned)(i * 2 + 2));
  }

  init_keychain();
  TEST_CHECK(load_keychain() == 0, "load_keychain on a fresh directory");

  TEST_CHECK(add_contact_with_keys("alice", "alice_enc_src", "alice_dec_src") == 0, "adding alice");
  TEST_CHECK(add_contact_with_keys("bob", "bob_enc_src", "bob_dec_src") == 0, "adding bob");
  TEST_CHECK(add_contact_with_keys("carol", "carol_enc_src", "carol_dec_src") == 0, "adding carol");
}

static int candidates_contain(const CandidateList *c, const char *name)
{
  for (int i = 0; i < c->count; i++)
    if (strcmp(c->names[i], name) == 0)
      return 1;
  return 0;
}

static void test_primary_alone_finds_nothing_without_fallback(const char *keychain_dir)
{
  FwConfig cfg;
  fwconfig_init(&cfg);
  PinTable pins;
  pin_init(&pins);

  CandidateList out;
  trial_select_primary(keychain_dir, &cfg, &pins, "203.0.113.99", &out);

  TEST_CHECK(!out.exclusive, "no pin means the candidate list must not be exclusive");
  TEST_CHECK_EQ_INT(out.count, 0,
                    "trial_select_primary() alone must not scan the keychain - that's the whole point of splitting it out");

  fwconfig_free(&cfg);
}

static void test_fallback_scan_covers_whole_keychain(const char *keychain_dir)
{
  FwConfig cfg;
  fwconfig_init(&cfg);
  PinTable pins;
  pin_init(&pins);

  CandidateList out;
  trial_select_primary(keychain_dir, &cfg, &pins, "203.0.113.99", &out);
  trial_add_fallback_scan(keychain_dir, &out);

  TEST_CHECK(!out.exclusive, "a fallback scan must not itself become exclusive");
  TEST_CHECK_EQ_INT(out.count, 3, "with no pin/config match, the fallback scan is every keychain contact");
  TEST_CHECK(candidates_contain(&out, "alice"), "alice should be a fallback candidate");
  TEST_CHECK(candidates_contain(&out, "bob"), "bob should be a fallback candidate");
  TEST_CHECK(candidates_contain(&out, "carol"), "carol should be a fallback candidate");

  fwconfig_free(&cfg);
}

static void test_configured_contact_tried_first(const char *keychain_dir)
{
  char path[] = "/tmp/otp_fw_test_trial_config.XXXXXX";
  int fd = mkstemp(path);
  TEST_CHECK(fd >= 0, "mkstemp for the trial test config");
  FILE *f = fdopen(fd, "w");
  fprintf(f, "bob 203.0.113.9\n");
  fclose(f);

  FwConfig cfg;
  fwconfig_init(&cfg);
  fwconfig_load(path, &cfg);
  fwconfig_resolve(&cfg);
  unlink(path);

  PinTable pins;
  pin_init(&pins);

  CandidateList out;
  trial_select_primary(keychain_dir, &cfg, &pins, "203.0.113.9", &out);

  TEST_CHECK(!out.exclusive, "a config match alone must not make the list exclusive");
  TEST_CHECK_EQ_INT(out.count, 1, "trial_select_primary() alone should offer just the configured contact");
  TEST_CHECK_EQ_STR(out.names[0], "bob", "the contact configured for this source IP must be the primary candidate");

  trial_add_fallback_scan(keychain_dir, &out);
  TEST_CHECK_EQ_INT(out.count, 3, "a subsequent fallback scan adds the rest of the keychain");
  TEST_CHECK_EQ_STR(out.names[0], "bob", "the configured contact must still be tried first after the fallback scan");

  fwconfig_free(&cfg);
}

static void test_pin_is_exclusive(const char *keychain_dir)
{
  FwConfig cfg;
  fwconfig_init(&cfg);
  PinTable pins;
  pin_init(&pins);
  pin_set(&pins, "203.0.113.50", "carol");

  CandidateList out;
  trial_select_primary(keychain_dir, &cfg, &pins, "203.0.113.50", &out);

  TEST_CHECK(out.exclusive, "a pinned source IP must produce an exclusive candidate list");
  TEST_CHECK_EQ_INT(out.count, 1, "a pinned IP must only ever offer its one pinned contact");
  TEST_CHECK_EQ_STR(out.names[0], "carol", "the pinned contact must be the sole candidate");

  trial_add_fallback_scan(keychain_dir, &out);
  TEST_CHECK(out.exclusive, "fallback scan must not clear the exclusive flag");
  TEST_CHECK_EQ_INT(out.count, 1, "fallback scan must be a no-op on an exclusive (pinned) list");
  TEST_CHECK_EQ_STR(out.names[0], "carol", "the sole candidate must be unchanged after a no-op fallback scan");

  fwconfig_free(&cfg);
}

static void test_pin_to_unknown_contact_yields_no_candidates(const char *keychain_dir)
{
  FwConfig cfg;
  fwconfig_init(&cfg);
  PinTable pins;
  pin_init(&pins);
  pin_set(&pins, "203.0.113.51", "nonexistent-contact");

  CandidateList out;
  trial_select_primary(keychain_dir, &cfg, &pins, "203.0.113.51", &out);

  TEST_CHECK(out.exclusive, "still exclusive: a stale/invalid pin must not silently fall back to a scan");
  TEST_CHECK_EQ_INT(out.count, 0,
                    "a pin to a contact that no longer resolves must yield zero candidates, not a fallback scan");

  trial_add_fallback_scan(keychain_dir, &out);
  TEST_CHECK(out.exclusive, "fallback scan must not clear the exclusive flag even when the list is empty");
  TEST_CHECK_EQ_INT(out.count, 0, "fallback scan must still be a no-op on an exclusive empty list");

  fwconfig_free(&cfg);
}

static void test_unrelated_ip_is_unaffected_by_pins_and_config(const char *keychain_dir)
{
  char path[] = "/tmp/otp_fw_test_trial_config2.XXXXXX";
  int fd = mkstemp(path);
  FILE *f = fdopen(fd, "w");
  fprintf(f, "bob 203.0.113.9\n");
  fclose(f);

  FwConfig cfg;
  fwconfig_init(&cfg);
  fwconfig_load(path, &cfg);
  fwconfig_resolve(&cfg);
  unlink(path);

  PinTable pins;
  pin_init(&pins);
  pin_set(&pins, "203.0.113.50", "carol");

  CandidateList out;
  trial_select_primary(keychain_dir, &cfg, &pins, "198.51.100.200", &out);
  TEST_CHECK(!out.exclusive, "an IP with neither a pin nor a config entry is not exclusive");
  TEST_CHECK_EQ_INT(out.count, 0, "trial_select_primary() alone offers nothing for an unrelated IP");

  trial_add_fallback_scan(keychain_dir, &out);
  TEST_CHECK_EQ_INT(out.count, 3, "the fallback scan still covers the whole keychain for an unrelated IP");

  fwconfig_free(&cfg);
}

int main(void)
{
  char scratch[] = "/tmp/otp_fw_test_trial.XXXXXX";
  TEST_CHECK(mkdtemp(scratch) != NULL, "mkdtemp for the test keychain scratch dir");
  setup_three_contacts(scratch);

  char keychain_dir[512];
  TEST_CHECK(get_keychain_dir(keychain_dir, sizeof(keychain_dir)) == 0, "get_keychain_dir");

  test_primary_alone_finds_nothing_without_fallback(keychain_dir);
  test_fallback_scan_covers_whole_keychain(keychain_dir);
  test_configured_contact_tried_first(keychain_dir);
  test_pin_is_exclusive(keychain_dir);
  test_pin_to_unknown_contact_yields_no_candidates(keychain_dir);
  test_unrelated_ip_is_unaffected_by_pins_and_config(keychain_dir);

  cleanup_keychain();
  return TEST_REPORT();
}
