#define _DEFAULT_SOURCE /* mkstemp() */

#include "test_harness.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Hostname resolution is deliberately not exercised here: it needs real
 * DNS, which isn't hermetic/deterministic for an automated test. Every
 * case below uses literal IP addresses, which fwconfig_resolve() handles
 * via inet_pton() with no network access at all. */

static const char *write_temp_config(const char *contents)
{
  /* Re-snprintf'd fresh on every call: mkstemp() overwrites the trailing
   * XXXXXX in place, so reusing the buffer without resetting the
   * template would hand it a string that no longer ends in XXXXXX on
   * the second and subsequent calls. */
  static char path[64];
  snprintf(path, sizeof(path), "/tmp/otp_fw_test_config.XXXXXX");
  int fd = mkstemp(path);
  TEST_CHECK(fd >= 0, "mkstemp for a test config file");
  FILE *f = fdopen(fd, "w");
  fputs(contents, f);
  fclose(f);
  return path;
}

static void test_parse_basic(void)
{
  const char *path = write_temp_config(
     "# a comment line, and a blank line follow\n"
     "\n"
     "alice 203.0.113.5 203.0.113.6\n"
     "bob   198.51.100.9  # trailing comment on a real line\n");
  FwConfig cfg;
  fwconfig_init(&cfg);
  TEST_CHECK(fwconfig_load(path, &cfg) == 0, "fwconfig_load should succeed on a valid file");
  TEST_CHECK_EQ_INT(cfg.count, 3, "alice has 2 entries, bob has 1: 3 total");
  TEST_CHECK_EQ_STR(cfg.entries[0].contact, "alice", "entry 0 contact");
  TEST_CHECK_EQ_STR(cfg.entries[0].host, "203.0.113.5", "entry 0 host");
  TEST_CHECK_EQ_STR(cfg.entries[1].host, "203.0.113.6", "entry 1 host");
  TEST_CHECK_EQ_STR(cfg.entries[2].contact, "bob", "entry 2 contact");
  TEST_CHECK_EQ_STR(cfg.entries[2].host, "198.51.100.9",
                    "trailing '#' comment must be stripped from the host token");
  fwconfig_free(&cfg);
  unlink(path);
}

static void test_missing_file_is_not_an_error(void)
{
  FwConfig cfg;
  fwconfig_init(&cfg);
  TEST_CHECK(fwconfig_load("/nonexistent/otp_fw_test/firewall.config", &cfg) == 0,
            "a missing config file should load as empty, not fail");
  TEST_CHECK_EQ_INT(cfg.count, 0, "missing file yields zero entries");
  fwconfig_free(&cfg);
}

static void test_resolve_literal_ips_and_contact_lookup(void)
{
  const char *path = write_temp_config("alice 203.0.113.5\nbob 198.51.100.9\n");
  FwConfig cfg;
  fwconfig_init(&cfg);
  fwconfig_load(path, &cfg);
  fwconfig_resolve(&cfg);

  TEST_CHECK_EQ_STR(cfg.entries[0].resolved_ip, "203.0.113.5", "literal IPv4 resolves to itself");
  TEST_CHECK_EQ_STR(fwconfig_contact_for_ip(&cfg, "203.0.113.5"), "alice",
                    "contact lookup by resolved IP");
  TEST_CHECK_EQ_STR(fwconfig_contact_for_ip(&cfg, "198.51.100.9"), "bob",
                    "contact lookup by resolved IP");
  TEST_CHECK(fwconfig_contact_for_ip(&cfg, "192.0.2.1") == NULL,
            "an unlisted IP must not match any contact");

  fwconfig_free(&cfg);
  unlink(path);
}

static void test_candidate_ips_dedup(void)
{
  const char *path = write_temp_config(
     "alice 203.0.113.5 203.0.113.6\n"
     "bob   203.0.113.6\n" /* same address as one of alice's - must not be listed twice */
  );
  FwConfig cfg;
  fwconfig_init(&cfg);
  fwconfig_load(path, &cfg);
  fwconfig_resolve(&cfg);

  char buf[256];
  int n = fwconfig_candidate_ips(&cfg, buf, sizeof(buf));
  TEST_CHECK(n > 0, "candidate_ips should succeed with room to spare");

  int newlines = 0;
  for (int i = 0; i < n; i++)
    if (buf[i] == '\n')
      newlines++;
  TEST_CHECK_EQ_INT(newlines, 2, "203.0.113.6 is shared by two contacts but must appear once");

  fwconfig_free(&cfg);
  unlink(path);
}

static void test_candidate_ips_buffer_too_small(void)
{
  const char *path = write_temp_config("alice 203.0.113.5\n");
  FwConfig cfg;
  fwconfig_init(&cfg);
  fwconfig_load(path, &cfg);
  fwconfig_resolve(&cfg);

  char tiny[4];
  TEST_CHECK(fwconfig_candidate_ips(&cfg, tiny, sizeof(tiny)) == -1,
            "candidate_ips must fail cleanly (not overflow) when the buffer is too small");

  fwconfig_free(&cfg);
  unlink(path);
}

/* Regression test for the bug where fwconfig_load() unconditionally
 * wiped every entry's resolved_ip before reparsing, making
 * fwconfig_resolve()'s "keep the previous address on a transient DNS
 * failure" fallback dead code: a reload with the same (contact, host)
 * pairs must carry the previously resolved address forward, so a
 * transient re-resolve failure afterwards has something to fall back to. */
static void test_reload_preserves_resolved_ip(void)
{
  const char *path = write_temp_config("alice 203.0.113.5\n");
  FwConfig cfg;
  fwconfig_init(&cfg);
  fwconfig_load(path, &cfg);
  /* Simulate an already-resolved entry from a previous run, without
   * depending on fwconfig_resolve()/DNS at all. */
  snprintf(cfg.entries[0].resolved_ip, sizeof(cfg.entries[0].resolved_ip), "203.0.113.5");

  TEST_CHECK(fwconfig_load(path, &cfg) == 0, "reload of the same file should succeed");
  TEST_CHECK_EQ_INT(cfg.count, 1, "reload should reparse the same single entry");
  TEST_CHECK_EQ_STR(cfg.entries[0].resolved_ip, "203.0.113.5",
                    "resolved_ip must survive a reload of an unchanged (contact, host) pair");

  fwconfig_free(&cfg);
  unlink(path);
}

/* A reload where a (contact, host) pair is genuinely new must start
 * unresolved, not accidentally inherit some other entry's address. */
static void test_reload_new_entry_starts_unresolved(void)
{
  const char *path = write_temp_config("alice 203.0.113.5\n");
  FwConfig cfg;
  fwconfig_init(&cfg);
  fwconfig_load(path, &cfg);
  snprintf(cfg.entries[0].resolved_ip, sizeof(cfg.entries[0].resolved_ip), "203.0.113.5");

  FILE *f = fopen(path, "w");
  fputs("alice 203.0.113.5\nbob 198.51.100.9\n", f);
  fclose(f);

  fwconfig_load(path, &cfg);
  TEST_CHECK_EQ_INT(cfg.count, 2, "reload should now see both entries");
  TEST_CHECK_EQ_STR(cfg.entries[0].resolved_ip, "203.0.113.5",
                    "the unchanged entry must keep its resolved address");
  TEST_CHECK_EQ_STR(cfg.entries[1].resolved_ip, "",
                    "a brand-new entry must start unresolved, not inherit another entry's address");

  fwconfig_free(&cfg);
  unlink(path);
}

/* Regression test: a non-ENOENT fopen() failure (permissions, a
 * transient EIO, ...) on a reload must not wipe every configured
 * contact - it must restore the previous good config instead. Opening a
 * directory as a config file reliably fails with EISDIR regardless of
 * privilege level (unlike chmod 000, which root ignores), making it a
 * portable way to force a non-ENOENT failure here. */
static void test_reload_failure_keeps_previous_config(void)
{
  const char *path = write_temp_config("alice 203.0.113.5\n");
  FwConfig cfg;
  fwconfig_init(&cfg);
  TEST_CHECK(fwconfig_load(path, &cfg) == 0, "initial load of a valid config should succeed");
  snprintf(cfg.entries[0].resolved_ip, sizeof(cfg.entries[0].resolved_ip), "203.0.113.5");

  char dir_template[] = "/tmp/otp_fw_test_config_dir.XXXXXX";
  char *dir = mkdtemp(dir_template);
  TEST_CHECK(dir != NULL, "mkdtemp for a directory to force a non-ENOENT fopen() failure");

  TEST_CHECK(fwconfig_load(dir, &cfg) == -1,
            "loading a directory as if it were the config file must fail");
  TEST_CHECK_EQ_INT(cfg.count, 1,
                    "a non-ENOENT load failure must not wipe the previous configuration");
  TEST_CHECK_EQ_STR(cfg.entries[0].contact, "alice",
                    "the previous configuration's contact must survive the failed reload");
  TEST_CHECK_EQ_STR(cfg.entries[0].resolved_ip, "203.0.113.5",
                    "the previous configuration's resolved address must survive too");

  rmdir(dir);
  fwconfig_free(&cfg);
  unlink(path);
}

int main(void)
{
  test_parse_basic();
  test_missing_file_is_not_an_error();
  test_resolve_literal_ips_and_contact_lookup();
  test_candidate_ips_dedup();
  test_candidate_ips_buffer_too_small();
  test_reload_preserves_resolved_ip();
  test_reload_new_entry_starts_unresolved();
  test_reload_failure_keeps_previous_config();
  return TEST_REPORT();
}
