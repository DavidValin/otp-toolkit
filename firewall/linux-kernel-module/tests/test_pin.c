#include "test_harness.h"
#include "pin.h"

static void test_lookup_miss_on_empty(void)
{
  PinTable t;
  pin_init(&t);
  TEST_CHECK(pin_lookup(&t, "203.0.113.5") == NULL, "empty table must miss");
}

static void test_set_then_lookup(void)
{
  PinTable t;
  pin_init(&t);
  TEST_CHECK(pin_set(&t, "203.0.113.5", "alice") == 0, "pin_set should succeed");
  const char *c = pin_lookup(&t, "203.0.113.5");
  TEST_CHECK(c != NULL, "expected a hit after pinning");
  if (c)
    TEST_CHECK_EQ_STR(c, "alice", "pinned contact");
  TEST_CHECK(pin_lookup(&t, "203.0.113.6") == NULL, "unrelated IP must still miss");
}

static void test_overwrite_existing_pin(void)
{
  PinTable t;
  pin_init(&t);
  pin_set(&t, "203.0.113.5", "alice");
  pin_set(&t, "203.0.113.5", "bob"); /* same IP, different contact: reassign in place */
  TEST_CHECK_EQ_INT(t.count, 1, "reassigning an existing IP must not grow the table");
  TEST_CHECK_EQ_STR(pin_lookup(&t, "203.0.113.5"), "bob", "pin should reflect the latest set()");
}

static void test_clear_ip(void)
{
  PinTable t;
  pin_init(&t);
  pin_set(&t, "203.0.113.5", "alice");
  pin_set(&t, "203.0.113.6", "bob");
  pin_clear_ip(&t, "203.0.113.5");
  TEST_CHECK_EQ_INT(t.count, 1, "clearing one IP should leave exactly one entry");
  TEST_CHECK(pin_lookup(&t, "203.0.113.5") == NULL, "cleared IP must miss");
  TEST_CHECK_EQ_STR(pin_lookup(&t, "203.0.113.6"), "bob", "unrelated pin must survive");

  /* clearing something absent must be a harmless no-op */
  pin_clear_ip(&t, "198.51.100.1");
  TEST_CHECK_EQ_INT(t.count, 1, "clearing a nonexistent IP must not change the count");
}

static void test_clear_contact(void)
{
  PinTable t;
  pin_init(&t);
  pin_set(&t, "203.0.113.5", "alice");
  pin_set(&t, "203.0.113.6", "alice");
  pin_set(&t, "203.0.113.7", "bob");
  pin_clear_contact(&t, "alice");
  TEST_CHECK_EQ_INT(t.count, 1, "clearing a contact should remove every pin bound to it");
  TEST_CHECK(pin_lookup(&t, "203.0.113.5") == NULL, "first alice pin must be gone");
  TEST_CHECK(pin_lookup(&t, "203.0.113.6") == NULL, "second alice pin must be gone");
  TEST_CHECK_EQ_STR(pin_lookup(&t, "203.0.113.7"), "bob", "bob's pin must be untouched");
}

static void test_table_full(void)
{
  PinTable t;
  pin_init(&t);
  char ip[OTP_FW_IPSTR_LEN];
  int i;
  for (i = 0; i < OTP_FW_MAX_PINS; i++)
  {
    snprintf(ip, sizeof(ip), "10.%d.%d.%d", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
    TEST_CHECK(pin_set(&t, ip, "alice") == 0, "pin_set should succeed while under capacity");
  }
  TEST_CHECK_EQ_INT(t.count, OTP_FW_MAX_PINS, "table should be exactly full");
  TEST_CHECK(pin_set(&t, "255.255.255.255", "bob") == -1,
            "pin_set on a full table must fail rather than overflow");
}

int main(void)
{
  test_lookup_miss_on_empty();
  test_set_then_lookup();
  test_overwrite_existing_pin();
  test_clear_ip();
  test_clear_contact();
  test_table_full();
  return TEST_REPORT();
}
