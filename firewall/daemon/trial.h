#ifndef OTP_FW_TRIAL_H
#define OTP_FW_TRIAL_H

#include "common.h"
#include "config.h"
#include "pin.h"
#include "keychain.h"

typedef struct
{
  char names[OTP_FW_MAX_CANDIDATES][MAX_NAME_LENGTH];
  int count;
  /* 1 if this list came from a pin: a failure against it must be
   * rejected outright, never fall back to scanning the rest of the
   * keychain (src/pin.h; the exclusivity is an explicit product
   * decision, not a performance shortcut). */
  int exclusive;
} CandidateList;

/* Read-only check (commit_classify(), commit.h:164-167) for whether `c`
 * is safe to hand to encrypt_with_contact()/decrypt_with_contact() for
 * live packet traffic right now. False whenever the contact has a
 * leftover interrupted operation in that direction - see the
 * "Trial-decryption order" section of docs/FIREWALL.md for why calling
 * the real encrypt/decrypt in that state would misbehave. `direction`
 * is "enc" or "dec". */
int otp_fw_contact_ready(const char *keychain_dir, Contact *c, const char *direction);

/* Cheap (O(1) pin lookup, or one otp_fw_contact_ready() check for a
 * firewall.config match): the pin (exclusive) or config-mapped contact
 * for `src_ip`, if either exists. Deliberately does NOT scan the rest of
 * the keychain - see trial_add_fallback_scan() below for why that's
 * split out. */
void trial_select_primary(const char *keychain_dir, const FwConfig *cfg,
                          const PinTable *pins, const char *src_ip, CandidateList *out);

/* Appends every other ready keychain contact not already in `out` (a
 * no-op if `out` is exclusive - a pinned IP never falls back to a full
 * scan, by design). This is the expensive O(keychain size) part of
 * candidate selection: one otp_fw_contact_ready() file check per
 * contact. Call it only after the primary candidate(s) from
 * trial_select_primary() have already been tried and failed - on the
 * common path (a pinned or correctly configured contact validates on
 * the first attempt), this never needs to run at all, instead of
 * scanning the whole keychain on every single inbound packet regardless
 * of whether the scan's results end up being used. */
void trial_add_fallback_scan(const char *keychain_dir, CandidateList *out);

#endif /* OTP_FW_TRIAL_H */
