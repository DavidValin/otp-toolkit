#include "trial.h"

#include "commit.h"

#include <string.h>

int otp_fw_contact_ready(const char *keychain_dir, Contact *c, const char *direction)
{
  int is_enc = strcmp(direction, "enc") == 0;
  const char *key_path = is_enc ? c->EncryptionKeyPath : c->DecryptionKeyPath;
  size_t declared_offset = is_enc ? c->EncryptionKeyOffset : c->DecryptionKeyOffset;
  size_t declared_size = is_enc ? c->EncryptionKeySize : c->DecryptionKeySize;

  CommitStatus status;
  if (commit_classify(keychain_dir, c->Name, direction, key_path, declared_offset, declared_size, &status) != 0)
    return 0; /* key file unreadable: fail closed, same as a genuine pending recovery */
  return status.action == COMMIT_RECOVER_NONE;
}

static void add_candidate(CandidateList *out, const char *name)
{
  if (out->count >= OTP_FW_MAX_CANDIDATES)
    return;
  for (int i = 0; i < out->count; i++)
    if (strcmp(out->names[i], name) == 0)
      return;
  snprintf(out->names[out->count], sizeof(out->names[out->count]), "%s", name);
  out->count++;
}

void trial_select_primary(const char *keychain_dir, const FwConfig *cfg,
                          const PinTable *pins, const char *src_ip, CandidateList *out)
{
  out->count = 0;
  out->exclusive = 0;

  const char *pinned = pin_lookup(pins, src_ip);
  if (pinned)
  {
    out->exclusive = 1;
    Contact *c = find_contact(pinned);
    if (c && otp_fw_contact_ready(keychain_dir, c, "dec"))
      add_candidate(out, pinned);
    /* If the pinned contact isn't ready (or was removed), the list is
     * left empty: exclusive means no fallback, and an empty candidate
     * list correctly results in the packet being rejected. */
    return;
  }

  const char *configured = fwconfig_contact_for_ip(cfg, src_ip);
  if (configured)
  {
    Contact *c = find_contact(configured);
    if (c && otp_fw_contact_ready(keychain_dir, c, "dec"))
      add_candidate(out, configured);
  }
}

void trial_add_fallback_scan(const char *keychain_dir, CandidateList *out)
{
  if (out->exclusive)
    return;

  for (int i = 0; i < g_keychain.count; i++)
  {
    Contact *c = &g_keychain.contacts[i];
    if (!otp_fw_contact_ready(keychain_dir, c, "dec"))
      continue;
    add_candidate(out, c->Name);
  }
}
