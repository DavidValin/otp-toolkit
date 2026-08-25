/*****************************************************************************\
 *                                                                           *
 *   keychain.h - Keychain management for OTP contacts                       *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <time.h>
#include <stdio.h>

#define MAX_CONTACTS 10000
#define MAX_NAME_LENGTH 256
#define MAX_KEY_SIZE 1099511627776ULL // 1TB max key size per contact
#define MIN_RETRY_COUNT 0
#define MAX_RETRY_COUNT 25000

typedef struct
{
  char Name[MAX_NAME_LENGTH];
  char EncryptionKeyPath[512];    // Path to encryption key file
  size_t EncryptionKeySize;       // Total size of encryption key file
  size_t EncryptionKeyOffset;     // How many bytes consumed
  size_t EncryptedSequence;       // Number of messages encrypted
  char DecryptionKeyPath[512];    // Path to decryption key file
  size_t DecryptionKeySize;       // Total size of decryption key file
  size_t DecryptionKeyOffset;     // How many bytes consumed
  size_t DecryptedSequence;       // Number of messages decrypted
  int RetryCount;
  time_t LastMessageSentAt;
  time_t LastMessageReceivedAt;
} Contact;

typedef struct
{
  Contact contacts[MAX_CONTACTS];
  int count;
} Keychain;

// Global keychain instance
extern Keychain g_keychain;

// Keychain functions
//
// There is no save_keychain(): each contact's metadata is persisted to
// its own file (<keychain_dir>/<name>.meta) internally by the functions
// below as they modify that contact, so two different contacts can never
// collide on a shared save. See the "Per-contact metadata files" section
// of README.md.
int load_keychain(void);
int add_contact(const char *name);
int add_contact_with_keys(const char *name, const char *encryption_key_file, const char *decryption_key_file);
int remove_contact(const char *name);
int has_contact(const char *name);
void list_contacts(void);
void show_contact(const char *name);

// Helper functions
Contact *find_contact(const char *name);
void init_keychain(void);
void cleanup_keychain(void);

// True if `name` is safe to build filenames/paths from (no path
// separators, no "." or "..", no control characters, etc.) - see the
// block comment above its definition in keychain.c. Used both for
// contact names and for --new-key-pair's part_a/part_b, which are built
// into paths (<name>_keys/..., the vault's pending-claim artifact) the
// same way a contact's name is.
int is_valid_contact_name(const char *name);

// Shared with cipher.c, which owns encrypt_with_contact() /
// decrypt_with_contact() (declared in cipher.h) but commits its key
// consumption through the keychain's own primitives:
//
// Resolve (and create if missing) the keychain directory.
int get_keychain_dir(char *dir_path, size_t dir_path_size);
// Append `size` bytes of randomness read from stdin to the keychain's
// randomness vault (<keychain_dir>/_randomness), creating it (mode 0600)
// on first use. Not tied to any contact, but still flock()'d
// (<keychain_dir>/_randomness.lock) against concurrent appends, and the
// incoming bytes are staged and read-back verified before the vault
// itself is ever touched - a short read from stdin leaves it unchanged.
// On success, *out_total_size (if non-NULL) receives the vault's total
// size after this call.
int add_rand_to_vault(size_t size, size_t *out_total_size);
// Report the vault's current size (0 with no error if it doesn't exist
// yet). See keychain.c for the -1 error case.
int get_vault_size(size_t *out_size);
// Claim `total_bytes` from the front of the vault for a vault-sourced
// --new-key-pair generation for (part_a, part_b): stage, verify and
// publish them to a pending artifact, then truncate the vault - in that
// order, so the claim is durable before the vault is touched. On success
// *out_path names the artifact (holding exactly total_bytes verified
// bytes, ready to stream key material from) and the vault is already
// reduced.
int vault_claim(size_t total_bytes, const char *part_a, const char *part_b,
                char *out_path, size_t out_path_size);
// Delete the pending artifact once the key files it fed are fully written.
void vault_claim_release(const char *pending_path);
// Look for a leftover pending artifact from an interrupted vault-sourced
// --new-key-pair run: 1 (with *out_path set) if one matches (part_a,
// part_b) and should be delivered instead of claiming fresh vault bytes,
// 0 if none exists, -1 if one exists for other names (must be resolved
// before any new vault claim).
int vault_claim_recover(const char *part_a, const char *part_b,
                        char *out_path, size_t out_path_size);
// Persist one contact's metadata atomically and verified.
int save_contact_meta(const char *keychain_dir, Contact *c);
// Record a key file's head in the spent-heads registry; direction is
// "enc" or "dec". Fails closed - a non-zero return must abort the
// operation before any key material is spent.
int spent_head_record(const char *keychain_dir, const char *direction,
                      const char *key_path);

#endif // KEYCHAIN_H
