/*****************************************************************************\
 *                                                                           *
 *   cipher.h - Encrypt/decrypt operations for OTP contacts                  *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef CIPHER_H
#define CIPHER_H

#include <stdio.h>

// Return codes for encrypt_with_contact() / decrypt_with_contact().
//
// KEYCHAIN_REDELIVERED is deliberately distinct from KEYCHAIN_OK. When a
// previous run was interrupted after its output was committed but before
// it was delivered, the next run redelivers that recovered message and
// does NOT process the input it was given this time - the input is left
// entirely unconsumed and must be re-submitted. Reporting that as success
// would let a script believe its message had been encrypted when the
// bytes it received actually belong to the previous one.
#define KEYCHAIN_OK 0
#define KEYCHAIN_ERROR (-1)
#define KEYCHAIN_REDELIVERED 8

// Metadata validation exit codes for --decrypt. Every message carries an
// encrypted metadata block (source_id / seq / offset - see the
// "Per-message metadata layer" comment in cipher.c); decryption
// validates it before any key material is consumed and, on mismatch,
// rejects the message with the exact combination that failed so an
// integrating program can react without parsing stderr. These are both
// the internal return values of decrypt_with_contact() and the process
// exit codes. A message whose metadata cannot even be parsed (garbage,
// or produced by an incompatible sender) verifies nothing and is
// rejected as KEYCHAIN_META_BAD_ALL. Note KEYCHAIN_META_BAD_SOURCE
// shares exit code 1 with generic errors, by design.
#define KEYCHAIN_META_BAD_SOURCE 1        // invalid source_id
#define KEYCHAIN_META_BAD_SEQ 2           // invalid seq
#define KEYCHAIN_META_BAD_OFFSET 3        // invalid offset
#define KEYCHAIN_META_BAD_SOURCE_SEQ 4    // invalid source_id and seq
#define KEYCHAIN_META_BAD_ALL 5           // invalid source_id, seq and offset
#define KEYCHAIN_META_BAD_SEQ_OFFSET 6    // invalid seq and offset
#define KEYCHAIN_META_BAD_SOURCE_OFFSET 7 // invalid source_id and offset

// Encryption/Decryption operations with contacts
int encrypt_with_contact(const char *contact_name, FILE *input, FILE *output);
int decrypt_with_contact(const char *contact_name, FILE *input, FILE *output);

// Delivery-confirmation gate. Within one direction messages are only
// decryptable if they arrive in order, complete, exactly once; the
// metadata layer rejects violations at decrypt time before key is spent,
// but only the correspondents can verify, out of band, that the channel
// itself is still in sync. Before spending key on any message after the first
// in a direction, the operator is therefore asked on the terminal to
// confirm the previous message arrived intact; answering anything but
// yes cancels the operation with no key consumed. Passing 1 here (set
// from the -y/--assume-delivered flag; the OTP_ASSUME_DELIVERED
// environment variable is equivalent) records that the operator already
// confirmed out of band, so the prompt is skipped. Required for
// non-interactive use: with no terminal to ask on, the operation fails
// closed rather than assuming delivery.
void keychain_set_assume_delivered(int yes);

// --status: report one contact's per-direction state, verified from the
// disk files themselves - the key file's physical size (the authority on
// remaining key), the .meta declarations, the pending-artifact scan
// (shared with crash recovery via commit_classify) and the kept
// last-payload copies. Strictly read-only with respect to keychain state:
// it never deletes, truncates, renames or heals anything; the only files
// it can create are the ones every command creates on first touch (the
// .keychain/ directory and the contact's empty .lock file, held briefly
// for a consistent snapshot). Returns the process exit code below, or -1
// on error (unknown contact, unreadable key file).
#define KEYCHAIN_STATUS_CLEAN 0
#define KEYCHAIN_STATUS_REDELIVERY_PENDING 4
#define KEYCHAIN_STATUS_ACK_OUTSTANDING 5
#define KEYCHAIN_STATUS_ROLLED_BACK 6
int keychain_status(const char *contact_name, int porcelain);

// --recover-last: stream the kept safety copy of the last delivered
// payload (sent=1: the last encrypt's exact ciphertext; sent=0: the last
// decrypt's exact plaintext) to `output`. Read-only and idempotent: the
// copy is never deleted here - not even on a fully successful stream,
// because bytes leaving this process is not proof they were persisted or
// delivered anywhere. Only the next operation in the same direction
// removes it, when the operator confirms delivery. Returns 0 (streamed),
// KEYCHAIN_RECOVER_NO_COPY (nothing awaits confirmation), or -1 on error.
#define KEYCHAIN_RECOVER_NO_COPY 2
int keychain_recover_last(const char *contact_name, int sent, FILE *output);

// --with-ack-file: write the message's source_id, as lowercase hex, to
// <contact>_<seq>_ack_ref.sent.txt (encrypt) or
// <contact>_<seq>_ack.received.txt (decrypt) in the working directory,
// and explain on stderr what the value is for.
//
// The source_id is the 16-byte chunk at the head of the message's key
// range. It is spent with that range but never used as pad (see the
// "Per-message metadata layer" comment in cipher.c), so disclosing it
// afterwards reveals nothing that protected the plaintext, while only a
// holder of the mirrored key at that exact offset could produce it -
// which is what makes it usable as a delivery reference between two
// correspondents who have agreed to acknowledge this way.
//
// The file is written, verified and published BEFORE any key material is
// spent, and a failure to write aborts the operation with nothing
// consumed: a message must never cost key bytes whose reference could
// not be recorded, because once the range is destroyed the source_id
// cannot be recomputed from anything that remains. The value depends
// only on the key file and the current offset, not on the message, so a
// run that is interrupted (or cancelled at the confirmation prompt)
// after publishing the file leaves a reference the retry recomputes
// identically - see cipher.c.
void cipher_set_ack_file(int yes);

// Delete the kept last-payload safety copies for a contact
// (<keychain_dir>/<contact>.last_sent and .last_received). Used when a
// contact is removed: removing it must take every trace of message
// content with it.
void cipher_discard_last_copies(const char *keychain_dir, const char *contact_name);

// Drop the consumed prefix from `key_path`: stream everything from offset
// `consumed` onward into a staging file, verify that staged copy by
// read-back, then atomically publish it over `key_path`. `direction` is
// used only in error messages. This is the same crash-safe
// stage/verify/publish primitive encrypt/decrypt use to truncate a
// contact's key file after each message; shared here so any other caller
// consuming a prefix of a file (e.g. the randomness vault) truncates it
// exactly the same way, rather than through a second, divergent code path.
int truncate_key_file(const char *direction, const char *key_path,
                      size_t consumed, size_t remaining_size);

#endif // CIPHER_H
