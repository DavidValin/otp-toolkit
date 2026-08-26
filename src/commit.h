/*****************************************************************************\
 *                                                                           *
 *   commit.h - Crash-safe, atomically-committed key consumption for OTP     *
 *                                                                           *
 *   Provides the durable-staging + verified-write + atomic-publish          *
 *   primitives that let encrypt/decrypt operations survive a process        *
 *   crash (kill, power loss) without ever risking one-time-pad key reuse.   *
 *   See the "Crash-safe key consumption" section of README.md for the full  *
 *   design rationale.                                                       *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef COMMIT_H
#define COMMIT_H

#include <stddef.h>
#include <stdio.h>

/* ---- One-shot verified buffer write -----------------------------------
 * Writes `size` bytes of `data` to `tmp_path` (any leftover file there is
 * removed first, then it is created exclusively with mode 0600),
 * fsyncs it, then reopens the file and compares every byte actually on
 * disk against `data`. On any failure the tmp file is removed and -1 is
 * returned; the caller must not proceed to commit_publish(). On success
 * the verified file is left at `tmp_path`, not yet published.
 */
int commit_write_verified(const char *tmp_path, const unsigned char *data, size_t size);

/* ---- Streaming verified write (checksum-based) -------------------------
 * For payloads produced incrementally (e.g. ciphertext streamed in 4MB
 * chunks) where holding a second full copy in RAM to compare against
 * would be wasteful. A CRC32 is accumulated while writing, then
 * recomputed from a fresh read-back and compared.
 */
typedef struct
{
  FILE *f;
  unsigned long crc;
  size_t written;
  char tmp_path[600];
} CommitStage;

/* Build the full path of a fresh staging file for `contact`/`direction`
 * ("enc" or "dec") inside `keychain_dir`:
 * <keychain_dir>/<contact>_<direction>_pending.<pid>.tmp - the one place
 * that spells out this naming convention, so the writer (a caller about
 * to commit_stage_open() it) and the reader (parse_stage_name(), used by
 * commit_reconcile()/commit_classify()/commit_discard_all_pending() to
 * recognize an abandoned staging file) can never drift apart. */
void commit_stage_path(const char *keychain_dir, const char *contact,
                       const char *direction, char *out, size_t out_size);
int commit_stage_open(CommitStage *stage, const char *tmp_path);
int commit_stage_write(CommitStage *stage, const unsigned char *data, size_t len);
/* fsync + close + reopen + recompute CRC32 + compare. 0 on success (file
 * left verified at stage->tmp_path), -1 on failure (tmp file removed). */
int commit_stage_close_verified(CommitStage *stage);
/* Close (if still open) and remove the tmp file - used on error paths. */
void commit_stage_abort(CommitStage *stage);

/* ---- Publish / discard --------------------------------------------------
 * Atomically renames tmp_path -> final_path (must be on the same
 * filesystem - both should live under the same keychain directory) and,
 * on POSIX, fsyncs the containing directory so the rename itself survives
 * a power loss and not just a process kill.
 */
int commit_publish(const char *tmp_path, const char *final_path);
void commit_discard_path(const char *path);

/* ---- Pending output artifacts -------------------------------------------
 * A "pending artifact" is the fully-verified ciphertext/plaintext of one
 * message, staged and published under a name tagged with the exact key
 * range it corresponds to, *before* the key file and the contact's .meta
 * file are committed to reflect that range as consumed. Because delivery
 * to the real output stream is the one step this tool cannot make atomic (it
 * doesn't control what's on the other end of stdout), key consumption is
 * anchored to this durable local copy instead - once it exists and is
 * verified, delivery becomes a separate, freely-retryable, idempotent
 * step that never needs to touch key material again.
 */
void commit_pending_path(const char *keychain_dir, const char *contact,
                          const char *direction, size_t sequence,
                          size_t offset, size_t length,
                          char *out, size_t out_size);

typedef enum
{
  COMMIT_RECOVER_NONE = 0,   /* no leftover pending artifact */
  COMMIT_RECOVER_DISCARD,    /* commit never started - discarded, nothing lost */
  COMMIT_RECOVER_FINISH,     /* key file committed, .meta was stale - finish it */
  COMMIT_RECOVER_DELIVER,    /* fully committed already - just redeliver */
  COMMIT_RECOVER_ERROR,      /* state didn't match any known-safe window - discarded defensively */
  COMMIT_RECOVER_BLOCKED     /* key file unreadable - artifact KEPT, caller must abort the run */
} CommitRecoverAction;

typedef struct
{
  CommitRecoverAction action;
  char pending_path[600];
  size_t sequence;
  size_t range_offset;
  size_t range_length;
  size_t corrected_offset; /* only meaningful for COMMIT_RECOVER_FINISH */
  size_t corrected_size;   /* only meaningful for COMMIT_RECOVER_FINISH */
} CommitRecovery;

/* Scans `keychain_dir` for a pending artifact belonging to `contact` in
 * `direction` ("enc" or "dec") and reconciles it against the *current*
 * physical size of `key_file_path` and the *declared* offset/size/
 * sequence the caller currently believes are committed (straight from the
 * Contact struct). See README.md for the truth table this implements.
 * Returns 0 on a decisive outcome (including NONE); -1 only when the key
 * file itself cannot be statted (out->action is set to BLOCKED). In that
 * case the pending artifact is deliberately left in place - on decrypt it
 * is the only copy of the recovered plaintext - and the caller MUST abort
 * the run rather than continue: if the stat failure were transient and the
 * run proceeded, it would publish a second artifact next to the kept one,
 * which the next reconciliation would discard as an unexpected extra.
 *
 * Also sweeps away any abandoned *staging* file for this contact and
 * direction - a partial write from a process that died before its output
 * was ever verified or published. Those carry no recoverable state, but
 * on the decrypt side they hold recovered plaintext, so they must not be
 * left behind. Deleting them here is safe precisely because callers hold
 * the contact lock, so no live process can be mid-staging.
 */
int commit_reconcile(const char *keychain_dir, const char *contact,
                      const char *direction, const char *key_file_path,
                      size_t declared_offset, size_t declared_size,
                      size_t declared_sequence, CommitRecovery *out);

/* Removes every leftover pending artifact AND every abandoned staging
 * file for `contact`, in both directions - used when a contact is removed,
 * so nothing of that contact's message content lingers in the keychain
 * directory after it is gone. */
void commit_discard_all_pending(const char *keychain_dir, const char *contact);

/* ---- Read-only status classification -------------------------------------
 * What commit_reconcile() WOULD decide, computed without acting on any of
 * it: no staging-file sweep, no artifact discard, no metadata correction,
 * no unlink of anything. This is what lets --status report a contact's
 * pending state while guaranteeing every byte in the keychain directory
 * is identical before and after the call. The three-window truth table is
 * the very same code commit_reconcile() runs (classify_window() in
 * commit.c), so the report and the recovery can never drift apart.
 */
typedef struct
{
  CommitRecoverAction action; /* what the next operation's reconcile will do */
  size_t sequence;            /* the artifact's own filename tag; 0 if none */
  size_t range_offset;
  size_t range_length;
  size_t corrected_offset;    /* only meaningful for COMMIT_RECOVER_FINISH */
  size_t corrected_size;
  int stale_staging;          /* abandoned staging files seen (informational) */
  int extra_artifacts;        /* artifacts beyond the first seen (abnormal) */
} CommitStatus;

/* Same inputs and same 0/-1 contract as commit_reconcile() (with -1 again
 * meaning the key file could not be sized and out->action is BLOCKED),
 * minus `declared_sequence`, which reconcile itself never consults. */
int commit_classify(const char *keychain_dir, const char *contact,
                    const char *direction, const char *key_file_path,
                    size_t declared_offset, size_t declared_size,
                    CommitStatus *out);

/* ---- Per-contact mutual exclusion --------------------------------------
 * Guards against two processes concurrently running encrypt/decrypt (or
 * remove) for the *same* contact. This is a distinct problem from
 * crash-safety: two racing processes would each independently read the
 * same starting key offset, and each would produce individually
 * verified, correctly-staged output - the staging/verification mechanism
 * above has no way to know the other process's key bytes were about to
 * be reused for a different message. Only mutual exclusion prevents that.
 *
 * Backed by flock() on a per-contact lock file living in the same
 * directory as the rest of that contact's keychain data
 * (<keychain_dir>/<contact>.lock). flock() locks are held by the kernel
 * against the open file description and are released automatically if
 * the holding process exits for any reason, including a crash - so,
 * unlike a PID-file scheme, there is no stale-lock state to detect or
 * recover from; it composes directly with the rest of this module.
 */
typedef struct
{
  int fd;
  char path[600];
} ContactLock;

/* Blocks until the exclusive lock for `contact` is acquired. Returns 0 on
 * success (lock->fd is open and locked), -1 on failure. */
int contact_lock_acquire(ContactLock *lock, const char *keychain_dir, const char *contact);
/* Releases and closes the lock. Safe to call on an already-released lock. */
void contact_lock_release(ContactLock *lock);

/* Test-only fault injection: if the OTP_TEST_CRASH_POINT environment
 * variable is set and equals `point`, flushes all output and terminates
 * the process immediately (as a crash would - no further commit steps
 * run), with a distinctive exit code so tests can confirm the crash
 * landed where intended. A no-op whenever the variable isn't set, so it
 * has zero effect on normal operation. */
void commit_test_crash_point(const char *point);

/* Test-only fault injection: if OTP_TEST_CORRUPT_POINT is set and equals
 * `point`, silently corrupts the file at `path` (flipping its first byte,
 * or appending one if it is empty). Placed between a staged write and its
 * read-back verification, this simulates the case the verification exists
 * for - bytes that libc accepted but that are not correctly on disk - so
 * tests can prove the check actually fires rather than merely assuming it
 * would. A no-op whenever the variable isn't set. */
void commit_test_corrupt_file(const char *point, const char *path);

#endif /* COMMIT_H */
