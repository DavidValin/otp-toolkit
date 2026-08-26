/*****************************************************************************\
 *                                                                           *
 *   commit.c - Crash-safe, atomically-committed key consumption for OTP     *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include "commit.h"
#include "compat.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#define O_BINARY_FLAG _O_BINARY
#define unlink _unlink
#define getpid _getpid
#ifndef _MSC_VER
/* Map the POSIX spellings this file uses onto the CRT's underscore names.
 * MSVC also exposes the POSIX names by default, but only as deprecated
 * aliases, so spell the mapping out rather than depending on that - the
 * same mapping keychain.c already makes. */
#define fileno _fileno
#define open _open
#define close _close
#define fdopen _fdopen
#endif
#else
#include <unistd.h>
#define O_BINARY_FLAG 0
#endif

#define READBACK_CHUNK 65536

/* ---- CRC32 (standard reflected, polynomial 0xEDB88320) ---------------- */

static unsigned long crc32_table[256];
static int crc32_table_ready = 0;

static void crc32_init_table(void)
{
  if (crc32_table_ready)
    return;
  for (unsigned long n = 0; n < 256; n++)
  {
    unsigned long c = n;
    for (int k = 0; k < 8; k++)
      c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
    crc32_table[n] = c;
  }
  crc32_table_ready = 1;
}

static unsigned long crc32_begin(void)
{
  crc32_init_table();
  return 0xFFFFFFFFUL;
}

static unsigned long crc32_feed(unsigned long state, const unsigned char *buf, size_t len)
{
  for (size_t i = 0; i < len; i++)
    state = crc32_table[(state ^ buf[i]) & 0xFF] ^ (state >> 8);
  return state;
}

static unsigned long crc32_final(unsigned long state)
{
  return state ^ 0xFFFFFFFFUL;
}

/* ---- small helpers ------------------------------------------------------ */

#ifndef _WIN32
static void split_dir(const char *path, char *dir, size_t dir_size)
{
  const char *slash = strrchr(path, '/');
#ifdef _WIN32
  const char *bslash = strrchr(path, '\\');
  if (!slash || (bslash && bslash > slash))
    slash = bslash;
#endif
  if (slash)
  {
    size_t len = (size_t)(slash - path);
    if (len >= dir_size)
      len = dir_size - 1;
    memcpy(dir, path, len);
    dir[len] = '\0';
  }
  else
  {
    snprintf(dir, dir_size, ".");
  }
}
#endif /* !_WIN32 - only fsync_parent_dir's POSIX body uses this */

/* Best-effort: fsync the directory containing `path` so a completed
 * rename() survives a power loss, not just a process kill. Windows has no
 * equivalent (directories aren't opened as file descriptors there), so
 * this is a no-op there. */
static void fsync_parent_dir(const char *path)
{
#ifndef _WIN32
  char dir[600];
  split_dir(path, dir, sizeof(dir));
  int dfd = open(dir, O_RDONLY);
  if (dfd >= 0)
  {
    otp_fsync(dfd);
    close(dfd);
  }
#else
  (void)path;
#endif
}

/* ---- one-shot verified buffer write ------------------------------------ */

int commit_write_verified(const char *tmp_path, const unsigned char *data, size_t size)
{
  unlink(tmp_path);
  int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot create %s: %s\n", tmp_path, strerror(errno));
    return -1;
  }
  FILE *f = fdopen(fd, "wb");
  if (!f)
  {
    fprintf(stderr, "Error: fdopen failed for %s: %s\n", tmp_path, strerror(errno));
    close(fd);
    unlink(tmp_path);
    return -1;
  }
  if (size > 0 && fwrite(data, 1, size, f) != size)
  {
    fprintf(stderr, "Error: failed writing %s: %s\n", tmp_path, strerror(errno));
    fclose(f);
    unlink(tmp_path);
    return -1;
  }
  if (fflush(f) != 0 || otp_fsync(fileno(f)) != 0)
  {
    fprintf(stderr, "Error: failed to fsync %s: %s\n", tmp_path, strerror(errno));
    fclose(f);
    unlink(tmp_path);
    return -1;
  }
  fclose(f);

  commit_test_corrupt_file("verified_write", tmp_path);

  /* Read back and verify byte-for-byte against what we intended to write -
   * a successful fwrite() only proves libc accepted the bytes, not that
   * they are durably and correctly present on disk. */
  FILE *rf = fopen(tmp_path, "rb");
  if (!rf)
  {
    fprintf(stderr, "Error: cannot reopen %s for verification: %s\n", tmp_path, strerror(errno));
    unlink(tmp_path);
    return -1;
  }
  unsigned char buf[READBACK_CHUNK];
  size_t compared = 0;
  int mismatch = 0;
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), rf)) > 0)
  {
    if (compared + n > size || memcmp(buf, data + compared, n) != 0)
    {
      mismatch = 1;
      break;
    }
    compared += n;
  }
  int had_error = ferror(rf);
  fclose(rf);
  if (mismatch || had_error || compared != size)
  {
    fprintf(stderr, "Error: verification failed for %s (read-back does not match what was written)\n", tmp_path);
    unlink(tmp_path);
    return -1;
  }
  return 0;
}

/* ---- streaming verified write ------------------------------------------ */

int commit_stage_open(CommitStage *stage, const char *tmp_path)
{
  memset(stage, 0, sizeof(*stage));
  unlink(tmp_path);
  int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot create staging file %s: %s\n", tmp_path, strerror(errno));
    return -1;
  }
  stage->f = fdopen(fd, "wb");
  if (!stage->f)
  {
    fprintf(stderr, "Error: fdopen failed for %s: %s\n", tmp_path, strerror(errno));
    close(fd);
    unlink(tmp_path);
    return -1;
  }
  stage->crc = crc32_begin();
  stage->written = 0;
  snprintf(stage->tmp_path, sizeof(stage->tmp_path), "%s", tmp_path);
  return 0;
}

int commit_stage_write(CommitStage *stage, const unsigned char *data, size_t len)
{
  if (len == 0)
    return 0;
  if (fwrite(data, 1, len, stage->f) != len)
  {
    fprintf(stderr, "Error: failed writing to staging file %s: %s\n", stage->tmp_path, strerror(errno));
    return -1;
  }
  stage->crc = crc32_feed(stage->crc, data, len);
  stage->written += len;
  return 0;
}

int commit_stage_close_verified(CommitStage *stage)
{
  if (fflush(stage->f) != 0 || otp_fsync(fileno(stage->f)) != 0)
  {
    fprintf(stderr, "Error: failed to fsync staging file %s: %s\n", stage->tmp_path, strerror(errno));
    fclose(stage->f);
    stage->f = NULL;
    unlink(stage->tmp_path);
    return -1;
  }
  fclose(stage->f);
  stage->f = NULL;

  commit_test_corrupt_file("staged_output", stage->tmp_path);

  FILE *rf = fopen(stage->tmp_path, "rb");
  if (!rf)
  {
    fprintf(stderr, "Error: cannot reopen staging file %s for verification: %s\n", stage->tmp_path, strerror(errno));
    unlink(stage->tmp_path);
    return -1;
  }
  unsigned char buf[READBACK_CHUNK];
  unsigned long check_crc = crc32_begin();
  size_t total = 0, n;
  while ((n = fread(buf, 1, sizeof(buf), rf)) > 0)
  {
    check_crc = crc32_feed(check_crc, buf, n);
    total += n;
  }
  int had_error = ferror(rf);
  fclose(rf);
  if (had_error || total != stage->written || crc32_final(check_crc) != crc32_final(stage->crc))
  {
    fprintf(stderr, "Error: verification failed for staged file %s (read-back does not match what was written)\n", stage->tmp_path);
    unlink(stage->tmp_path);
    return -1;
  }
  return 0;
}

void commit_stage_abort(CommitStage *stage)
{
  if (stage->f)
  {
    fclose(stage->f);
    stage->f = NULL;
  }
  if (stage->tmp_path[0])
    unlink(stage->tmp_path);
}

/* ---- publish / discard -------------------------------------------------- */

int commit_publish(const char *tmp_path, const char *final_path)
{
  /* otp_rename_replace(), not rename(): every publish here lands on a path
   * that already exists, and the Windows CRT rename() refuses that. See
   * compat.h. */
  if (otp_rename_replace(tmp_path, final_path) != 0)
  {
    fprintf(stderr, "Error: failed to publish %s -> %s: %s\n", tmp_path, final_path, strerror(errno));
    return -1;
  }
  fsync_parent_dir(final_path);
  return 0;
}

void commit_discard_path(const char *path)
{
  unlink(path);
}

/* ---- pending output artifacts ------------------------------------------ */

void commit_pending_path(const char *keychain_dir, const char *contact,
                          const char *direction, size_t sequence,
                          size_t offset, size_t length,
                          char *out, size_t out_size)
{
  snprintf(out, out_size, "%s/%s_%s_pending_seq%zu_off%zu_len%zu.bin",
           keychain_dir, contact, direction, sequence, offset, length);
}

/* Match a published artifact name *in full*.
 *
 * Matching the prefix and taking sscanf's return value alone is not
 * enough, and the difference is a cross-contact bug rather than a
 * cosmetic one. sscanf() reports how many conversions it assigned, not
 * whether the trailing literal matched, so "1_off0_len3_enc_pending_seq4_
 * off0_len9.bin" satisfies "%zu_off%zu_len%zu.bin" with a return of 3.
 * Contact names may legally contain '_' and digits, so a contact named
 * "x_enc_pending_seq1_off0_len3" produces artifacts that contact "x"
 * would then claim as its own - and either unlink them or redeliver
 * them, which on the decrypt side means handing out another contact's
 * plaintext.
 *
 * "%n" records how far the scan actually got; requiring it to land on
 * the terminating NUL is what makes the name unambiguous. It is only
 * assigned when every preceding directive - including the ".bin"
 * literal - matched, so it must be pre-set to -1 and checked. */
static int parse_pending_name(const char *name, const char *prefix,
                               size_t *seq, size_t *off, size_t *len)
{
  size_t prefix_len = strlen(prefix);
  if (strncmp(name, prefix, prefix_len) != 0)
    return 0;

  const char *rest = name + prefix_len;
  int consumed = -1;
  if (sscanf(rest, "%zu_off%zu_len%zu.bin%n", seq, off, len, &consumed) != 3)
    return 0;
  return consumed >= 0 && rest[consumed] == '\0';
}

/* Match an abandoned staging name in full: <stage_prefix><pid>.tmp, where
 * the pid part must be all digits and nothing else. Same reasoning as
 * parse_pending_name - a prefix test alone would let one contact sweep
 * another contact's in-flight staging file. */
static int parse_stage_name(const char *name, const char *stage_prefix)
{
  size_t prefix_len = strlen(stage_prefix);
  if (strncmp(name, stage_prefix, prefix_len) != 0)
    return 0;

  const char *p = name + prefix_len;
  if (*p < '0' || *p > '9')
    return 0;
  while (*p >= '0' && *p <= '9')
    p++;
  return strcmp(p, ".tmp") == 0;
}

/* Build the two name fragments that identify everything one direction of
 * one contact can leave behind in the keychain directory:
 *   <contact>_<dir>_pending_seq<N>_off<O>_len<L>.bin - a published,
 *     fully-verified artifact; the input to the recovery truth table.
 *   <contact>_<dir>_pending.<pid>.tmp - a *staging* file, still being
 *     written when its process died. It was never verified and never
 *     published, so it carries no recoverable meaning - but it does hold
 *     real message content (on the decrypt side, recovered plaintext),
 *     so it must not be left lying around. Callers sweep these while
 *     holding the contact lock, which is what makes deleting them safe:
 *     no other process can be mid-staging for this contact+direction.
 */
static void build_pending_prefixes(const char *contact, const char *direction,
                                    char *artifact_prefix, size_t artifact_size,
                                    char *stage_prefix, size_t stage_size)
{
  snprintf(artifact_prefix, artifact_size, "%s_%s_pending_seq", contact, direction);
  snprintf(stage_prefix, stage_size, "%s_%s_pending.", contact, direction);
}

/* Build the full path of a fresh staging file for `contact`/`direction`:
 * <keychain_dir>/<contact>_<direction>_pending.<pid>.tmp - the name a
 * caller (encrypt/decrypt in cipher.c) creates via commit_stage_open()
 * before its output is verified. Built from the exact same stage_prefix
 * computation parse_stage_name() (via build_pending_prefixes() above)
 * recognizes during crash recovery, rather than a second, independently
 * spelled-out format string, so the writer and the reader of this name
 * can never drift apart. */
void commit_stage_path(const char *keychain_dir, const char *contact,
                       const char *direction, char *out, size_t out_size)
{
  char artifact_prefix[300], stage_prefix[300];
  build_pending_prefixes(contact, direction, artifact_prefix, sizeof(artifact_prefix),
                         stage_prefix, sizeof(stage_prefix));
  snprintf(out, out_size, "%s/%s%ld.tmp", keychain_dir, stage_prefix, (long)getpid());
}

/* The three-window recovery truth table (see README.md), as one pure
 * function of the sizes involved. Both commit_reconcile() - which acts on
 * the verdict - and commit_classify() - which only reports it - call this
 * same code, so the report a --status consumer plans around is by
 * construction the recovery the next operation will perform. */
static CommitRecoverAction classify_window(size_t actual_key_size,
                                           size_t declared_offset, size_t declared_size,
                                           size_t found_offset, size_t found_len,
                                           size_t *corrected_offset, size_t *corrected_size)
{
  if (actual_key_size == declared_size && declared_offset == found_offset)
  {
    /* Window 1: neither the key file nor the .meta file reflect this
     * operation - it never committed. Nothing was ever spent or
     * delivered, so the leftover artifact is simply stale. */
    return COMMIT_RECOVER_DISCARD;
  }
  if (actual_key_size + found_len == declared_size && declared_offset == found_offset)
  {
    /* Window 2: the key file was already truncated for this operation,
     * but the .meta file hasn't caught up. The commit can be finished
     * using the values recorded in the artifact's own filename - no
     * guessing. */
    *corrected_offset = found_offset + found_len;
    *corrected_size = actual_key_size;
    return COMMIT_RECOVER_FINISH;
  }
  if (actual_key_size == declared_size && declared_offset == found_offset + found_len)
  {
    /* Window 3: fully committed already - only delivery/cleanup remains. */
    return COMMIT_RECOVER_DELIVER;
  }
  return COMMIT_RECOVER_ERROR;
}

int commit_reconcile(const char *keychain_dir, const char *contact,
                      const char *direction, const char *key_file_path,
                      size_t declared_offset, size_t declared_size,
                      size_t declared_sequence, CommitRecovery *out)
{
  (void)declared_sequence;
  memset(out, 0, sizeof(*out));
  out->action = COMMIT_RECOVER_NONE;

  DIR *d = opendir(keychain_dir);
  if (!d)
    return 0; /* no keychain dir yet - nothing to reconcile */

  char prefix[300], stage_prefix[300];
  build_pending_prefixes(contact, direction, prefix, sizeof(prefix),
                         stage_prefix, sizeof(stage_prefix));

  struct dirent *entry;
  char found_path[600] = {0};
  size_t found_seq = 0, found_offset = 0, found_len = 0;
  int found = 0;

  while ((entry = readdir(d)) != NULL)
  {
    size_t seq, off, len;

    /* Sweep abandoned staging files first. These are never recoverable -
     * an unfinished, unverified write - but they can be large and, when
     * left by an interrupted decrypt, they contain plaintext. */
    if (parse_stage_name(entry->d_name, stage_prefix))
    {
      char stale_path[600];
      snprintf(stale_path, sizeof(stale_path), "%s/%s", keychain_dir, entry->d_name);
      unlink(stale_path);
      continue;
    }

    if (!parse_pending_name(entry->d_name, prefix, &seq, &off, &len))
      continue;

    char full_path[600];
    snprintf(full_path, sizeof(full_path), "%s/%s", keychain_dir, entry->d_name);

    if (found)
    {
      /* Should never happen given reconcile always runs before any new
       * operation starts - defensively discard rather than guess. */
      fprintf(stderr, "Warning: discarding unexpected extra pending artifact %s\n", full_path);
      unlink(full_path);
      continue;
    }

    snprintf(found_path, sizeof(found_path), "%s", full_path);
    found_seq = seq;
    found_offset = off;
    found_len = len;
    found = 1;
  }
  closedir(d);

  if (!found)
    return 0;

  // Populate the found artifact's own fields before the stat below,
  // which can fail and return BLOCKED - matching commit_classify(),
  // which sets its equivalent fields before its own identical check.
  // Both describe the very same on-disk artifact this early, before
  // either has any reason to fail, so a BLOCKED caller (e.g. --status,
  // via commit_classify(), or a future reconcile() caller that wants to
  // report which artifact is stuck) always sees which one it is rather
  // than a zeroed struct - the parity the shared classify_window() truth
  // table is meant to guarantee.
  out->sequence = found_seq;
  out->range_offset = found_offset;
  out->range_length = found_len;
  snprintf(out->pending_path, sizeof(out->pending_path), "%s", found_path);

  unsigned long long key_size_64;
  if (otp_file_size(key_file_path, &key_size_64) != 0)
  {
    /* Without the key file's size nothing can be reconciled - but the
     * artifact must not be destroyed over what may be a transient
     * failure: on decrypt it is the sole copy of the recovered
     * plaintext, whose key bytes may already be gone. Keep it for a
     * later run to reconcile once the key file is readable again. The
     * caller must abort the whole run in response (see the header):
     * proceeding would publish a second artifact alongside the kept
     * one, and reconciliation discards "extra" artifacts on sight. */
    fprintf(stderr,
            "Warning: cannot stat key file %s while reconciling %s: %s - "
            "keeping the pending artifact for a later attempt\n",
            key_file_path, found_path, strerror(errno));
    out->action = COMMIT_RECOVER_BLOCKED;
    return -1;
  }
  size_t actual_key_size;
  if (otp_size_to_size_t(key_size_64, &actual_key_size) != 0)
  {
    /* Same fail-closed treatment as an unreadable key file: a size too
     * large for this build's size_t (32-bit build, >4GB key) cannot be
     * reconciled without truncating it. Keep the artifact and abort. */
    fprintf(stderr,
            "Warning: key file %s is too large for this build to reconcile %s - "
            "keeping the pending artifact\n",
            key_file_path, found_path);
    out->action = COMMIT_RECOVER_BLOCKED;
    return -1;
  }

  out->action = classify_window(actual_key_size, declared_offset, declared_size,
                                found_offset, found_len,
                                &out->corrected_offset, &out->corrected_size);

  switch (out->action)
  {
  case COMMIT_RECOVER_DISCARD:
    /* Window 1 (never committed): the artifact is stale evidence. */
    unlink(found_path);
    return 0;
  case COMMIT_RECOVER_FINISH:
  case COMMIT_RECOVER_DELIVER:
    return 0;
  default:
    fprintf(stderr,
            "Warning: pending artifact %s does not match a recognized recovery state "
            "(declared offset=%zu size=%zu, actual key size=%zu) - discarding without redelivery\n",
            found_path, declared_offset, declared_size, actual_key_size);
    unlink(found_path);
    out->action = COMMIT_RECOVER_ERROR;
    return 0;
  }
}

int commit_classify(const char *keychain_dir, const char *contact,
                    const char *direction, const char *key_file_path,
                    size_t declared_offset, size_t declared_size,
                    CommitStatus *out)
{
  memset(out, 0, sizeof(*out));
  out->action = COMMIT_RECOVER_NONE;

  DIR *d = opendir(keychain_dir);
  if (!d)
    return 0; /* no keychain dir yet - nothing pending */

  char prefix[300], stage_prefix[300];
  build_pending_prefixes(contact, direction, prefix, sizeof(prefix),
                         stage_prefix, sizeof(stage_prefix));

  /* Same scan order as commit_reconcile(), so "the" artifact classified
   * here is the same one reconcile will act on - but strictly read-only:
   * stale staging files and unexpected extras are counted, never removed.
   * Cleanup belongs to the operational paths. */
  struct dirent *entry;
  size_t found_seq = 0, found_offset = 0, found_len = 0;
  int found = 0;

  while ((entry = readdir(d)) != NULL)
  {
    size_t seq, off, len;

    if (parse_stage_name(entry->d_name, stage_prefix))
    {
      out->stale_staging++;
      continue;
    }
    if (!parse_pending_name(entry->d_name, prefix, &seq, &off, &len))
      continue;
    if (found)
    {
      out->extra_artifacts++;
      continue;
    }
    found_seq = seq;
    found_offset = off;
    found_len = len;
    found = 1;
  }
  closedir(d);

  if (!found)
    return 0;

  out->sequence = found_seq;
  out->range_offset = found_offset;
  out->range_length = found_len;

  unsigned long long key_size_64;
  size_t actual_key_size;
  if (otp_file_size(key_file_path, &key_size_64) != 0 ||
      otp_size_to_size_t(key_size_64, &actual_key_size) != 0)
  {
    /* Same fail-closed verdict as reconcile: without the key file's size
     * nothing can be concluded. Quiet here - this is a query primitive,
     * and the caller owns the reporting. */
    out->action = COMMIT_RECOVER_BLOCKED;
    return -1;
  }

  out->action = classify_window(actual_key_size, declared_offset, declared_size,
                                found_offset, found_len,
                                &out->corrected_offset, &out->corrected_size);
  return 0;
}

void commit_discard_all_pending(const char *keychain_dir, const char *contact)
{
  DIR *d = opendir(keychain_dir);
  if (!d)
    return;

  /* Covers both published artifacts and abandoned staging files
   * (<contact>_<dir>_pending.<pid>.tmp) in both directions. This is the
   * only thing that ever revisits a dead process's pid-tagged name, so
   * anything it misses stays on disk forever - and on the decrypt side
   * that file holds recovered plaintext.
   *
   * Names are matched in full rather than by prefix, for the reason
   * given above parse_pending_name: a prefix test would also delete the
   * artifacts of any *other* contact whose name happens to begin with
   * this one's, including that contact's staged plaintext. */
  const char *directions[2] = {"enc", "dec"};

  struct dirent *entry;
  while ((entry = readdir(d)) != NULL)
  {
    int matched = 0;
    for (int i = 0; i < 2 && !matched; i++)
    {
      char artifact_prefix[300], stage_prefix[300];
      size_t seq, off, len;
      build_pending_prefixes(contact, directions[i],
                             artifact_prefix, sizeof(artifact_prefix),
                             stage_prefix, sizeof(stage_prefix));

      if (parse_pending_name(entry->d_name, artifact_prefix, &seq, &off, &len) ||
          parse_stage_name(entry->d_name, stage_prefix))
        matched = 1;
    }

    if (matched)
    {
      char full_path[600];
      snprintf(full_path, sizeof(full_path), "%s/%s", keychain_dir, entry->d_name);
      unlink(full_path);
    }
  }
  closedir(d);
}

/* ---- per-contact mutual exclusion --------------------------------------- */

int contact_lock_acquire(ContactLock *lock, const char *keychain_dir, const char *contact)
{
  lock->fd = -1;
  snprintf(lock->path, sizeof(lock->path), "%s/%s.lock", keychain_dir, contact);

  int fd = open(lock->path, O_CREAT | O_RDWR | O_BINARY_FLAG, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot create lock file %s: %s\n", lock->path, strerror(errno));
    return -1;
  }

  /* Blocks until any other process holding this contact's lock releases
   * it - including via crash or kill, since the OS drops the lock as
   * soon as the holding file descriptor closes (POSIX flock() and the
   * Windows LockFileEx-backed shim in compat.h both guarantee this). */
  if (flock(fd, LOCK_EX) != 0)
  {
    fprintf(stderr, "Error: failed to lock %s: %s\n", lock->path, strerror(errno));
    close(fd);
    return -1;
  }

  lock->fd = fd;
  return 0;
}

void contact_lock_release(ContactLock *lock)
{
  if (lock->fd >= 0)
  {
    flock(lock->fd, LOCK_UN);
    close(lock->fd);
    lock->fd = -1;
  }
}

/* ---- test-only fault injection ------------------------------------------ */

void commit_test_corrupt_file(const char *point, const char *path)
{
  const char *target = getenv("OTP_TEST_CORRUPT_POINT");
  if (!target || strcmp(target, point) != 0)
    return;

  FILE *f = fopen(path, "r+b");
  if (!f)
    return;
  int first = fgetc(f);
  if (first == EOF)
  {
    /* Empty payload: make it non-empty so the length check catches it. */
    fclose(f);
    f = fopen(path, "ab");
    if (f)
    {
      fputc('X', f);
      fclose(f);
    }
    return;
  }
  if (fseek(f, 0, SEEK_SET) == 0)
    fputc(first ^ 0xFF, f);
  fclose(f);
}

void commit_test_crash_point(const char *point)
{
  const char *target = getenv("OTP_TEST_CRASH_POINT");
  if (target && strcmp(target, point) == 0)
  {
    fflush(NULL);
    _Exit(77);
  }
}
