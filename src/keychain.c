/*****************************************************************************\
 *                                                                           *
 *   keychain.c - Keychain management for OTP contacts                       *
 *                                                                           *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com          *
 *   License: Apache 2.0                                                     *
 *                                                                           *
 \****************************************************************************/

// Enable Large File Support (LFS) for files >2GB on 32-bit POSIX systems
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include "keychain.h"
#include "cipher.h"
#include "commit.h"
#include "compat.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

// Platform-specific includes
#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
// Windows compatibility mappings
#define mkdir(path, mode) _mkdir(path)
#define unlink(path) _unlink(path)
#define stat _stat
/* MinGW's <sys/stat.h> already defines these; MSVC's does not */
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_STR "\\"
#define getpid _getpid
#define O_BINARY_FLAG _O_BINARY
#ifndef _MSC_VER
#define fileno _fileno
#define open _open
#define close _close
#define fdopen _fdopen
#endif
#else
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#define O_BINARY_FLAG 0
#endif

// Global keychain instance
Keychain g_keychain = {0};

// The keychain is a single directory, resolved relative to the process's
// current working directory. That is the whole location scheme: there is
// no keychain index file, and no path is derived from one. Running otp
// from a different directory therefore uses a different keychain, which
// is what lets two correspondents' keychains sit side by side.
#define KEYCHAIN_DIR_NAME ".keychain"

// Get keychain directory path (creates if doesn't exist). Also used by
// cipher.c, which builds every staging and artifact path from it.
int get_keychain_dir(char *dir_path, size_t dir_path_size)
{
  if (snprintf(dir_path, dir_path_size, "%s", KEYCHAIN_DIR_NAME) >= (int)dir_path_size)
    return -1;

  // mkdir() is the atomic check-and-create: two processes can race to
  // create this directory at once - e.g. concurrent --add-rand-to-vault
  // invocations hitting an empty working directory, as covered by
  // randvault.test.sh's "concurrent invocations" case. Only one mkdir()
  // can win that race; the loser must tolerate EEXIST rather than fail,
  // since the directory existing is exactly this function's postcondition,
  // not evidence of an error. Same idiom as the *_keys directories in
  // cli.c's key-pair generation.
  if (mkdir(dir_path, 0700) != 0 && errno != EEXIST)
  {
    fprintf(stderr, "Error: Failed to create keychain directory '%s': %s\n",
            dir_path, strerror(errno));
    return -1;
  }
  return 0;
}

// The randomness vault: <keychain_dir>/_randomness, a single sequential
// randomness stream that --add-rand-to-vault appends pre-generated
// randomness to. It belongs to no contact and is not itself consumed or
// tracked the way a contact's key material is - at this point it exists
// purely as accumulated storage. It still shares two protections with
// every contact: the same per-name flock() (<keychain_dir>/_randomness.lock)
// serializes concurrent appends, and new content is staged and read-back
// verified before the vault is ever touched.
#define RAND_VAULT_NAME "_randomness"
#define RAND_VAULT_CHUNK (1024 * 1024)

// Append `size` bytes of randomness, read from stdin, to the vault -
// creating it (mode 0600, matching every other secret this tool writes)
// the first time this is called, appending on every call after.
//
// Two failure modes this guards against, beyond a plain O_APPEND write:
//
// 1. Concurrent invocations. Two processes appending at once could
//    otherwise interleave their writes - flock()'d exclusively via the
//    same per-name lock contact operations use (contact_lock_acquire),
//    just keyed by the vault's own name instead of a contact's.
//
// 2. A short read from stdin (the randomness source died, was piped from
//    a file smaller than claimed, or was killed mid-stream). The incoming
//    bytes are staged into a tmp file and read-back verified via
//    commit_stage_close_verified() *before* the vault is touched at all -
//    so a caller who never supplies the full `size` bytes leaves the
//    vault exactly as it was, never partially appended.
//
// Once the new bytes are confirmed durable and complete, folding them
// into the vault is a plain O_APPEND copy - cheap (proportional to the
// new data, not the vault's total size) and, unlike the truncate-and-
// rewrite treatment key files get, safe to do in place: appending can
// only ever extend the file, never rewrite bytes already durable there,
// so even a failure partway through this last step cannot corrupt
// pre-existing vault content - it can at worst leave the new addition
// incomplete, which a later call simply appends past.
//
// On success, *out_total_size (if non-NULL) is set to the vault's total
// size after this call: for a brand-new vault, the exact count of bytes
// just staged; for an existing one, a fresh stat() of the vault itself
// taken right after the append, still under the lock this call holds
// throughout - so nothing else could have changed it in between.
int add_rand_to_vault(size_t size, size_t *out_total_size)
{
  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
    return -1;

  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, RAND_VAULT_NAME) != 0)
    return -1;

  char vault_path[600];
  char stage_tmp[600];
  if (snprintf(vault_path, sizeof(vault_path), "%s%c%s", keychain_dir, PATH_SEPARATOR,
               RAND_VAULT_NAME) >= (int)sizeof(vault_path) ||
      snprintf(stage_tmp, sizeof(stage_tmp), "%s%c%s.tmp", keychain_dir, PATH_SEPARATOR,
               RAND_VAULT_NAME) >= (int)sizeof(stage_tmp))
  {
    fprintf(stderr, "Error: randomness vault path too long\n");
    contact_lock_release(&lock);
    return -1;
  }

  // Stage 1: read and read-back-verify the incoming randomness on its
  // own, entirely independent of the vault.
  CommitStage stage;
  if (commit_stage_open(&stage, stage_tmp) != 0)
  {
    contact_lock_release(&lock);
    return -1;
  }

  unsigned char *buf = malloc(RAND_VAULT_CHUNK);
  if (!buf)
  {
    fprintf(stderr, "Memory allocation failed\n");
    commit_stage_abort(&stage);
    contact_lock_release(&lock);
    return -1;
  }

  size_t left = size;
  while (left > 0)
  {
    size_t want = (left < RAND_VAULT_CHUNK) ? left : RAND_VAULT_CHUNK;
    /* Every requested byte must come from stdin before any of it is
     * staged: a short read (stdin ended early) must never be padded out
     * with whatever the buffer already held. */
    if (fread(buf, 1, want, stdin) != want)
    {
      fprintf(stderr, "Error: Expected %zu bytes of randomness on stdin, got less\n", size);
      free(buf);
      commit_stage_abort(&stage);
      contact_lock_release(&lock);
      return -1;
    }
    if (commit_stage_write(&stage, buf, want) != 0)
    {
      free(buf);
      commit_stage_abort(&stage);
      contact_lock_release(&lock);
      return -1;
    }
    left -= want;
  }
  free(buf);

  if (commit_stage_close_verified(&stage) != 0)
  {
    contact_lock_release(&lock);
    return -1;
  }

  // Stage 2: the incoming randomness is now durable and verified on
  // disk. If the vault doesn't exist yet, the staged file simply
  // *becomes* it via atomic rename - no copy needed. Otherwise its
  // verified bytes are streamed onto the end of the existing vault.
  struct stat vst;
  int rc;
  size_t total = 0;
  if (stat(vault_path, &vst) != 0 && errno == ENOENT)
  {
    rc = commit_publish(stage.tmp_path, vault_path);
    if (rc == 0)
      total = stage.written; // the staged file *is* the whole new vault
  }
  else
  {
    int fd = open(vault_path, O_WRONLY | O_CREAT | O_APPEND | O_BINARY_FLAG, 0600);
    if (fd < 0)
    {
      fprintf(stderr, "Error: Cannot open randomness vault '%s': %s\n", vault_path, strerror(errno));
      rc = -1;
    }
    else
    {
      FILE *vault = fdopen(fd, "ab");
      if (!vault)
      {
        fprintf(stderr, "Error: Cannot open randomness vault '%s': %s\n", vault_path, strerror(errno));
        close(fd);
        rc = -1;
      }
      else
      {
        FILE *verified = fopen(stage.tmp_path, "rb");
        if (!verified)
        {
          fprintf(stderr, "Error: Cannot reopen staged randomness: %s\n", strerror(errno));
          rc = -1;
        }
        else
        {
          rc = 0;
          unsigned char copybuf[RAND_VAULT_CHUNK];
          size_t got;
          while ((got = fread(copybuf, 1, sizeof(copybuf), verified)) > 0)
          {
            if (fwrite(copybuf, 1, got, vault) != got)
            {
              fprintf(stderr, "Error writing randomness vault '%s': %s\n", vault_path, strerror(errno));
              rc = -1;
              break;
            }
          }
          if (rc == 0 && ferror(verified))
          {
            fprintf(stderr, "Error: Failed reading staged randomness\n");
            rc = -1;
          }
          fclose(verified);
        }
        /* fflush()/fsync() report a failed write that fwrite() alone
         * cannot: a vault silently truncated by a full disk would
         * otherwise be treated as complete. */
        if (rc == 0 && (fflush(vault) != 0 || otp_fsync(fileno(vault)) != 0))
        {
          fprintf(stderr, "Error: Failed to store randomness vault '%s': %s\n", vault_path, strerror(errno));
          rc = -1;
        }
        fclose(vault);
        /* A fresh stat() of the vault itself, taken under the same lock
         * held for the whole call (so nothing else could have changed
         * it meanwhile), is the authority on the final size - more
         * direct than trusting the pre-append stat() plus the byte
         * count we meant to add. */
        if (rc == 0)
        {
          struct stat post;
          if (stat(vault_path, &post) == 0)
            total = (size_t)post.st_size;
        }
      }
    }
    commit_discard_path(stage.tmp_path);
  }

  if (rc == 0 && out_total_size)
    *out_total_size = total;

  contact_lock_release(&lock);
  return rc;
}

// Report the randomness vault's current size, without touching it.
// Returns 0 with *out_size set to 0 when no vault exists yet (never an
// error - the vault is optional, unlike a contact's key files), 0 with
// *out_size set to its byte length when it does, -1 on a real stat
// failure (permissions, I/O error).
int get_vault_size(size_t *out_size)
{
  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
    return -1;

  char vault_path[600];
  if (snprintf(vault_path, sizeof(vault_path), "%s%c%s", keychain_dir, PATH_SEPARATOR,
               RAND_VAULT_NAME) >= (int)sizeof(vault_path))
  {
    fprintf(stderr, "Error: randomness vault path too long\n");
    return -1;
  }

  struct stat st;
  if (stat(vault_path, &st) != 0)
  {
    if (errno == ENOENT)
    {
      if (out_size)
        *out_size = 0;
      return 0;
    }
    fprintf(stderr, "Error: Cannot stat randomness vault '%s': %s\n", vault_path, strerror(errno));
    return -1;
  }
  if (out_size)
    *out_size = (size_t)st.st_size;
  return 0;
}

// --new-key-pair, when run with no piped stdin, can draw its randomness
// from the vault instead of refusing outright. vault_claim() /
// vault_claim_release() / vault_claim_recover() below let it do so while
// respecting exactly the same commit discipline a contact's key file gets
// on every encrypt/decrypt: the bytes about to be consumed are staged and
// verified into a durable, named artifact *before* the vault is touched at
// all (commit_stage_open/write/close_verified + commit_publish, the same
// primitives add_rand_to_vault() above uses), the vault is only then
// physically shrunk (truncate_key_file(), the very function that trims a
// contact's key file after each message - not a reimplementation of it),
// and the artifact is deleted only once the key files it fed are fully
// written. A crash at any point leaves a decisive, recoverable state: if
// it lands before the artifact is published the vault is simply untouched
// and nothing was ever claimed; if it lands after, the claimed bytes exist
// durably in exactly one place (either still in the vault, or already
// published to the artifact) and vault_claim_recover() finds that artifact
// on the next run instead of a fresh claim silently drawing the same
// randomness twice.
#define VAULT_PENDING_PREFIX "_randomness_pending_"

static int vault_pending_name(char *out, size_t out_size, const char *part_a, const char *part_b)
{
  return snprintf(out, out_size, VAULT_PENDING_PREFIX "%s_%s.bin", part_a, part_b) >= (int)out_size ? -1 : 0;
}

// Claim `total_bytes` from the front of the vault for the key pair being
// generated for (part_a, part_b): stage and verify them into a pending
// artifact, publish it, then truncate the vault to remove them - in that
// order, so the claim is durable before the vault ever shrinks. On
// success *out_path names the artifact (now holding exactly `total_bytes`
// verified bytes) and the vault is already reduced; the caller streams the
// key pair from *out_path exactly as it would have from stdin, then calls
// vault_claim_release() once every key file is safely written. On failure
// the vault is left exactly as it was (or, if the failure happens to land
// during the truncate step itself, already-published artifact still holds
// every claimed byte for a later vault_claim_recover() to pick up - see
// above).
int vault_claim(size_t total_bytes, const char *part_a, const char *part_b,
                char *out_path, size_t out_path_size)
{
  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
    return -1;

  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, RAND_VAULT_NAME) != 0)
    return -1;

  char vault_path[600], pending_name[300], pending_path[600], stage_tmp[600];
  if (snprintf(vault_path, sizeof(vault_path), "%s%c%s", keychain_dir, PATH_SEPARATOR,
               RAND_VAULT_NAME) >= (int)sizeof(vault_path) ||
      vault_pending_name(pending_name, sizeof(pending_name), part_a, part_b) != 0 ||
      snprintf(pending_path, sizeof(pending_path), "%s%c%s", keychain_dir, PATH_SEPARATOR,
               pending_name) >= (int)sizeof(pending_path) ||
      snprintf(stage_tmp, sizeof(stage_tmp), "%s.tmp", pending_path) >= (int)sizeof(stage_tmp))
  {
    fprintf(stderr, "Error: vault claim path too long\n");
    contact_lock_release(&lock);
    return -1;
  }

  // Refuse if a pending claim for this exact (part_a, part_b) already
  // exists. The caller (cli.c) checks this too, via vault_claim_recover(),
  // but that check runs BEFORE the interactive delivery-confirmation
  // prompt and without holding this lock - a human-timescale window in
  // which a second concurrent run for the same pair could reach here
  // first. Without this check, this call's commit_publish() below would
  // silently overwrite that already-published, already-vault-charged
  // artifact via its atomic rename, losing track of the first claim's
  // randomness. This is the same check, but authoritative: taken right
  // before publishing, under the lock that actually serializes concurrent
  // claims.
  struct stat pst;
  if (stat(pending_path, &pst) == 0)
  {
    fprintf(stderr,
            "Error: a pending vault claim for '%s'/'%s' already exists at '%s' - "
            "another run may be in progress for this exact pair, or an earlier "
            "interrupted run left it behind. Rerun --new-key-pair with the same size "
            "and party names to deliver it, or remove the file yourself if the "
            "randomness should be treated as lost.\n",
            part_a, part_b, pending_path);
    contact_lock_release(&lock);
    return -1;
  }

  // Re-check under the lock: the caller's earlier size check is only
  // advisory (a concurrent claim could have shrunk the vault meanwhile).
  struct stat vst;
  if (stat(vault_path, &vst) != 0)
  {
    fprintf(stderr, "Error: Cannot stat randomness vault '%s': %s\n", vault_path, strerror(errno));
    contact_lock_release(&lock);
    return -1;
  }
  size_t vault_size = (size_t)vst.st_size;
  if (vault_size < total_bytes)
  {
    fprintf(stderr,
            "Error: randomness vault only holds %zu bytes now, less than the %zu needed\n",
            vault_size, total_bytes);
    contact_lock_release(&lock);
    return -1;
  }

  FILE *vf = fopen(vault_path, "rb");
  if (!vf)
  {
    fprintf(stderr, "Error: Cannot open randomness vault '%s': %s\n", vault_path, strerror(errno));
    contact_lock_release(&lock);
    return -1;
  }

  CommitStage stage;
  if (commit_stage_open(&stage, stage_tmp) != 0)
  {
    fclose(vf);
    contact_lock_release(&lock);
    return -1;
  }

  unsigned char *buf = malloc(RAND_VAULT_CHUNK);
  if (!buf)
  {
    fprintf(stderr, "Memory allocation failed\n");
    fclose(vf);
    commit_stage_abort(&stage);
    contact_lock_release(&lock);
    return -1;
  }

  size_t left = total_bytes;
  while (left > 0)
  {
    size_t want = (left < RAND_VAULT_CHUNK) ? left : RAND_VAULT_CHUNK;
    size_t got = fread(buf, 1, want, vf);
    if (got != want)
    {
      fprintf(stderr, "Error: Failed to read randomness vault\n");
      free(buf);
      fclose(vf);
      commit_stage_abort(&stage);
      contact_lock_release(&lock);
      return -1;
    }
    if (commit_stage_write(&stage, buf, got) != 0)
    {
      free(buf);
      fclose(vf);
      commit_stage_abort(&stage);
      contact_lock_release(&lock);
      return -1;
    }
    left -= got;
  }
  free(buf);
  fclose(vf);

  if (commit_stage_close_verified(&stage) != 0)
  {
    contact_lock_release(&lock);
    return -1;
  }
  if (commit_publish(stage.tmp_path, pending_path) != 0)
  {
    contact_lock_release(&lock);
    return -1;
  }

  // The claimed bytes are now durable at pending_path, independent of the
  // vault - safe to shrink the vault itself, via the same truncate
  // primitive a contact's key file gets after every message.
  if (truncate_key_file("randomness vault", vault_path, total_bytes, vault_size - total_bytes) != 0)
  {
    // The vault is either untouched or already fully truncated (truncate_
    // key_file's own publish step is atomic) - either way no bytes were
    // lost or duplicated, and pending_path still holds the claimed bytes
    // for vault_claim_recover() to find on a later run.
    contact_lock_release(&lock);
    return -1;
  }

  if (snprintf(out_path, out_path_size, "%s", pending_path) >= (int)out_path_size)
  {
    fprintf(stderr, "Error: vault claim path too long\n");
    contact_lock_release(&lock);
    return -1;
  }

  contact_lock_release(&lock);
  return 0;
}

// Delete the pending artifact once every key file it fed has been fully
// written and closed - the vault-claim equivalent of a contact's pending
// artifact being removed once its message is delivered.
void vault_claim_release(const char *pending_path)
{
  commit_discard_path(pending_path);
}

// Finish an interrupted vault_claim() truncation: if the vault's front
// bytes are still byte-identical to `pending_path`'s full content (i.e.
// the earlier run crashed after publishing the artifact but before the
// truncate's atomic rename completed), truncate them off now; otherwise
// the truncation already happened before the crash, and this is a no-op.
// Runs under the vault's own lock throughout, so it can never race a
// concurrent claim.
static int vault_claim_finish_truncate(const char *pending_path)
{
  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
    return -1;

  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, RAND_VAULT_NAME) != 0)
    return -1;

  char vault_path[600];
  if (snprintf(vault_path, sizeof(vault_path), "%s%c%s", keychain_dir, PATH_SEPARATOR,
               RAND_VAULT_NAME) >= (int)sizeof(vault_path))
  {
    fprintf(stderr, "Error: randomness vault path too long\n");
    contact_lock_release(&lock);
    return -1;
  }

  unsigned long long pending_size_64;
  if (otp_file_size(pending_path, &pending_size_64) != 0)
  {
    fprintf(stderr, "Error: Cannot stat pending vault claim '%s': %s\n", pending_path, strerror(errno));
    contact_lock_release(&lock);
    return -1;
  }
  size_t pending_size;
  if (otp_size_to_size_t(pending_size_64, &pending_size) != 0)
  {
    fprintf(stderr, "Error: pending vault claim '%s' is too large for this build\n", pending_path);
    contact_lock_release(&lock);
    return -1;
  }

  struct stat vst;
  if (stat(vault_path, &vst) != 0)
  {
    /* No vault, or unreadable: either way there is nothing left to
     * truncate, so the artifact's claim is already fully reflected. */
    contact_lock_release(&lock);
    return 0;
  }
  size_t vault_size = (size_t)vst.st_size;
  if (vault_size < pending_size)
  {
    contact_lock_release(&lock); /* too short to still hold a copy - already truncated */
    return 0;
  }

  FILE *vf = fopen(vault_path, "rb");
  FILE *pf = fopen(pending_path, "rb");
  if (!vf || !pf)
  {
    fprintf(stderr, "Error: Cannot reopen vault or pending claim for comparison: %s\n", strerror(errno));
    if (vf)
      fclose(vf);
    if (pf)
      fclose(pf);
    contact_lock_release(&lock);
    return -1;
  }

  unsigned char vbuf[RAND_VAULT_CHUNK], pbuf[RAND_VAULT_CHUNK];
  size_t left = pending_size;
  int identical = 1;
  while (left > 0 && identical)
  {
    size_t want = (left < RAND_VAULT_CHUNK) ? left : RAND_VAULT_CHUNK;
    size_t vgot = fread(vbuf, 1, want, vf);
    size_t pgot = fread(pbuf, 1, want, pf);
    if (vgot != want || pgot != want || memcmp(vbuf, pbuf, want) != 0)
      identical = 0;
    left -= want;
  }
  fclose(vf);
  fclose(pf);

  if (!identical)
  {
    contact_lock_release(&lock); /* front no longer matches - already truncated */
    return 0;
  }

  int rc = truncate_key_file("randomness vault", vault_path, pending_size, vault_size - pending_size);
  contact_lock_release(&lock);
  return rc;
}

// Look for a leftover pending artifact from an interrupted vault-sourced
// --new-key-pair run.
//
// Returns 1 with *out_path set when one matching (part_a, part_b) exists:
// the vault was already durably (and, per vault_claim()'s ordering,
// irreversibly) charged for this exact pair, so the caller should
// regenerate the key files straight from *out_path instead of prompting
// or touching the vault again - re-claiming would draw fresh bytes for
// keys that were already paid for.
// Returns 0 when none exists - safe to proceed with a normal vault check.
// Returns -1 when a pending artifact exists for OTHER names: distinct
// randomness was already spent from the vault and is sitting undelivered:
// refusing to silently ignore it is the same defensive stance
// commit_reconcile() takes on an unexpected extra artifact, since either
// discarding it (permanently losing that randomness) or ignoring it
// (leaving spent-but-undelivered bytes with no way back to them) needs the
// operator to decide, not this call.
int vault_claim_recover(const char *part_a, const char *part_b,
                        char *out_path, size_t out_path_size)
{
  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
    return -1;

  DIR *d = opendir(keychain_dir);
  if (!d)
    return 0; /* no keychain dir yet - nothing pending */

  char match_name[300];
  if (vault_pending_name(match_name, sizeof(match_name), part_a, part_b) != 0)
  {
    closedir(d);
    fprintf(stderr, "Error: name too long\n");
    return -1;
  }

  int found_match = 0, found_other = 0;
  char other_name[300] = {0};
  struct dirent *entry;
  size_t prefix_len = strlen(VAULT_PENDING_PREFIX);
  while ((entry = readdir(d)) != NULL)
  {
    if (strncmp(entry->d_name, VAULT_PENDING_PREFIX, prefix_len) != 0)
      continue;
    if (strcmp(entry->d_name, match_name) == 0)
      found_match = 1;
    else if (!found_other)
    {
      found_other = 1;
      snprintf(other_name, sizeof(other_name), "%s", entry->d_name);
    }
  }
  closedir(d);

  if (found_match)
  {
    if (snprintf(out_path, out_path_size, "%s%c%s", keychain_dir, PATH_SEPARATOR,
                 match_name) >= (int)out_path_size)
    {
      fprintf(stderr, "Error: vault claim path too long\n");
      return -1;
    }

    /* vault_claim() publishes this artifact BEFORE truncating the vault,
     * so a crash between those two steps leaves it here with the vault
     * still holding its own (untruncated) copy of the very same bytes at
     * the front. Finish that truncation now, under the same lock, before
     * handing the artifact back - otherwise those bytes would still be
     * sitting in the vault, available to be claimed (and reused) a second
     * time. Whether that finishing step is even still needed is decided
     * by comparing the vault's current front bytes against the artifact's
     * exact content: if the truncation already completed before the
     * crash, the vault's front no longer matches (or the vault is now too
     * short to hold a copy at all) and nothing further is done. */
    if (vault_claim_finish_truncate(out_path) != 0)
      return -1;

    return 1;
  }

  if (found_other)
  {
    fprintf(stderr,
            "Error: an interrupted vault-sourced --new-key-pair run left randomness already "
            "claimed from the vault but not yet delivered, at '%s%c%s'.\n"
            "Rerun --new-key-pair with the exact same size and party names that produced it "
            "to finish delivering those key files, or remove that file yourself if the "
            "randomness should be treated as lost (it was already spent from the vault either "
            "way and cannot be reused).\n",
            keychain_dir, PATH_SEPARATOR, other_name);
    return -1;
  }

  return 0;
}

// Copy a key file into the keychain directory, streaming so that a
// terabyte-scale key is never held in RAM.
//
// Staged via the same stage/verify/publish primitives (commit.c) used for
// every other durable artifact this tool produces: the copy is written to
// a tmp file - created with mode 0600 rather than created under the
// process umask (which typically yields 0644) and tightened afterwards,
// since one-time-pad key material is the entire secret here and creating
// it readable leaves a window, however brief, in which any other local
// user could copy it - fsynced, then read back and compared by checksum
// before it is ever published to dst_path. A silent write failure
// (fwrite() accepting bytes libc never actually persists) previously went
// undetected here, unlike every other durable write in this codebase;
// this closes that gap.
static int copy_key_file(const char *src_path, const char *dst_path)
{
  FILE *src = fopen(src_path, "rb");
  if (!src)
  {
    fprintf(stderr, "Error: Cannot open key file '%s': %s\n", src_path, strerror(errno));
    return -1;
  }

  char tmp_path[600];
  if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", dst_path) >= (int)sizeof(tmp_path))
  {
    fprintf(stderr, "Error: key file path too long for '%s'\n", dst_path);
    fclose(src);
    return -1;
  }

  CommitStage stage;
  if (commit_stage_open(&stage, tmp_path) != 0)
  {
    fclose(src);
    return -1;
  }

  unsigned char buffer[1024 * 1024]; // 1MB streaming buffer
  size_t bytes;
  while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
  {
    if (commit_stage_write(&stage, buffer, bytes) != 0)
    {
      fclose(src);
      commit_stage_abort(&stage);
      return -1;
    }
  }

  int read_failed = ferror(src);
  fclose(src);
  if (read_failed)
  {
    fprintf(stderr, "Error: Failed to read key file '%s': %s\n", src_path, strerror(errno));
    commit_stage_abort(&stage);
    return -1;
  }

  if (commit_stage_close_verified(&stage) != 0)
    return -1;

  if (commit_publish(stage.tmp_path, dst_path) != 0)
  {
    commit_discard_path(stage.tmp_path);
    return -1;
  }
  return 0;
}

// Two key files holding the same bytes are the same one-time pad. Giving
// a contact that pad for both directions means the range that encrypts an
// outgoing message is the same range that decrypts an incoming one - two
// messages sharing key material, which is precisely the break the pad
// must never suffer. Refusing here is the only point at which this is
// cheaply detectable; afterwards the two copies are independent files and
// nothing distinguishes them from a legitimately distinct pair.
//
// Compared by content rather than by path: a copy (cp k.bin k2.bin) is
// exactly as dangerous as passing the same filename twice, and a path
// comparison would miss it, as would an inode comparison.
//
// Equal size is NOT a precondition for danger, so it is not used as a
// shortcut. Key material here is consumed from the front and the file is
// truncated, so the natural leftover of this tool - a partially consumed
// key from .keychain/ - is a *suffix* of the pad it came from. Handing
// over a pad and its own leftover is overlap just as total as handing
// over the same file twice, and the sizes differ precisely because some
// of it was already spent. A truncated head of a pad is the mirror image
// of that case.
//
// Nor is overlap confined to those two alignments: a pad trimmed at both
// ends, or two windows cut from the same pad, share key material without
// either file being a prefix or suffix of the other. Detection therefore
// searches for each file's opening KEY_ANCHOR_LEN bytes at *every* offset
// of the other file, with a rolling hash so the search is one sequential
// read of each file. Any overlap that includes either file's first
// KEY_ANCHOR_LEN bytes is found this way; only an overlap that excludes
// both files' heads (which no artifact of this tool produces - every
// truncation preserves one end) or one shorter
// than the anchor can escape. Files smaller than the anchor keep the two
// aligned comparisons only: a handful of bytes genuinely can coincide in
// two independent pads, and refusing on such a coincidence would reject
// legitimate keys.
//
// The cost is a full read of both files rather than the early-exit a
// front-only comparison would allow. Adding a contact is rare and this is
// the one moment overlap is detectable at all, so the trade is taken.
#define KEY_COMPARE_CHUNK (1024 * 1024)
#define KEY_ANCHOR_LEN 64

typedef enum
{
  KEY_OVERLAP_NONE = 0,
  KEY_OVERLAP_IDENTICAL, // same size, same bytes
  KEY_OVERLAP_PREFIX,    // the shorter file is the head of the longer
  KEY_OVERLAP_SUFFIX,    // the shorter file is the tail of the longer
  KEY_OVERLAP_INTERIOR,  // shared material at an unaligned, interior offset
  KEY_OVERLAP_UNKNOWN    // comparison could not be carried out at all
} KeyOverlap;

// Polynomial rolling hash over a KEY_ANCHOR_LEN-byte window, modulo 2^64
// via unsigned wraparound. Not cryptographic and does not need to be: a
// collision only costs a byte comparison (or, for the spent-heads
// registry, a second, structurally different digest check).
#define KEY_HASH_BASE 1099511628211ULL

static uint64_t anchor_hash(const unsigned char *buf, size_t len)
{
  uint64_t h = 0;
  for (size_t i = 0; i < len; i++)
    h = h * KEY_HASH_BASE + buf[i];
  return h;
}

// FNV-1a: the independent second digest used to confirm a rolling-hash
// hit where the original bytes are no longer available to compare
// against (the spent-heads registry stores digests, never key bytes).
static uint64_t confirm_hash(const unsigned char *buf, size_t len)
{
  uint64_t h = 14695981039346656037ULL;
  for (size_t i = 0; i < len; i++)
  {
    h ^= buf[i];
    h *= 1099511628211ULL;
  }
  return h;
}

// The weight the oldest byte of the window carries in the rolling hash,
// KEY_HASH_BASE^(KEY_ANCHOR_LEN-1) mod 2^64.
static uint64_t rolling_out_weight(void)
{
  uint64_t w = 1;
  for (int i = 0; i < KEY_ANCHOR_LEN - 1; i++)
    w *= KEY_HASH_BASE;
  return w;
}

// Search `hay_path` (of size `hay_size`) for the first KEY_ANCHOR_LEN
// bytes of `needle_path`. Returns 1 and sets *found_at to the byte offset
// of the first match, 0 when absent, -1 when the search could not be
// carried out - which, exactly like file_ranges_equal()'s -1, must stay
// distinct from "absent": a failed search proves nothing about the files.
static int find_head_in_file(const char *needle_path,
                             const char *hay_path, size_t hay_size,
                             size_t *found_at)
{
  // Same fault injection as file_ranges_equal(): the whole overlap check
  // must fail closed together.
  if (getenv("OTP_TEST_FAIL_KEY_COMPARE"))
    return -1;
  if (hay_size < KEY_ANCHOR_LEN)
    return 0;

  unsigned char anchor[KEY_ANCHOR_LEN];
  FILE *nf = fopen(needle_path, "rb");
  if (!nf)
    return -1;
  size_t got = fread(anchor, 1, KEY_ANCHOR_LEN, nf);
  fclose(nf);
  if (got != KEY_ANCHOR_LEN)
    return -1; // callers only search for heads they know are this long

  uint64_t target = anchor_hash(anchor, KEY_ANCHOR_LEN);
  uint64_t out_weight = rolling_out_weight();

  FILE *hf = fopen(hay_path, "rb");
  unsigned char *buf = malloc(KEY_COMPARE_CHUNK);
  if (!hf || !buf)
  {
    free(buf);
    if (hf)
      fclose(hf);
    return -1;
  }

  // Circular window of the last KEY_ANCHOR_LEN bytes; the byte at
  // absolute position p lives at index p % KEY_ANCHOR_LEN.
  unsigned char window[KEY_ANCHOR_LEN];
  uint64_t h = 0;
  size_t pos = 0;
  int result = 0;

  size_t n;
  while (result == 0 && (n = fread(buf, 1, KEY_COMPARE_CHUNK, hf)) > 0)
  {
    for (size_t i = 0; i < n; i++)
    {
      unsigned char c = buf[i];
      if (pos >= KEY_ANCHOR_LEN)
        h = (h - (uint64_t)window[pos % KEY_ANCHOR_LEN] * out_weight) * KEY_HASH_BASE + c;
      else
        h = h * KEY_HASH_BASE + c;
      window[pos % KEY_ANCHOR_LEN] = c;
      pos++;
      if (pos >= KEY_ANCHOR_LEN && h == target)
      {
        size_t start = pos - KEY_ANCHOR_LEN;
        int match = 1;
        for (int j = 0; j < KEY_ANCHOR_LEN; j++)
        {
          if (window[(start + j) % KEY_ANCHOR_LEN] != anchor[j])
          {
            match = 0;
            break;
          }
        }
        if (match)
        {
          *found_at = start;
          result = 1;
          break;
        }
      }
    }
  }

  // stat said hay_size bytes exist; reading fewer without an error flag
  // still means the file changed underfoot or the read silently failed.
  if (result == 0 && (ferror(hf) || pos != hay_size))
    result = -1;

  free(buf);
  fclose(hf);
  return result;
}

// Compare `length` bytes of two files, each starting at its own offset.
// Returns 1 if every byte matches, 0 if any byte differs, and -1 if the
// comparison could not be carried out (open/allocate/seek/read failure).
// The -1 case must stay distinct from 0: a failure here proves nothing
// about the ranges, and reporting it as "differ" would let two identical
// pads slip through the overlap check. Nor can the copy step that
// follows be trusted to hit the same problem - it uses a stack buffer
// and opens its files sequentially, so neither an allocation failure nor
// fd exhaustion here has to reproduce there.
static int file_ranges_equal(const char *path_a, size_t offset_a,
                             const char *path_b, size_t offset_b,
                             size_t length)
{
  if (length == 0)
    return 0;

  FILE *fa = fopen(path_a, "rb");
  FILE *fb = fopen(path_b, "rb");
  unsigned char *buf_a = malloc(KEY_COMPARE_CHUNK);
  unsigned char *buf_b = malloc(KEY_COMPARE_CHUNK);

  int result = (fa && fb && buf_a && buf_b) ? 1 : -1;

  // Test-only fault injection: simulates the acquisitions above failing,
  // to prove the check fails closed instead of reading as "no overlap".
  // A no-op whenever the variable isn't set.
  if (getenv("OTP_TEST_FAIL_KEY_COMPARE"))
    result = -1;

  // otp_fseek(), not fseek(): fseek() takes a long, which is 32-bit on
  // Windows even in 64-bit builds, so a tail comparison on a key over
  // 2GB would silently start in the wrong place.
  if (result == 1 && (otp_fseek(fa, offset_a) != 0 || otp_fseek(fb, offset_b) != 0))
    result = -1;

  size_t left = length;
  while (result == 1 && left > 0)
  {
    size_t want = (left < KEY_COMPARE_CHUNK) ? left : KEY_COMPARE_CHUNK;
    if (fread(buf_a, 1, want, fa) != want || fread(buf_b, 1, want, fb) != want)
      result = -1; // stat said these bytes exist, so a short read is an I/O failure
    else if (memcmp(buf_a, buf_b, want) != 0)
      result = 0;
    else
      left -= want;
  }

  free(buf_a);
  free(buf_b);
  if (fa)
    fclose(fa);
  if (fb)
    fclose(fb);
  return result;
}

static KeyOverlap key_files_overlap(const char *path_a, const char *path_b,
                                    size_t size_a, size_t size_b)
{
  size_t shorter = (size_a < size_b) ? size_a : size_b;
  if (shorter == 0)
    return KEY_OVERLAP_NONE;

  // Files smaller than one anchor: aligned comparisons only (see the
  // block comment above KEY_COMPARE_CHUNK for why an interior search on
  // so few bytes would produce false refusals).
  if (shorter < KEY_ANCHOR_LEN)
  {
    int front = file_ranges_equal(path_a, 0, path_b, 0, shorter);
    if (front < 0)
      return KEY_OVERLAP_UNKNOWN;
    if (front)
      return (size_a == size_b) ? KEY_OVERLAP_IDENTICAL : KEY_OVERLAP_PREFIX;
    if (size_a == size_b)
      return KEY_OVERLAP_NONE;
    int tail = file_ranges_equal(path_a, size_a - shorter, path_b, size_b - shorter, shorter);
    if (tail < 0)
      return KEY_OVERLAP_UNKNOWN;
    return tail ? KEY_OVERLAP_SUFFIX : KEY_OVERLAP_NONE;
  }

  // Search for each file's opening anchor anywhere in the other. This
  // covers the aligned cases (a prefix match sits at offset 0, a suffix
  // match at the end) and every interior or partially-shifted overlap
  // that includes either file's head.
  for (int swapped = 0; swapped < 2; swapped++)
  {
    const char *needle = swapped ? path_b : path_a;
    const char *hay = swapped ? path_a : path_b;
    size_t needle_size = swapped ? size_b : size_a;
    size_t hay_size = swapped ? size_a : size_b;

    size_t at = 0;
    int found = find_head_in_file(needle, hay, hay_size, &at);
    if (found < 0)
      return KEY_OVERLAP_UNKNOWN;
    if (!found)
      continue;

    // The anchor match alone is already KEY_ANCHOR_LEN bytes of shared
    // pad. The full-extent comparison below only refines *how* the files
    // overlap for the caller's message; if the bytes past the anchor
    // diverge the pair still shares key material and is still refused,
    // just reported as interior overlap.
    size_t extent = hay_size - at;
    if (extent > needle_size)
      extent = needle_size;
    int whole = file_ranges_equal(needle, 0, hay, at, extent);
    if (whole < 0)
      return KEY_OVERLAP_UNKNOWN;
    if (whole != 1)
      return KEY_OVERLAP_INTERIOR;
    if (at == 0)
      return (size_a == size_b) ? KEY_OVERLAP_IDENTICAL : KEY_OVERLAP_PREFIX;
    if (at + needle_size == hay_size)
      return KEY_OVERLAP_SUFFIX;
    return KEY_OVERLAP_INTERIOR;
  }

  return KEY_OVERLAP_NONE;
}

// ---------------------------------------------------------------------------
// The spent-heads registry: <keychain_dir>/spent_heads
//
// Removing a contact deletes its key files, so nothing remains for the
// overlap check above to compare a later candidate against - which is
// exactly how a partially spent ORIGINAL key file could come back under a
// brand-new contact name and restart at offset 0 over bytes that already
// encrypted messages. The registry closes that hole: the first time a
// key's opening bytes are about to be consumed, two 64-bit digests of its
// first KEY_ANCHOR_LEN bytes are appended here, and every future add
// scans its candidate files for any registered head at any offset. The
// original always contains its own spent head, so it is recognized no
// matter what the contact is now called; the legitimately reusable
// remainder no longer contains it, so it still passes.
//
// Only digests are stored, never key bytes. This is still a deliberate,
// documented trade-off rather than a free lunch: a digest of spent pad
// bytes is a confirmation oracle - someone who reads this file AND holds
// a captured ciphertext can *verify a complete guess* of that message's
// first KEY_ANCHOR_LEN plaintext bytes. It recovers nothing by itself,
// and anyone able to read .keychain/ already holds every live key in it,
// which is strictly worse. The alternative - no durable trace - is the
// silent two-time pad this registry exists to prevent.
//
// Entries are one line each, "v1 <enc|dec> <rolling-hash> <confirm-hash>",
// appended and fsynced. The direction matters when a match is judged: a
// candidate DECRYPTION key containing an ENC-spent head is the mirrored
// other-endpoint pattern (it will decrypt exactly the messages those
// bytes already encrypted) and is only warned about; every other pairing
// means the same pad would cover two different messages and is refused.
// ---------------------------------------------------------------------------

typedef struct
{
  char direction[4]; // "enc" or "dec"
  uint64_t roll;
  uint64_t confirm;
} SpentHead;

static void spent_heads_path(const char *keychain_dir, char *path, size_t path_size)
{
  snprintf(path, path_size, "%s%cspent_heads", keychain_dir, PATH_SEPARATOR);
}

// Load every well-formed entry. A missing file is an empty registry. A
// malformed line (a torn append from a crash) is skipped rather than
// fatal: the entry it would have held was never durably recorded, and
// treating it as fatal would refuse every future add forever.
static int spent_heads_load(const char *keychain_dir, SpentHead **out, size_t *count)
{
  *out = NULL;
  *count = 0;

  char path[600];
  spent_heads_path(keychain_dir, path, sizeof(path));
  FILE *f = fopen(path, "r");
  if (!f)
    return (errno == ENOENT) ? 0 : -1;

  SpentHead *heads = NULL;
  size_t n = 0, cap = 0;
  char line[128];
  while (fgets(line, sizeof(line), f))
  {
    SpentHead h;
    unsigned long long roll, confirm;
    if (sscanf(line, "v1 %3s %llx %llx", h.direction, &roll, &confirm) != 3 ||
        (strcmp(h.direction, "enc") != 0 && strcmp(h.direction, "dec") != 0))
      continue;
    h.roll = roll;
    h.confirm = confirm;
    if (n == cap)
    {
      size_t new_cap = cap ? cap * 2 : 16;
      SpentHead *nh = realloc(heads, new_cap * sizeof(*nh));
      if (!nh)
      {
        free(heads);
        fclose(f);
        return -1;
      }
      heads = nh;
      cap = new_cap;
    }
    heads[n++] = h;
  }

  int bad = ferror(f);
  fclose(f);
  if (bad)
  {
    free(heads);
    return -1;
  }
  *out = heads;
  *count = n;
  return 0;
}

// Record the head of `key_path` as spent. Called at the moment the key's
// first bytes are about to be consumed for the first time, BEFORE any
// consumption is committed: recorded-but-unspent (after a crash) costs at
// worst a spurious refusal of a key that was never actually used, while
// spent-but-unrecorded would silently lose the very protection the
// registry provides. A failure here must therefore abort the caller's
// operation while nothing has been spent yet. Called from cipher.c at the
// moment an encrypt/decrypt first touches a key's offset 0.
int spent_head_record(const char *keychain_dir, const char *direction,
                      const char *key_path)
{
  // Test-only fault injection: proves a failed record aborts the
  // operation before key material is spent. A no-op when unset.
  if (getenv("OTP_TEST_FAIL_SPENT_RECORD"))
    return -1;

  unsigned char head[KEY_ANCHOR_LEN];
  FILE *kf = fopen(key_path, "rb");
  if (!kf)
    return -1;
  size_t got = fread(head, 1, KEY_ANCHOR_LEN, kf);
  fclose(kf);
  // A key with fewer than KEY_ANCHOR_LEN bytes cannot be recorded (or
  // later searched for) without false positives; what a missed record
  // leaves unprotected is smaller than one anchor.
  if (got < KEY_ANCHOR_LEN)
    return 0;

  uint64_t roll = anchor_hash(head, KEY_ANCHOR_LEN);
  uint64_t confirm = confirm_hash(head, KEY_ANCHOR_LEN);

  // Skip an entry that is already present: crash recovery can pass
  // through offset 0 more than once for the same head.
  SpentHead *heads = NULL;
  size_t n = 0;
  if (spent_heads_load(keychain_dir, &heads, &n) != 0)
    return -1;
  for (size_t i = 0; i < n; i++)
  {
    if (heads[i].roll == roll && heads[i].confirm == confirm &&
        strcmp(heads[i].direction, direction) == 0)
    {
      free(heads);
      return 0;
    }
  }
  free(heads);

  char path[600];
  spent_heads_path(keychain_dir, path, sizeof(path));
  // O_APPEND with a single sub-buffer-sized write, so two processes
  // spending different contacts' keys at once interleave whole lines,
  // never fragments. Created 0600 like everything else in .keychain.
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_BINARY_FLAG, 0600);
  if (fd < 0)
    return -1;
  FILE *f = fdopen(fd, "ab");
  if (!f)
  {
    close(fd);
    return -1;
  }
  int rc = 0;
  if (fprintf(f, "v1 %s %016llx %016llx\n", direction,
              (unsigned long long)roll, (unsigned long long)confirm) < 0 ||
      fflush(f) != 0 || otp_fsync(fileno(f)) != 0)
    rc = -1;
  if (fclose(f) != 0)
    rc = -1;
  return rc;
}

// Scan `path` for any registered spent head at any byte offset, with the
// same rolling hash the pairwise search uses. Returns 1 and the matching
// entry's index, 0 when clean, and -1 when the scan could not be carried
// out - which callers must treat as "not proven clean", never as clean.
static int spent_heads_scan_file(const char *path, const SpentHead *heads,
                                 size_t count, size_t *match)
{
  if (count == 0)
    return 0;

  FILE *f = fopen(path, "rb");
  unsigned char *buf = malloc(KEY_COMPARE_CHUNK);
  if (!f || !buf)
  {
    free(buf);
    if (f)
      fclose(f);
    return -1;
  }

  uint64_t out_weight = rolling_out_weight();
  unsigned char window[KEY_ANCHOR_LEN];
  uint64_t h = 0;
  size_t pos = 0;
  int result = 0;

  size_t n;
  while (result == 0 && (n = fread(buf, 1, KEY_COMPARE_CHUNK, f)) > 0)
  {
    for (size_t i = 0; i < n && result == 0; i++)
    {
      unsigned char c = buf[i];
      if (pos >= KEY_ANCHOR_LEN)
        h = (h - (uint64_t)window[pos % KEY_ANCHOR_LEN] * out_weight) * KEY_HASH_BASE + c;
      else
        h = h * KEY_HASH_BASE + c;
      window[pos % KEY_ANCHOR_LEN] = c;
      pos++;
      if (pos < KEY_ANCHOR_LEN)
        continue;

      // The confirm digest is computed at most once per position, and
      // only when some entry's rolling hash already matched.
      uint64_t confirm = 0;
      int have_confirm = 0;
      for (size_t e = 0; e < count; e++)
      {
        if (heads[e].roll != h)
          continue;
        if (!have_confirm)
        {
          unsigned char ordered[KEY_ANCHOR_LEN];
          size_t start = pos - KEY_ANCHOR_LEN;
          for (int j = 0; j < KEY_ANCHOR_LEN; j++)
            ordered[j] = window[(start + j) % KEY_ANCHOR_LEN];
          confirm = confirm_hash(ordered, KEY_ANCHOR_LEN);
          have_confirm = 1;
        }
        if (heads[e].confirm == confirm)
        {
          *match = e;
          result = 1;
          break;
        }
      }
    }
  }

  if (result == 0 && ferror(f))
    result = -1;

  free(buf);
  fclose(f);
  return result;
}

// A contact name that has been used before is a reuse hazard the program
// cannot see through: its key files are gone, so there is nothing left to
// compare a freshly supplied key against. The lock file deliberately
// outlives a removed contact, which makes it the one durable trace that
// this name was in service. Warn rather than refuse - rotating a contact
// onto genuinely fresh keys is legitimate and common - but say plainly
// which key files are safe to supply.
static void warn_if_name_previously_used(const char *keychain_dir, const char *name)
{
  char path[600];
  unsigned long long ignored;
  int had_keys = 0, had_lock = 0;

  snprintf(path, sizeof(path), "%s%c%s_enc.key", keychain_dir, PATH_SEPARATOR, name);
  if (otp_file_size(path, &ignored) == 0)
    had_keys = 1;
  snprintf(path, sizeof(path), "%s%c%s_dec.key", keychain_dir, PATH_SEPARATOR, name);
  if (otp_file_size(path, &ignored) == 0)
    had_keys = 1;
  snprintf(path, sizeof(path), "%s%c%s.lock", keychain_dir, PATH_SEPARATOR, name);
  if (otp_file_size(path, &ignored) == 0)
    had_lock = 1;

  if (!had_keys && !had_lock)
    return;

  fprintf(stderr,
          "Warning: contact '%s' has been used on this keychain before (%s). If the key files you "
          "are supplying now are the ORIGINAL copies from key generation, part of that key has "
          "already encrypted messages, and using it again breaks the one-time pad. Only supply key "
          "material that has never been used - either freshly generated keys, or the partially "
          "consumed files from %s%c itself.\n",
          name, had_keys ? "its key files are still present" : "a lock file from a previous contact remains",
          keychain_dir, PATH_SEPARATOR);
}

// Build path for contact's key file
static void build_key_path(const char *contact_name, const char *key_type,
                           char *path, size_t path_size)
{
  char dir[512];
  get_keychain_dir(dir, sizeof(dir));
  int written = snprintf(path, path_size, "%s" PATH_SEPARATOR_STR "%s_%s.key", dir, contact_name, key_type);
  // Ensure null termination if truncated
  if (written >= (int)path_size)
  {
    path[path_size - 1] = '\0';
  }
}

// A contact's name is not just a label: it is used verbatim to build the
// filenames of that contact's key files, its .meta file, its .lock file
// and its pending artifacts, all of which are meant to stay inside the
// keychain directory. Without validation, a name like "../../evil" would
// place those files anywhere the user can write, and a name containing a
// path separator could make two distinct contacts share one lock file -
// quietly defeating the mutual exclusion the lock exists to provide.
//
// Rejected: empty or over-long names, "." and "..", anything containing a
// path separator or a character that is illegal in a Windows filename,
// control characters, and '=' (which would corrupt the key=value .meta
// format the name is stored in). Everything else - spaces, dots,
// non-ASCII/UTF-8 names - is still allowed.
//
// Not static: --new-key-pair's part_a/part_b names are built into paths
// (<name>_keys/..., and the vault's pending-claim artifact inside
// .keychain/) exactly the same way a contact's name is, so they need the
// same protection - see the CLI's use of this function.
int is_valid_contact_name(const char *name)
{
  if (!name || name[0] == '\0')
    return 0;
  if (strlen(name) >= MAX_NAME_LENGTH)
    return 0;
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;

  for (const unsigned char *p = (const unsigned char *)name; *p; p++)
  {
    if (*p < 0x20 || *p == 0x7f)
      return 0;
    if (strchr("/\\:*?\"<>|=", (char)*p))
      return 0;
  }
  return 1;
}

static int reject_invalid_contact_name(const char *name)
{
  if (is_valid_contact_name(name))
    return 0;
  fprintf(stderr,
          "Error: Invalid contact name '%s' - names must be 1-%d characters and may not be "
          "\".\" or \"..\", contain a path separator (/ or \\), any of : * ? \" < > | = , "
          "or control characters\n",
          name ? name : "", MAX_NAME_LENGTH - 1);
  return -1;
}

// Initialize keychain
void init_keychain(void)
{
  memset(&g_keychain, 0, sizeof(Keychain));
  g_keychain.count = 0;
}

// Cleanup keychain memory
//
// Contacts own no heap allocations - key material lives in files and
// metadata is all fixed-size fields - so dropping the count is the whole
// job.
void cleanup_keychain(void)
{
  g_keychain.count = 0;
}

// Find a contact by name
Contact *find_contact(const char *name)
{
  for (int i = 0; i < g_keychain.count; i++)
  {
    if (strcmp(g_keychain.contacts[i].Name, name) == 0)
    {
      return &g_keychain.contacts[i];
    }
  }
  return NULL;
}

// Escape special characters for file storage
static void escape_string(const char *input, char *output, size_t max_output)
{
  size_t i, j;
  for (i = 0, j = 0; input[i] && j < max_output - 2; i++)
  {
    if (input[i] == '\\' || input[i] == '\n' || input[i] == '\r')
    {
      output[j++] = '\\';
      if (input[i] == '\n')
        output[j++] = 'n';
      else if (input[i] == '\r')
        output[j++] = 'r';
      else
        output[j++] = '\\';
    }
    else
    {
      output[j++] = input[i];
    }
  }
  output[j] = '\0';
}

static void unescape_string(const char *input, char *output, size_t max_output)
{
  size_t i, j;
  for (i = 0, j = 0; input[i] && j < max_output - 1; i++)
  {
    if (input[i] == '\\' && input[i + 1])
    {
      i++;
      if (input[i] == 'n')
        output[j++] = '\n';
      else if (input[i] == 'r')
        output[j++] = '\r';
      else
        output[j++] = input[i];
    }
    else
    {
      output[j++] = input[i];
    }
  }
  output[j] = '\0';
}

// Read the key=value fields of one contact's .meta file from an
// already-open stream, stopping at a blank line, a "[...]" section
// header, or EOF.
static void parse_contact_fields(FILE *f, Contact *c)
{
// Every field is bounded: the longest possible line is a key file path
// (512) or an escaped contact name (512), so a few KB is ample. Nothing
// stored here scales with message or key size.
#define FIELD_LINE_BUFFER_SIZE 8192
  char *line = malloc(FIELD_LINE_BUFFER_SIZE);
  char *value = malloc(FIELD_LINE_BUFFER_SIZE);
  if (!line || !value)
  {
    free(line);
    free(value);
    return;
  }

  while (fgets(line, FIELD_LINE_BUFFER_SIZE, f))
  {
    if (line[0] == '\n' || line[0] == '[')
      break;

    char key[256];
    // Split at the first '='; the value is copied manually so its length
    // is not capped by a sscanf field width (key file paths can be long)
    char *equals = strchr(line, '=');
    if (equals && sscanf(line, "%255[^=]", key) == 1)
    {
      // Copy everything after '=' to value
      strncpy(value, equals + 1, FIELD_LINE_BUFFER_SIZE - 1);
      value[FIELD_LINE_BUFFER_SIZE - 1] = '\0';
      // Remove trailing newline if present
      size_t len = strlen(value);
      if (len > 0 && value[len - 1] == '\n')
      {
        value[len - 1] = '\0';
      }
      if (strcmp(key, "Name") == 0)
      {
        unescape_string(value, c->Name, MAX_NAME_LENGTH);
      }
      else if (strcmp(key, "EncryptionKeyPath") == 0)
      {
        strncpy(c->EncryptionKeyPath, value, sizeof(c->EncryptionKeyPath) - 1);
      }
      else if (strcmp(key, "EncryptionKeySize") == 0)
      {
        c->EncryptionKeySize = (size_t)atoll(value);
      }
      else if (strcmp(key, "EncryptionKeyOffset") == 0)
      {
        c->EncryptionKeyOffset = (size_t)atoll(value);
      }
      else if (strcmp(key, "EncryptedSequence") == 0)
      {
        c->EncryptedSequence = (size_t)atoll(value);
      }
      else if (strcmp(key, "DecryptionKeyPath") == 0)
      {
        strncpy(c->DecryptionKeyPath, value, sizeof(c->DecryptionKeyPath) - 1);
      }
      else if (strcmp(key, "DecryptionKeySize") == 0)
      {
        c->DecryptionKeySize = (size_t)atoll(value);
      }
      else if (strcmp(key, "DecryptionKeyOffset") == 0)
      {
        c->DecryptionKeyOffset = (size_t)atoll(value);
      }
      else if (strcmp(key, "DecryptedSequence") == 0)
      {
        c->DecryptedSequence = (size_t)atoll(value);
      }
      else if (strcmp(key, "RetryCount") == 0)
      {
        c->RetryCount = atoi(value);
        if (c->RetryCount < MIN_RETRY_COUNT)
          c->RetryCount = MIN_RETRY_COUNT;
        if (c->RetryCount > MAX_RETRY_COUNT)
          c->RetryCount = MAX_RETRY_COUNT;
      }
      else if (strcmp(key, "LastMessageSentAt") == 0)
      {
        c->LastMessageSentAt = (time_t)atoll(value);
      }
      else if (strcmp(key, "LastMessageReceivedAt") == 0)
      {
        c->LastMessageReceivedAt = (time_t)atoll(value);
      }
    }
  }

  free(line);
  free(value);
#undef FIELD_LINE_BUFFER_SIZE
}

// Small growable buffer used to build one contact's metadata content in
// memory before it is committed - this lets save_contact_meta hand the
// exact, complete, intended bytes to commit_write_verified() for a real
// read-back comparison, rather than trusting fprintf()'s return value.
typedef struct
{
  char *data;
  size_t len;
  size_t cap;
} GrowBuf;

static int gb_append(GrowBuf *g, const char *s, size_t n)
{
  if (g->len + n + 1 > g->cap)
  {
    size_t new_cap = g->cap ? g->cap * 2 : 4096;
    while (new_cap < g->len + n + 1)
      new_cap *= 2;
    char *nd = realloc(g->data, new_cap);
    if (!nd)
      return -1;
    g->data = nd;
    g->cap = new_cap;
  }
  memcpy(g->data + g->len, s, n);
  g->len += n;
  g->data[g->len] = '\0';
  return 0;
}

static int gb_printf(GrowBuf *g, const char *fmt, ...)
{
  char stackbuf[4096];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
  va_end(ap);
  if (n < 0)
    return -1;
  if ((size_t)n < sizeof(stackbuf))
    return gb_append(g, stackbuf, (size_t)n);

  char *big = malloc((size_t)n + 1);
  if (!big)
    return -1;
  va_start(ap, fmt);
  vsnprintf(big, (size_t)n + 1, fmt, ap);
  va_end(ap);
  int rc = gb_append(g, big, (size_t)n);
  free(big);
  return rc;
}

// Persist ONE contact to its own file, <keychain_dir>/<name>.meta -
// atomically and verified, via the same stage -> verify -> publish
// primitives used everywhere else in this module (commit_write_verified
// + commit_publish). Each contact's metadata lives in its own file, so
// concurrent operations on two different contacts write to two different
// files and cannot collide here at all - there is no shared mutable
// state between contacts for them to race on. Also called from cipher.c
// after each committed encrypt/decrypt step.
int save_contact_meta(const char *keychain_dir, Contact *c)
{
  GrowBuf buf = {0};
  int build_failed = 0;

  char escaped_name[MAX_NAME_LENGTH * 2];
  escape_string(c->Name, escaped_name, sizeof(escaped_name));

  if (gb_printf(&buf, "[CONTACT]\n") != 0 ||
      gb_printf(&buf, "Name=%s\n", escaped_name) != 0 ||
      gb_printf(&buf, "EncryptionKeyPath=%s\n", c->EncryptionKeyPath) != 0 ||
      gb_printf(&buf, "EncryptionKeySize=%zu\n", c->EncryptionKeySize) != 0 ||
      gb_printf(&buf, "EncryptionKeyOffset=%zu\n", c->EncryptionKeyOffset) != 0 ||
      gb_printf(&buf, "EncryptedSequence=%zu\n", c->EncryptedSequence) != 0 ||
      gb_printf(&buf, "DecryptionKeyPath=%s\n", c->DecryptionKeyPath) != 0 ||
      gb_printf(&buf, "DecryptionKeySize=%zu\n", c->DecryptionKeySize) != 0 ||
      gb_printf(&buf, "DecryptionKeyOffset=%zu\n", c->DecryptionKeyOffset) != 0 ||
      gb_printf(&buf, "DecryptedSequence=%zu\n", c->DecryptedSequence) != 0)
  {
    build_failed = 1;
  }

  // Message content is deliberately never stored here - only fixed-size
  // bookkeeping. That keeps a .meta file the same handful of bytes no
  // matter how much traffic passes through the contact, and keeps this
  // function's write-fsync-read-back verification cheap enough to run on
  // every single operation.
  if (!build_failed &&
      (gb_printf(&buf, "RetryCount=%d\n", c->RetryCount) != 0 ||
       gb_printf(&buf, "LastMessageSentAt=%lld\n", (long long)c->LastMessageSentAt) != 0 ||
       gb_printf(&buf, "LastMessageReceivedAt=%lld\n", (long long)c->LastMessageReceivedAt) != 0))
  {
    build_failed = 1;
  }

  if (build_failed)
  {
    fprintf(stderr, "Error: Memory allocation failed while building metadata for '%s'\n", c->Name);
    free(buf.data);
    return -1;
  }

  char meta_path[600];
  snprintf(meta_path, sizeof(meta_path), "%s%c%s.meta", keychain_dir, PATH_SEPARATOR, c->Name);
  char tmp_path[620];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", meta_path);

  if (commit_write_verified(tmp_path, (const unsigned char *)buf.data, buf.len) != 0)
  {
    free(buf.data);
    return -1;
  }
  free(buf.data);

  commit_test_crash_point("after_meta_staged");

  return commit_publish(tmp_path, meta_path);
}

// Load a single contact from its own .meta file into g_keychain.
static void load_contact_meta_file(const char *path)
{
  if (g_keychain.count >= MAX_CONTACTS)
    return;

  FILE *f = fopen(path, "r");
  if (!f)
    return;

  char header[32];
  if (!fgets(header, sizeof(header), f))
  {
    fclose(f);
    return;
  }
  // First line is the "[CONTACT]" marker written by save_contact_meta();
  // remaining lines are key=value fields.

  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));
  parse_contact_fields(f, c);
  fclose(f);

  // Validate here too, not only on add: this is the single choke point
  // every contact passes through before anything builds a file path from
  // its name, so a hand-edited or hand-planted .meta file can't smuggle
  // one past the checks in add_contact/add_contact_with_keys.
  if (!is_valid_contact_name(c->Name))
  {
    if (c->Name[0] != '\0')
      fprintf(stderr, "Warning: ignoring '%s' - it declares an invalid contact name\n", path);
    memset(c, 0, sizeof(Contact));
    return;
  }

  g_keychain.count++;
}

// Load keychain: reads every contact from its own .meta file under the
// keychain directory.
//
// This is a pure reader - it writes nothing, and must stay that way.
// It runs both before any lock is held (process startup) and again after
// a contact's lock is acquired; if it wrote, two processes starting at
// once could each persist their own stale view of a contact, one
// overwriting offsets the other had already committed. Reading only
// makes that impossible by construction.
//
// A contact exists if and only if it has a <name>.meta file in the
// keychain directory; nothing else in the directory is consulted.
int load_keychain(void)
{
  cleanup_keychain();
  init_keychain();

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Every contact lives in its own <name>.meta file inside the keychain
  // directory - load each one. opendir/readdir/closedir come from
  // compat.h, which is a real dirent-backed implementation on POSIX
  // and a FindFirstFile/FindNextFile-backed shim on Windows, so this
  // loop is identical on both platforms.
  DIR *d = opendir(keychain_dir);
  if (!d)
    return 0; // brand new keychain - nothing to load yet

  struct dirent *entry;
  while ((entry = readdir(d)) != NULL)
  {
    size_t name_len = strlen(entry->d_name);
    if (name_len <= 5 || strcmp(entry->d_name + name_len - 5, ".meta") != 0)
      continue;

    char full_path[600];
    int written = snprintf(full_path, sizeof(full_path), "%s%c%s",
                           keychain_dir, PATH_SEPARATOR, entry->d_name);
    if (written < 0 || (size_t)written >= sizeof(full_path))
    {
      fprintf(stderr, "Warning: skipping '%s' - its full path is too long\n", entry->d_name);
      continue;
    }
    load_contact_meta_file(full_path);
  }
  closedir(d);

  return 0;
}


// Add a contact. Runs with this contact's lock already held and the
// keychain freshly reloaded under it - see add_contact().
static int add_contact_locked(const char *name, const char *keychain_dir)
{
  if (g_keychain.count >= MAX_CONTACTS)
  {
    fprintf(stderr, "Error: Maximum contacts reached\n");
    return -1;
  }

  if (find_contact(name))
  {
    fprintf(stderr, "Error: Contact '%s' already exists\n", name);
    return -1;
  }

  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));
  strncpy(c->Name, name, MAX_NAME_LENGTH - 1);
  c->RetryCount = 0;

  g_keychain.count++;

  return save_contact_meta(keychain_dir, c);
}

int add_contact(const char *name)
{
  if (reject_invalid_contact_name(name) != 0)
    return -1;

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Hold this contact's lock across the existence check and the write -
  // the same per-contact lock encrypt/decrypt/remove take. Without it two
  // concurrent adds of one name both see "does not exist" and the slower
  // writer is silently lost, and an add can race a remove of the same
  // name. The lock name is built from the contact name, so validation
  // above must have passed first.
  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, name) != 0)
    return -1;

  // Re-read the on-disk state now that the lock is held: another process
  // may have added or removed this contact while we waited for the lock,
  // so the snapshot loaded at process start (without the lock) can be stale.
  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }

  int result = add_contact_locked(name, keychain_dir);
  contact_lock_release(&lock);
  return result;
}

// Add a contact with key files. Runs with this contact's lock already
// held and the keychain freshly reloaded under it - see
// add_contact_with_keys(). Holding the lock is what makes the
// cross-contact overlap scan below read a stable set of other contacts:
// without it, a concurrent add of the same name could also pass its own
// existence check and both would write, and the reloaded view could go
// stale mid-scan.
static int add_contact_with_keys_locked(const char *name, const char *encryption_key_file,
                                        const char *decryption_key_file, const char *keychain_dir)
{
  if (g_keychain.count >= MAX_CONTACTS)
  {
    fprintf(stderr, "Error: Maximum contacts reached\n");
    return -1;
  }

  if (find_contact(name))
  {
    fprintf(stderr, "Error: Contact '%s' already exists\n", name);
    return -1;
  }

  // Get key file sizes (without loading into memory). otp_file_size()
  // rather than stat(): the Windows CRT's struct stat carries a 32-bit
  // st_size, which would silently truncate the size of any key over 2GB.
  unsigned long long enc_size_64, dec_size_64;
  if (otp_file_size(encryption_key_file, &enc_size_64) != 0)
  {
    fprintf(stderr, "Error: Cannot stat encryption key file '%s': %s\n",
            encryption_key_file, strerror(errno));
    return -1;
  }
  if (otp_file_size(decryption_key_file, &dec_size_64) != 0)
  {
    fprintf(stderr, "Error: Cannot stat decryption key file '%s': %s\n",
            decryption_key_file, strerror(errno));
    return -1;
  }

  // Validate on the 64-bit sizes BEFORE narrowing to size_t: on a 32-bit
  // platform the cast itself truncates, so checking afterwards would let
  // an oversized key wrap around and slip past with a bogus small size.
  // On such platforms size_t's own range is the effective ceiling.
  unsigned long long max_key = MAX_KEY_SIZE;
  if ((unsigned long long)SIZE_MAX < max_key)
    max_key = (unsigned long long)SIZE_MAX;

  if (enc_size_64 > max_key)
  {
    fprintf(stderr, "Error: Encryption key file too large (max %llu bytes)\n",
            max_key);
    return -1;
  }
  if (dec_size_64 > max_key)
  {
    fprintf(stderr, "Error: Decryption key file too large (max %llu bytes)\n",
            max_key);
    return -1;
  }

  size_t enc_size = (size_t)enc_size_64;
  size_t dec_size = (size_t)dec_size_64;
  if (enc_size == 0 || dec_size == 0)
  {
    fprintf(stderr, "Error: Key files cannot be empty\n");
    return -1;
  }

  KeyOverlap overlap = key_files_overlap(encryption_key_file, decryption_key_file,
                                         enc_size, dec_size);
  if (overlap == KEY_OVERLAP_UNKNOWN)
  {
    // Fail closed: accepting an identical pair here would silently break
    // the pad forever, while refusing costs only a retry. This is the one
    // moment the mistake is detectable - once copied into the keychain the
    // two files are indistinguishable from a legitimately distinct pair.
    fprintf(stderr,
            "Error: Could not compare '%s' and '%s' to verify they hold different key "
            "material (a file could not be read, or memory for the comparison could not "
            "be allocated). Refusing to add the contact rather than risk installing one "
            "pad for both directions - resolve the failure and retry.\n",
            encryption_key_file, decryption_key_file);
    return -1;
  }
  if (overlap != KEY_OVERLAP_NONE)
  {
    fprintf(stderr,
            "Error: '%s' and '%s' contain the same key material%s. A contact needs two DIFFERENT "
            "one-time pads - one for sending, one for receiving. Using one pad for both means the "
            "bytes that encrypt an outgoing message also decrypt an incoming one, so the same key "
            "range covers two messages and the pad is broken. Generate a pair with "
            "--new-key-pair, which produces the two distinct keys this expects.\n",
            encryption_key_file, decryption_key_file,
            overlap == KEY_OVERLAP_IDENTICAL
                ? ""
                : (overlap == KEY_OVERLAP_PREFIX
                       ? " - the smaller file is the beginning of the larger one, so the whole of it "
                         "is key that the larger file also covers"
                       : (overlap == KEY_OVERLAP_SUFFIX
                              ? " - the smaller file is the tail of the larger one, which is what a partially "
                                "consumed key looks like; every byte it holds is still "
                                "present in the larger file"
                              : " - a stretch of one appears inside the other at an interior offset, which "
                                "is what a pad trimmed at both ends (or two windows cut from one pad) "
                                "looks like; every shared byte is one pad serving two roles")));
    return -1;
  }

  // The pair check above only rules out overlap between the two candidate
  // files themselves. The same pad must also not already be installed for
  // any OTHER contact: two contacts each consume their copy from its own
  // start, so shared material means two different messages encrypted or
  // decrypted with the same bytes. One shape is treated differently - the
  // mirrored pair (candidate enc = an existing dec, candidate dec = an
  // existing enc), which is how a single machine legitimately operates
  // both endpoints of its own pads (e.g. loopback testing in one
  // directory). That is allowed with a warning; same-direction overlap is
  // refused outright.
  struct
  {
    const char *path;
    size_t size;
    const char *word;
  } cands[2] = {
      {encryption_key_file, enc_size, "encryption"},
      {decryption_key_file, dec_size, "decryption"}};

  for (int i = 0; i < g_keychain.count; i++)
  {
    Contact *other = &g_keychain.contacts[i];
    struct
    {
      const char *path;
      const char *word;
    } theirs[2] = {
        {other->EncryptionKeyPath, "encryption"},
        {other->DecryptionKeyPath, "decryption"}};

    for (int t = 0; t < 2; t++)
    {
      if (theirs[t].path[0] == '\0')
        continue;
      unsigned long long their_size;
      if (otp_file_size(theirs[t].path, &their_size) != 0)
      {
        fprintf(stderr,
                "Error: Could not read contact '%s's %s key to rule out shared key material "
                "with the new contact. Refusing to add rather than risk installing an "
                "already-installed pad - resolve the failure and retry.\n",
                other->Name, theirs[t].word);
        return -1;
      }
      if (their_size == 0)
        continue; // fully consumed - nothing left to overlap with

      // A key too large for this build's size_t (possible when a keychain
      // written by a 64-bit build is opened by a 32-bit one) cannot be
      // compared without truncating it, which could hide an overlap - so
      // refuse to add, same as any other unverifiable-overlap failure.
      size_t their_size_sz;
      if (otp_size_to_size_t(their_size, &their_size_sz) != 0)
      {
        fprintf(stderr,
                "Error: contact '%s's %s key is too large for this build to rule out shared "
                "key material with the new contact. Refusing to add rather than risk "
                "installing an already-installed pad.\n",
                other->Name, theirs[t].word);
        return -1;
      }

      for (int cnd = 0; cnd < 2; cnd++)
      {
        KeyOverlap cross = key_files_overlap(cands[cnd].path, theirs[t].path,
                                             cands[cnd].size, their_size_sz);
        if (cross == KEY_OVERLAP_UNKNOWN)
        {
          fprintf(stderr,
                  "Error: Could not compare '%s' against contact '%s's %s key to rule out "
                  "shared key material. Refusing to add the contact rather than risk "
                  "installing one pad twice - resolve the failure and retry.\n",
                  cands[cnd].path, other->Name, theirs[t].word);
          return -1;
        }
        if (cross == KEY_OVERLAP_NONE)
          continue;
        if (cnd == t)
        {
          fprintf(stderr,
                  "Error: '%s' holds the same key material as contact '%s's %s key. One pad "
                  "installed under two contacts is consumed twice from its own start, so two "
                  "different messages would share key bytes - a broken one-time pad. Every "
                  "contact needs key material no other contact holds.\n",
                  cands[cnd].path, other->Name, theirs[t].word);
          return -1;
        }
        fprintf(stderr,
                "Warning: '%s' matches contact '%s's %s key - this pair looks like the "
                "other endpoint of that contact's pads. That is only safe when this "
                "keychain deliberately operates both correspondents (for example loopback "
                "testing in one directory); between two real contacts a shared pad breaks.\n",
                cands[cnd].path, other->Name, theirs[t].word);
      }
    }
  }

  // Keys of *removed* contacts no longer exist to be compared against;
  // the spent-heads registry is what remains of them. A candidate that
  // contains a recorded spent head is (a copy of) an original whose
  // opening bytes already encrypted or decrypted messages here.
  SpentHead *spent = NULL;
  size_t spent_count = 0;
  if (spent_heads_load(keychain_dir, &spent, &spent_count) != 0)
  {
    fprintf(stderr,
            "Error: Could not read the spent-key registry (%s%cspent_heads) to check the "
            "supplied keys against previously consumed material. Refusing to add the "
            "contact rather than risk re-installing a spent pad - resolve the failure "
            "and retry.\n",
            keychain_dir, PATH_SEPARATOR);
    return -1;
  }
  for (int cnd = 0; cnd < 2 && spent_count > 0; cnd++)
  {
    size_t m = 0;
    int hit = spent_heads_scan_file(cands[cnd].path, spent, spent_count, &m);
    if (hit < 0)
    {
      fprintf(stderr,
              "Error: Could not scan '%s' against the spent-key registry. Refusing to add "
              "the contact rather than risk re-installing a spent pad - resolve the "
              "failure and retry.\n",
              cands[cnd].path);
      free(spent);
      return -1;
    }
    if (hit == 1)
    {
      int cand_is_enc = (cnd == 0);
      int spent_as_enc = (strcmp(spent[m].direction, "enc") == 0);
      if (!cand_is_enc && spent_as_enc)
      {
        // The mirrored-endpoint case again, this time against history: a
        // decryption key holding an enc-spent head will decrypt exactly
        // the messages those bytes already encrypted - no new exposure.
        fprintf(stderr,
                "Warning: '%s' contains the head of key material this keychain already "
                "spent for encryption. As a decryption key it will decrypt exactly those "
                "already-sent messages - sensible only when this keychain deliberately "
                "acts as the other endpoint of its own pads.\n",
                cands[cnd].path);
      }
      else
      {
        fprintf(stderr,
                "Error: '%s' contains key material that was already spent on this keychain: "
                "its bytes include the head of a %s key consumed by a previous message "
                "(possibly under a contact that has since been removed). Using them again "
                "would cover two messages with one pad. Supply only never-used key "
                "material, or the partially consumed remainder file if you kept it.\n",
                cands[cnd].path, spent_as_enc ? "encryption" : "decryption");
        free(spent);
        return -1;
      }
    }
  }
  free(spent);

  // Build destination paths
  char enc_dest[512], dec_dest[512];
  build_key_path(name, "enc", enc_dest, sizeof(enc_dest));
  build_key_path(name, "dec", dec_dest, sizeof(dec_dest));

  // Copy both key files into the keychain, 0600 and fsynced
  if (copy_key_file(encryption_key_file, enc_dest) != 0)
    return -1;

  if (copy_key_file(decryption_key_file, dec_dest) != 0)
  {
    unlink(enc_dest);
    return -1;
  }

  // Create contact with paths to key files
  Contact *c = &g_keychain.contacts[g_keychain.count];
  memset(c, 0, sizeof(Contact));

  snprintf(c->Name, MAX_NAME_LENGTH, "%s", name);
  snprintf(c->EncryptionKeyPath, sizeof(c->EncryptionKeyPath), "%s", enc_dest);
  c->EncryptionKeySize = enc_size;
  c->EncryptionKeyOffset = 0;
  snprintf(c->DecryptionKeyPath, sizeof(c->DecryptionKeyPath), "%s", dec_dest);
  c->DecryptionKeySize = dec_size;
  c->DecryptionKeyOffset = 0;
  c->EncryptedSequence = 0;
  c->DecryptedSequence = 0;
  c->RetryCount = 0;
  c->LastMessageSentAt = 0;
  c->LastMessageReceivedAt = 0;

  g_keychain.count++;

  int result = save_contact_meta(keychain_dir, c);
  if (result == 0)
  {
    printf("Contact '%s' added with keys:\n", name);
    printf("  Encryption key: %zu bytes from %s\n", enc_size, encryption_key_file);
    printf("  Decryption key: %zu bytes from %s\n", dec_size, decryption_key_file);
  }

  return result;
}

int add_contact_with_keys(const char *name, const char *encryption_key_file, const char *decryption_key_file)
{
  if (reject_invalid_contact_name(name) != 0)
    return -1;

  char keychain_dir[512];
  if (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) != 0)
  {
    fprintf(stderr, "Error: Cannot determine keychain directory\n");
    return -1;
  }

  // Sample the "name used before" signal *before* acquiring this contact's
  // lock: acquiring it creates <name>.lock, which is one of the very
  // signals this warning keys on, so reading it afterwards would make the
  // warning fire on every add. It only reads files and needs no locking.
  warn_if_name_previously_used(keychain_dir, name);

  // Same per-contact lock discipline as encrypt/decrypt/remove - see
  // add_contact() for why an add must hold it too.
  ContactLock lock;
  if (contact_lock_acquire(&lock, keychain_dir, name) != 0)
    return -1;

  if (load_keychain() != 0)
  {
    fprintf(stderr, "Error: Failed to reload keychain\n");
    contact_lock_release(&lock);
    return -1;
  }

  int result = add_contact_with_keys_locked(name, encryption_key_file,
                                            decryption_key_file, keychain_dir);
  contact_lock_release(&lock);
  return result;
}

// Remove a contact
int remove_contact(const char *name)
{
  int index = -1;
  for (int i = 0; i < g_keychain.count; i++)
  {
    if (strcmp(g_keychain.contacts[i].Name, name) == 0)
    {
      index = i;
      break;
    }
  }

  if (index == -1)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", name);
    return -1;
  }

  // Hold the same per-contact lock encrypt/decrypt use, so a removal
  // can't race with an in-flight operation that's mid-way through
  // reading or truncating this contact's key files.
  char keychain_dir[512];
  int have_dir = (get_keychain_dir(keychain_dir, sizeof(keychain_dir)) == 0);

  ContactLock lock;
  int locked = 0;
  if (have_dir)
  {
    if (contact_lock_acquire(&lock, keychain_dir, name) != 0)
      return -1;
    locked = 1;

    // Reload from disk now that we hold the lock, and re-find the
    // contact by name (not by the index computed before the wait) in
    // case concurrent activity changed its position or removed it.
    //
    // A failed reload has to abort: load_keychain() empties the in-memory
    // keychain before it can fail, so carrying on with the pre-reload
    // `index` would read a zeroed contact and then decrement a count that
    // is already 0 down to -1.
    if (load_keychain() != 0)
    {
      fprintf(stderr, "Error: Failed to reload keychain\n");
      contact_lock_release(&lock);
      return -1;
    }

    index = -1;
    for (int i = 0; i < g_keychain.count; i++)
    {
      if (strcmp(g_keychain.contacts[i].Name, name) == 0)
      {
        index = i;
        break;
      }
    }
    if (index == -1)
    {
      fprintf(stderr, "Error: Contact '%s' not found\n", name);
      contact_lock_release(&lock);
      return -1;
    }
  }

  // Delete key files, and any staging sibling a crash mid-truncation may
  // have left next to them - that file holds this contact's key material,
  // so removing the key file without it would leave the secret behind.
  char sibling[600];
  if (g_keychain.contacts[index].EncryptionKeyPath[0] != '\0')
  {
    unlink(g_keychain.contacts[index].EncryptionKeyPath);
    snprintf(sibling, sizeof(sibling), "%s.tmp", g_keychain.contacts[index].EncryptionKeyPath);
    unlink(sibling);
  }
  if (g_keychain.contacts[index].DecryptionKeyPath[0] != '\0')
  {
    unlink(g_keychain.contacts[index].DecryptionKeyPath);
    snprintf(sibling, sizeof(sibling), "%s.tmp", g_keychain.contacts[index].DecryptionKeyPath);
    unlink(sibling);
  }

  // Clean up any leftover staged pending artifacts for this contact so
  // they don't linger in .keychain/ forever, and the kept last-payload
  // copies: removing a contact must take every trace of message content
  // with it (the empty .lock file below is the one deliberate exception).
  if (have_dir)
  {
    commit_discard_all_pending(keychain_dir, name);
    cipher_discard_last_copies(keychain_dir, name);
  }

  // Shift remaining contacts (in-memory bookkeeping only)
  for (int i = index; i < g_keychain.count - 1; i++)
  {
    g_keychain.contacts[i] = g_keychain.contacts[i + 1];
  }

  g_keychain.count--;

  // Each contact owns its own metadata file, so removing one is just
  // deleting that file - no other contact's file is ever touched.
  int result = 0;
  if (have_dir)
  {
    char meta_path[600];
    snprintf(meta_path, sizeof(meta_path), "%s%c%s.meta", keychain_dir, PATH_SEPARATOR, name);
    if (unlink(meta_path) != 0 && errno != ENOENT)
    {
      fprintf(stderr, "Error: Failed to remove metadata file %s: %s\n", meta_path, strerror(errno));
      result = -1;
    }

    char meta_tmp[620];
    snprintf(meta_tmp, sizeof(meta_tmp), "%s.tmp", meta_path);
    unlink(meta_tmp);
  }

  if (locked)
  {
    // The empty .lock file is deliberately left in place. Unlinking it
    // would break mutual exclusion for anyone already blocked on it:
    // flock() locks an *inode*, so a waiter holding the old, now-unlinked
    // inode and a newcomer that creates a fresh file at the same path
    // would each hold "the" lock simultaneously. That matters as soon as
    // a contact is re-added under the same name. A zero-byte file is a
    // very cheap price for not having to reason about that.
    contact_lock_release(&lock);
  }

  return result;
}

// Check if contact exists
int has_contact(const char *name)
{
  return find_contact(name) != NULL;
}

// List all contacts
void list_contacts(void)
{
  if (g_keychain.count == 0)
  {
    printf("No contacts in keychain\n");
    return;
  }

  printf("Contacts (%d):\n", g_keychain.count);
  for (int i = 0; i < g_keychain.count; i++)
  {
    printf("  - %s\n", g_keychain.contacts[i].Name);
  }
}

// Show contact details
void show_contact(const char *name)
{
  Contact *c = find_contact(name);
  if (!c)
  {
    fprintf(stderr, "Error: Contact '%s' not found\n", name);
    return;
  }

  printf("\nContact: %s\n", c->Name);
  printf("  EncryptionKey: ******* (%zu bytes)\n", c->EncryptionKeySize);
  printf("  EncryptionKeyOffset: %zu\n", c->EncryptionKeyOffset);
  printf("  EncryptedSequence: %zu\n", c->EncryptedSequence);
  printf("  DecryptionKey: ******* (%zu bytes)\n", c->DecryptionKeySize);
  printf("  DecryptionKeyOffset: %zu\n", c->DecryptionKeyOffset);
  printf("  DecryptedSequence: %zu\n", c->DecryptedSequence);

  printf("  RetryCount: %d\n", c->RetryCount);

  if (c->LastMessageSentAt > 0)
  {
    printf("  LastMessageSentAt: %s", ctime(&c->LastMessageSentAt));
  }
  else
  {
    printf("  LastMessageSentAt: never\n");
  }

  if (c->LastMessageReceivedAt > 0)
  {
    printf("  LastMessageReceivedAt: %s", ctime(&c->LastMessageReceivedAt));
  }
  else
  {
    printf("  LastMessageReceivedAt: never\n");
  }
  printf("\n");
}

