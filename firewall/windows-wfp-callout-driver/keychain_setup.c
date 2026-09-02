#include "keychain_setup.h"
#include "common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Windows has no unprivileged POSIX-style symlink() the way this file's
 * ".keychain -> firewall_keychain" trick needs on POSIX: creating a
 * symbolic link requires either Administrator rights or Windows 10's
 * "Developer Mode" enabled (Settings > Privacy & Security > For
 * developers) - CreateSymbolicLinkA()'s
 * SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE flag is what lets it
 * succeed under Developer Mode without elevation; without either, it
 * fails with ERROR_PRIVILEGE_NOT_HELD, surfaced below as an actionable
 * error rather than a bare Win32 error code. This whole block - the
 * only Windows-specific logic in this file beyond the mkdir/chdir
 * signature differences - could not be tested against a real Windows
 * system; see ../windows-wfp-callout-driver/README.md for the same
 * caveat that applies to the rest of that directory. */
#ifdef _WIN32
#include <direct.h> /* _mkdir, _chdir */
#include <windows.h>

static int otp_fw_mkdir(const char *path) { return _mkdir(path); }
#define otp_fw_chdir _chdir

static const char *resolve_home(void)
{
  const char *home = getenv("HOME");
  if (home && home[0] != '\0')
    return home;
  /* Windows has no $HOME by default (some shells/MSYS2 set it, but it's
   * not guaranteed) - USERPROFILE is the native equivalent. */
  home = getenv("USERPROFILE");
  if (home && home[0] != '\0')
    return home;
  return NULL;
}

/* Returns 1 if `path` exists and is a reparse point (symlink/junction),
 * 0 if it exists but isn't, -1 if it doesn't exist, -2 on any other
 * stat failure. */
static int otp_fw_reparse_point_status(const char *path)
{
  DWORD attrs = GetFileAttributesA(path);
  if (attrs == INVALID_FILE_ATTRIBUTES)
  {
    DWORD err = GetLastError();
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
      return -1;
    return -2;
  }
  return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;
}

/* Resolves `path` to its final, fully-qualified target path (CreateFileA
 * follows reparse points by default) by asking Windows for the path it
 * resolved to, rather than manually parsing a REPARSE_DATA_BUFFER.
 *
 * Deliberately returns the FULL resolved path, not just its basename:
 * OTP_FW_KEYCHAIN_DIRNAME ("firewall_keychain") is a public, non-secret
 * constant, so comparing only the last path component would let an
 * unprivileged local process pre-create the link as a directory
 * junction (no elevation required, unlike a symlink) pointing at ANY
 * directory on disk that happens to be named "firewall_keychain" -
 * silently redirecting every keychain read/write there. Comparing the
 * full resolved path against the real keychain directory's own
 * resolved path (see the call site) closes that gap the same way the
 * POSIX branch's exact readlink() text comparison already does. */
static int otp_fw_resolve_full_path(const char *path, char *out, size_t out_size)
{
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return -1;
  DWORD n = GetFinalPathNameByHandleA(h, out, (DWORD)out_size, FILE_NAME_NORMALIZED);
  CloseHandle(h);
  if (n == 0 || n >= out_size)
    return -1;
  return 0;
}

static int otp_fw_create_dir_symlink(const char *link_path, const char *target_name)
{
  if (CreateSymbolicLinkA(link_path, target_name,
                         SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
    return 0;
  if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD)
    fprintf(stderr,
           "Error: creating '%s' needs either Administrator rights or Windows 10's "
           "Developer Mode enabled (Settings > Privacy & Security > For developers).\n",
           link_path);
  return -1;
}
#else
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

static int otp_fw_mkdir(const char *path) { return mkdir(path, 0700); }
#define otp_fw_chdir chdir

static const char *resolve_home(void)
{
  const char *home = getenv("HOME");
  if (home && home[0] != '\0')
    return home;
  struct passwd *pw = getpwuid(getuid());
  if (pw && pw->pw_dir && pw->pw_dir[0] != '\0')
    return pw->pw_dir;
  return NULL;
}
#endif

int otp_fw_home_dir(char *out, size_t out_size)
{
  const char *home = resolve_home();
  if (!home)
  {
    fprintf(stderr, "Error: cannot resolve the invoking user's home directory (no $HOME, no passwd entry)\n");
    return -1;
  }
  if (snprintf(out, out_size, "%s/%s", home, OTP_FW_HOME_SUBDIR) >= (int)out_size)
  {
    fprintf(stderr, "Error: home directory path too long\n");
    return -1;
  }
  if (otp_fw_mkdir(out) != 0 && errno != EEXIST)
  {
    fprintf(stderr, "Error: cannot create '%s': %s\n", out, strerror(errno));
    return -1;
  }
  return 0;
}

int otp_fw_setup_keychain_dir(void)
{
  char home_dir[512];
  if (otp_fw_home_dir(home_dir, sizeof(home_dir)) != 0)
    return -1;

  char keychain_real[600];
  if (snprintf(keychain_real, sizeof(keychain_real), "%s/%s", home_dir, OTP_FW_KEYCHAIN_DIRNAME) >= (int)sizeof(keychain_real))
  {
    fprintf(stderr, "Error: keychain path too long\n");
    return -1;
  }
  if (otp_fw_mkdir(keychain_real) != 0 && errno != EEXIST)
  {
    fprintf(stderr, "Error: cannot create '%s': %s\n", keychain_real, strerror(errno));
    return -1;
  }

  char link_path[600];
  if (snprintf(link_path, sizeof(link_path), "%s/%s", home_dir, OTP_FW_KEYCHAIN_LINK) >= (int)sizeof(link_path))
  {
    fprintf(stderr, "Error: keychain link path too long\n");
    return -1;
  }

#ifdef _WIN32
  int status = otp_fw_reparse_point_status(link_path);
  if (status == -2)
  {
    fprintf(stderr, "Error: cannot stat '%s'\n", link_path);
    return -1;
  }
  if (status == 0)
  {
    fprintf(stderr,
           "Error: '%s' already exists and is not the firewall's keychain link; "
           "refusing to touch it. Move it aside or remove it if it is safe to do so.\n",
           link_path);
    return -1;
  }
  if (status == 1)
  {
    char target_resolved[1024], expected_resolved[1024];
    if (otp_fw_resolve_full_path(link_path, target_resolved, sizeof(target_resolved)) != 0)
    {
      fprintf(stderr, "Error: cannot read link '%s'\n", link_path);
      return -1;
    }
    /* Resolve the real keychain directory (created/confirmed to exist
     * just above) the same way, and compare full paths rather than just
     * the trailing component - see otp_fw_resolve_full_path()'s comment
     * for why a basename-only check would be spoofable. */
    if (otp_fw_resolve_full_path(keychain_real, expected_resolved, sizeof(expected_resolved)) != 0)
    {
      fprintf(stderr, "Error: cannot resolve '%s'\n", keychain_real);
      return -1;
    }
    if (_stricmp(target_resolved, expected_resolved) != 0)
    {
      fprintf(stderr,
             "Error: '%s' links to '%s', not '%s'; refusing to touch it.\n",
             link_path, target_resolved, expected_resolved);
      return -1;
    }
  }
  else /* status == -1: doesn't exist yet */
  {
    if (otp_fw_create_dir_symlink(link_path, OTP_FW_KEYCHAIN_DIRNAME) != 0)
    {
      fprintf(stderr, "Error: cannot create link '%s' -> '%s'\n", link_path, OTP_FW_KEYCHAIN_DIRNAME);
      return -1;
    }
  }
#else
  struct stat st;
  if (lstat(link_path, &st) == 0)
  {
    if (!S_ISLNK(st.st_mode))
    {
      fprintf(stderr,
              "Error: '%s' already exists and is not the firewall's keychain symlink; "
              "refusing to touch it. Move it aside or remove it if it is safe to do so.\n",
              link_path);
      return -1;
    }
    char target[600];
    ssize_t n = readlink(link_path, target, sizeof(target) - 1);
    if (n < 0)
    {
      fprintf(stderr, "Error: cannot read symlink '%s': %s\n", link_path, strerror(errno));
      return -1;
    }
    target[n] = '\0';
    if (strcmp(target, OTP_FW_KEYCHAIN_DIRNAME) != 0)
    {
      fprintf(stderr,
              "Error: '%s' is a symlink to '%s', not '%s'; refusing to touch it.\n",
              link_path, target, OTP_FW_KEYCHAIN_DIRNAME);
      return -1;
    }
  }
  else if (errno == ENOENT)
  {
    if (symlink(OTP_FW_KEYCHAIN_DIRNAME, link_path) != 0)
    {
      fprintf(stderr, "Error: cannot create symlink '%s' -> '%s': %s\n",
              link_path, OTP_FW_KEYCHAIN_DIRNAME, strerror(errno));
      return -1;
    }
  }
  else
  {
    fprintf(stderr, "Error: cannot stat '%s': %s\n", link_path, strerror(errno));
    return -1;
  }
#endif

  if (otp_fw_chdir(home_dir) != 0)
  {
    fprintf(stderr, "Error: cannot chdir to '%s': %s\n", home_dir, strerror(errno));
    return -1;
  }
  return 0;
}
