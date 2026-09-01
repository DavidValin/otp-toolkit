#include "keychain_setup.h"
#include "common.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
  if (mkdir(out, 0700) != 0 && errno != EEXIST)
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
  if (mkdir(keychain_real, 0700) != 0 && errno != EEXIST)
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

  if (chdir(home_dir) != 0)
  {
    fprintf(stderr, "Error: cannot chdir to '%s': %s\n", home_dir, strerror(errno));
    return -1;
  }
  return 0;
}
