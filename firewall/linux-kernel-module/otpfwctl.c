/*
 * otpfwctl.c - kill switch control utility, talking to
 * /proc/otp_firewall/enabled directly; does not touch the daemon.
 * Equivalent to `echo 1/0 | sudo tee /proc/otp_firewall/enabled` (see
 * otp_firewall.c's enabled_read()/enabled_write()) - both reach the
 * exact same kernel state, this is just the scriptable/status-checking
 * form, matching the otpfwctl that each other platform ships.
 *
 * Usage: otpfwctl {enable|disable|status}
 */

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int open_enabled(int flags)
{
  int fd = open(OTP_FW_PROC_ENABLED, flags);
  if (fd < 0)
    fprintf(stderr, "Error: cannot open %s (kernel module not loaded - see README.md): %s\n",
           OTP_FW_PROC_ENABLED, strerror(errno));
  return fd;
}

static int set_enabled(int enabled)
{
  int fd = open_enabled(O_WRONLY);
  if (fd < 0)
    return 1;

  const char *data = enabled ? "1" : "0";
  if (write(fd, data, 1) != 1)
  {
    fprintf(stderr, "Error: write to %s failed: %s\n", OTP_FW_PROC_ENABLED, strerror(errno));
    close(fd);
    return 1;
  }
  close(fd);
  printf("otp-toolkit firewall: %s\n", enabled ? "enabled (enforcing)" : "disabled (fail-open passthrough)");
  return 0;
}

static int get_status(void)
{
  int fd = open_enabled(O_RDONLY);
  if (fd < 0)
    return 1;

  char buf[8] = {0};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n < 0)
  {
    fprintf(stderr, "Error: read from %s failed: %s\n", OTP_FW_PROC_ENABLED, strerror(errno));
    return 1;
  }
  int v = (buf[0] == '1');
  printf("otp-toolkit firewall: %s\n", v ? "enabled (enforcing)" : "disabled (fail-open passthrough)");
  return 0;
}

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s {enable|disable|status}\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "enable") == 0)
    return set_enabled(1);
  if (strcmp(argv[1], "disable") == 0)
    return set_enabled(0);
  if (strcmp(argv[1], "status") == 0)
    return get_status();

  fprintf(stderr, "Usage: %s {enable|disable|status}\n", argv[0]);
  return 2;
}
