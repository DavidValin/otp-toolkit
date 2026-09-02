/*
 * otpfwctl.c - kill switch control utility, talking to
 * /dev/otp_firewall directly via ioctl(); does not touch the daemon.
 * Equivalent to `sysctl net.otp_firewall.enabled=0/1` (see
 * otp_firewall.c's sysctl_otp_fw_enabled()) - both reach the exact same
 * kernel variable, this is just the scriptable/status-checking form.
 *
 * Usage: otpfwctl {enable|disable|status}
 *
 * UNVERIFIED - see README.md.
 */

#include "otp_firewall_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int open_device(void)
{
  int fd = open(OTP_FW_DEVICE_PATH, O_RDWR);
  if (fd < 0)
    fprintf(stderr, "Error: cannot open %s (kernel module not loaded - see README.md): %s\n",
           OTP_FW_DEVICE_PATH, strerror(errno));
  return fd;
}

static int set_enabled(int enabled)
{
  int fd = open_device();
  if (fd < 0)
    return 1;

  uint32_t v = enabled ? 1 : 0;
  if (ioctl(fd, OTP_FW_IOC_SET_ENABLED, &v) < 0)
  {
    fprintf(stderr, "Error: ioctl(SET_ENABLED) failed: %s\n", strerror(errno));
    close(fd);
    return 1;
  }
  close(fd);
  printf("otp-toolkit firewall: %s\n", enabled ? "enabled (enforcing)" : "disabled (fail-open passthrough)");
  return 0;
}

static int get_status(void)
{
  int fd = open_device();
  if (fd < 0)
    return 1;

  uint32_t v = 0;
  if (ioctl(fd, OTP_FW_IOC_GET_ENABLED, &v) < 0)
  {
    fprintf(stderr, "Error: ioctl(GET_ENABLED) failed: %s\n", strerror(errno));
    close(fd);
    return 1;
  }
  close(fd);
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
