/*
 * otpfwctl.c - Windows equivalent of the Linux kill switch's
 * `echo 0/1 > /proc/otp_firewall/enabled` / `cat /proc/otp_firewall/enabled`.
 * Talks to \\.\OTPFirewall directly; does not touch the service.
 *
 * Usage: otpfwctl.exe {enable|disable|status}
 *
 * UNVERIFIED - see ../README.md.
 */

#include "../Driver/otp_toolkit_firewall.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

static HANDLE open_device(void)
{
  HANDLE dev = CreateFileA(OTP_FW_WIN32_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (dev == INVALID_HANDLE_VALUE)
  {
    fprintf(stderr, "Error: cannot open %s (driver not loaded/started - see ../README.md): %lu\n",
           OTP_FW_WIN32_DEVICE_PATH, GetLastError());
  }
  return dev;
}

static int set_enabled(int enabled)
{
  HANDLE dev = open_device();
  if (dev == INVALID_HANDLE_VALUE)
    return 1;

  UINT32 v = enabled ? 1 : 0;
  DWORD bytes = 0;
  BOOL ok = DeviceIoControl(dev, OTP_FW_IOCTL_SET_ENABLED, &v, sizeof(v), NULL, 0, &bytes, NULL);
  CloseHandle(dev);
  if (!ok)
  {
    fprintf(stderr, "Error: DeviceIoControl(SET_ENABLED) failed: %lu\n", GetLastError());
    return 1;
  }
  printf("otp-toolkit firewall: %s\n", enabled ? "enabled (enforcing)" : "disabled (fail-open passthrough)");
  return 0;
}

static int get_status(void)
{
  HANDLE dev = open_device();
  if (dev == INVALID_HANDLE_VALUE)
    return 1;

  UINT32 v = 0;
  DWORD bytes = 0;
  BOOL ok = DeviceIoControl(dev, OTP_FW_IOCTL_GET_ENABLED, NULL, 0, &v, sizeof(v), &bytes, NULL);
  CloseHandle(dev);
  if (!ok || bytes < sizeof(v))
  {
    fprintf(stderr, "Error: DeviceIoControl(GET_ENABLED) failed: %lu\n", GetLastError());
    return 1;
  }
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
