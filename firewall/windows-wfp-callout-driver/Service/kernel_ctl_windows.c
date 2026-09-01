/*
 * kernel_ctl_windows.c - Windows port of firewall/daemon/kernel_ctl.c.
 * Declares the exact same public API as kernel_ctl.h (reused unmodified
 * from firewall/daemon/, same drop-in-replacement pattern as
 * packet_codec_windows.c), but pushes the candidate IP set to
 * \\.\OTPFirewall via DeviceIoControl(OTP_FW_IOCTL_SET_CANDIDATES)
 * instead of writing text to /proc/otp_firewall/candidates.
 *
 * UNVERIFIED - see ../README.md.
 */

#include "kernel_ctl.h"
#include "common.h"

#include "../Driver/otp_toolkit_firewall.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string.h>

/* fwconfig_candidate_ips() returns a newline-delimited, already-deduped
 * list of resolved IPs (see config.c) - reused as-is rather than
 * re-deriving candidate extraction from FwConfig here, same as every
 * other platform's kernel_ctl port. */
int otp_fw_kernel_push_candidates(const FwConfig *cfg)
{
  static char ip_list[OTP_FW_MAX_CANDIDATE_TEXT];
  if (fwconfig_candidate_ips(cfg, ip_list, sizeof(ip_list)) < 0)
  {
    fprintf(stderr, "Error: candidate IP list too large for the push buffer, not pushing\n");
    return -1;
  }

  static otp_fw_candidate_t candidates[OTP_FW_WIRE_MAX_CANDIDATES];
  ULONG count = 0;

  char *save = NULL;
  char *line = strtok_s(ip_list, "\n", &save);
  while (line && count < OTP_FW_WIRE_MAX_CANDIDATES)
  {
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, line, &v4) == 1)
    {
      candidates[count].is_v6 = 0;
      memset(candidates[count].addr, 0, sizeof(candidates[count].addr));
      memcpy(candidates[count].addr, &v4, 4);
      count++;
    }
    else if (inet_pton(AF_INET6, line, &v6) == 1)
    {
      candidates[count].is_v6 = 1;
      memcpy(candidates[count].addr, &v6, 16);
      count++;
    }
    else
    {
      fprintf(stderr, "Warning: kernel_ctl_windows: could not parse candidate IP '%s', skipping\n", line);
    }
    line = strtok_s(NULL, "\n", &save);
  }
  if (line)
    fprintf(stderr, "Warning: candidate list exceeds %d entries, the rest were not pushed\n", OTP_FW_WIRE_MAX_CANDIDATES);

  HANDLE dev = CreateFileA(OTP_FW_WIN32_DEVICE_PATH, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (dev == INVALID_HANDLE_VALUE)
  {
    /* Missing (driver not loaded/started) is reported but not fatal,
     * same "still useful for a driver-less test setup" reasoning
     * kernel_ctl.h documents for the Linux /proc case - though on
     * Windows there is no nft-rules fallback, so this mainly matters
     * for iterating on the service's own logic before the driver is
     * ready. */
    fprintf(stderr, "Warning: cannot open %s (driver not loaded?), not pushing candidates\n",
           OTP_FW_WIN32_DEVICE_PATH);
    return -1;
  }

  DWORD bytes_out = 0;
  BOOL ok = DeviceIoControl(dev, OTP_FW_IOCTL_SET_CANDIDATES,
                            candidates, count * (DWORD)sizeof(otp_fw_candidate_t),
                            NULL, 0, &bytes_out, NULL);
  CloseHandle(dev);
  if (!ok)
  {
    fprintf(stderr, "Error: DeviceIoControl(SET_CANDIDATES) failed: %lu\n", GetLastError());
    return -1;
  }
  return 0;
}
