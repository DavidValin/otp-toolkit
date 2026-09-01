/*
 * kernel_ctl_freebsd.c - FreeBSD port of firewall/daemon/kernel_ctl.c.
 * Declares the exact same public API as kernel_ctl.h (reused unmodified
 * from firewall/daemon/, same drop-in-replacement pattern as
 * packet_codec_freebsd.c), but pushes the candidate IP set to
 * /dev/otp_firewall via OTP_FW_IOC_SET_CANDIDATES instead of writing
 * text to a /proc file.
 *
 * UNVERIFIED - see ../README.md.
 */

#include "kernel_ctl.h"
#include "common.h"

#include "otp_firewall_proto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* fwconfig_candidate_ips() returns a newline-delimited, already-deduped
 * list of resolved IPs (see config.c) - reused as-is, same as every
 * other platform's kernel_ctl port. */
int otp_fw_kernel_push_candidates(const FwConfig *cfg)
{
  static char ip_list[1 << 20]; /* generous, matches the other platforms' candidate-push buffer cap */
  if (fwconfig_candidate_ips(cfg, ip_list, sizeof(ip_list)) < 0)
  {
    fprintf(stderr, "Error: candidate IP list too large for the push buffer, not pushing\n");
    return -1;
  }

  static otp_fw_candidate_t candidates[OTP_FW_MAX_CANDIDATES];
  uint32_t count = 0;

  char *save = NULL;
  char *line = strtok_r(ip_list, "\n", &save);
  while (line && count < OTP_FW_MAX_CANDIDATES)
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
      fprintf(stderr, "Warning: kernel_ctl_freebsd: could not parse candidate IP '%s', skipping\n", line);
    }
    line = strtok_r(NULL, "\n", &save);
  }
  if (line)
    fprintf(stderr, "Warning: candidate list exceeds %d entries, the rest were not pushed\n", OTP_FW_MAX_CANDIDATES);

  int fd = open(OTP_FW_DEVICE_PATH, O_RDWR);
  if (fd < 0)
  {
    /* Missing (module not loaded) is reported but not fatal - matters
     * mainly for iterating on the daemon's own logic before the module
     * is loaded, same reasoning as the Linux/Windows ports. */
    fprintf(stderr, "Warning: cannot open %s (kernel module not loaded?): %s\n",
           OTP_FW_DEVICE_PATH, strerror(errno));
    return -1;
  }

  otp_fw_set_candidates_t req;
  req.count = count;
  req.candidates = candidates;
  int rc = ioctl(fd, OTP_FW_IOC_SET_CANDIDATES, &req);
  close(fd);
  if (rc < 0)
  {
    fprintf(stderr, "Error: ioctl(OTP_FW_IOC_SET_CANDIDATES) failed: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}
