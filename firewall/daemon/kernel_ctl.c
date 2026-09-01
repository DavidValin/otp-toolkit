#include "kernel_ctl.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_proc_file(const char *path, const char *data, size_t len)
{
  int fd = open(path, O_WRONLY);
  if (fd < 0)
  {
    if (errno == ENOENT)
      fprintf(stderr, "Warning: '%s' does not exist - is otp_firewall.ko loaded?\n", path);
    else
      fprintf(stderr, "Warning: cannot open '%s': %s\n", path, strerror(errno));
    return -1;
  }
  /* A zero-length candidate set (the last contact just got removed from
   * firewall.config) must still reach the kernel as an explicit "replace
   * the table with nothing" write, not be skipped as a no-op - otherwise
   * there is no way to ever clear a previously-pushed candidate table
   * back to empty, and the kernel keeps queuing packets for IPs that are
   * no longer configured anywhere. A single write() with len==0 is a
   * well-defined, valid call (returns 0, not an error) and still reaches
   * the kernel's candidates_write() handler. */
  size_t off = 0;
  do
  {
    ssize_t n = write(fd, data + off, len - off);
    if (n < 0)
    {
      fprintf(stderr, "Warning: write to '%s' failed: %s\n", path, strerror(errno));
      close(fd);
      return -1;
    }
    off += (size_t)n;
  } while (off < len);
  close(fd);
  return 0;
}

int otp_fw_kernel_push_candidates(const FwConfig *cfg)
{
  /* Sized to the actual config rather than a fixed guess: a fixed 64KB
   * buffer holds only a few thousand resolved IPs at most, well under
   * OTP_FW_MAX_CONFIG_ENTRIES - and on overflow this pushed nothing at
   * all, leaving the kernel's candidate table stale (every contact
   * dropped, not just the ones past the limit) rather than failing only
   * the entries that didn't fit. */
  size_t cap = (size_t)cfg->count * (OTP_FW_IPSTR_LEN + 1) + 1;
  if (cap < 4096)
    cap = 4096;
  char *buf = malloc(cap);
  if (!buf)
  {
    fprintf(stderr, "Error: out of memory building the candidate IP list\n");
    return -1;
  }
  int n = fwconfig_candidate_ips(cfg, buf, cap);
  if (n < 0)
  {
    fprintf(stderr, "Error: candidate IP set too large for the kernel control buffer\n");
    free(buf);
    return -1;
  }
  int rc = write_proc_file(OTP_FW_PROC_CANDIDATES, buf, (size_t)n);
  free(buf);
  return rc;
}
