#include "log.h"
#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* otp_fw_setup_keychain_dir() has already chdir()'d to ~/.otp by the
 * time this runs, so these are deliberately relative paths. */
static const char *AUTH_LOG = OTP_FW_AUTH_LOG_NAME;
static const char *RESTRICT_LOG = OTP_FW_RESTRICT_LOG_NAME;

int otp_fw_log_init(void)
{
  int fd = open(AUTH_LOG, O_CREAT | O_WRONLY | O_APPEND, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot open '%s': %s\n", AUTH_LOG, strerror(errno));
    return -1;
  }
  close(fd);
  fd = open(RESTRICT_LOG, O_CREAT | O_WRONLY | O_APPEND, 0600);
  if (fd < 0)
  {
    fprintf(stderr, "Error: cannot open '%s': %s\n", RESTRICT_LOG, strerror(errno));
    return -1;
  }
  close(fd);
  return 0;
}

static void append_line(const char *path, const char *direction, const char *contact,
                        const char *src_ip, unsigned src_port, const char *dst_ip,
                        unsigned dst_port, const char *proto, const char *reason)
{
  time_t now = time(NULL);
  struct tm tm_utc;
  gmtime_r(&now, &tm_utc);
  char ts[32];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

  char line[512];
  int n = snprintf(line, sizeof(line), "%s %s %s %s:%u %s:%u %s %s\n",
                   ts, direction, (contact && contact[0]) ? contact : "-",
                   src_ip, src_port, dst_ip, dst_port, proto, reason);
  if (n <= 0)
    return;
  size_t len = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;

  int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0600);
  if (fd < 0)
    return;
  ssize_t written = write(fd, line, len);
  (void)written;
  close(fd);
}

void otp_fw_log_authorized(const char *direction, const char *contact,
                           const char *src_ip, unsigned src_port,
                           const char *dst_ip, unsigned dst_port, const char *proto)
{
  append_line(AUTH_LOG, direction, contact, src_ip, src_port, dst_ip, dst_port, proto, "validated");
}

void otp_fw_log_restricted(const char *direction, const char *contact,
                           const char *src_ip, unsigned src_port,
                           const char *dst_ip, unsigned dst_port,
                           const char *proto, const char *reason)
{
  append_line(RESTRICT_LOG, direction, contact, src_ip, src_port, dst_ip, dst_port, proto, reason);
}
