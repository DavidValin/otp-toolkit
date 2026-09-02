#ifndef OTP_FW_KERNEL_CTL_H
#define OTP_FW_KERNEL_CTL_H

#include "config.h"

/* Pushes the config's current resolved candidate IP set to the kernel
 * module - the mechanism is platform-specific (see this directory's own
 * kernel_ctl.c: a /proc write on Linux, ioctl(2) on Windows/FreeBSD).
 * The kernel module being unreachable (not loaded) is reported but not
 * fatal, so the daemon can still run against a not-yet-loaded module.
 * Returns 0 on success, -1 otherwise. */
int otp_fw_kernel_push_candidates(const FwConfig *cfg);

#endif /* OTP_FW_KERNEL_CTL_H */
