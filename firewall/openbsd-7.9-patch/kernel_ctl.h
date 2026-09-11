#ifndef OTP_FW_KERNEL_CTL_H
#define OTP_FW_KERNEL_CTL_H

#include "config.h"

/* Pushes the config's current resolved candidate IP set to the kernel-
 * resident hook via ioctl(OTP_FW_IOC_SET_CANDIDATES) on /dev/otpfw (see
 * kernel/otpfw.c) - the OpenBSD analog of a /proc write on Linux or
 * ioctl(2) on Windows/FreeBSD. The device being unreachable (kernel
 * built without `pseudo-device otpfw` - see README.md's "Kernel
 * integration") is reported but not fatal, so the daemon can still run
 * against a kernel that doesn't have this hook compiled in yet.
 * Returns 0 on success, -1 otherwise. */
int otp_fw_kernel_push_candidates(const FwConfig *cfg);

#endif /* OTP_FW_KERNEL_CTL_H */
