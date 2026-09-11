#ifndef OTP_FW_KERNEL_CTL_H
#define OTP_FW_KERNEL_CTL_H

#include "config.h"

/* Pushes the config's current resolved candidate IP set to the kernel
 * module's /proc/otp_firewall/candidates. Missing (module not loaded)
 * is reported but not fatal, so the daemon can still run in a
 * kernel-module-less test setup driving NFQUEUE via nft rules directly.
 * Returns 0 on success, -1 otherwise. */
int otp_fw_kernel_push_candidates(const FwConfig *cfg);

#endif /* OTP_FW_KERNEL_CTL_H */
