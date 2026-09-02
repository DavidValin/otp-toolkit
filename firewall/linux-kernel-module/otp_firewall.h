#ifndef OTP_FIREWALL_H
#define OTP_FIREWALL_H

#define OTP_FW_PROC_DIR "otp_firewall"
#define OTP_FW_PROC_ENABLED_NAME "enabled"
#define OTP_FW_PROC_CANDIDATES_NAME "candidates"

#define OTP_FW_MAX_CANDIDATES 10001 /* mirrors MAX_CONTACTS in src/keychain.h, +1 headroom */

/* Must match common.h's OTP_FW_ACK_PORT exactly - the daemon's
 * delivery-acknowledgment side channel (see ack.h) needs this traffic
 * exempted from the encrypt/decrypt pipeline here in the kernel, the
 * same way ICMPv6 is, since neither this header nor the userspace one
 * can include the other (kernel vs. userspace build). */
#define OTP_FW_ACK_PORT 34443

#endif /* OTP_FIREWALL_H */
