#ifndef OTP_FW_LOG_H
#define OTP_FW_LOG_H

/* Must be called once, after otp_fw_setup_keychain_dir() (which chdir()s
 * to ~/.otp), before any otp_fw_log_* call. Returns 0 on success. */
int otp_fw_log_init(void);

void otp_fw_log_authorized(const char *direction, const char *contact,
                           const char *src_ip, unsigned src_port,
                           const char *dst_ip, unsigned dst_port, const char *proto);

void otp_fw_log_restricted(const char *direction, const char *contact,
                           const char *src_ip, unsigned src_port,
                           const char *dst_ip, unsigned dst_port,
                           const char *proto, const char *reason);

#endif /* OTP_FW_LOG_H */
