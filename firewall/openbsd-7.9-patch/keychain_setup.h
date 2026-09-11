#ifndef OTP_FW_KEYCHAIN_SETUP_H
#define OTP_FW_KEYCHAIN_SETUP_H

#include <stddef.h>

/* Fills `out` with the firewall's home directory (~/.otp), creating it
 * (mode 0700) if missing. Returns 0 on success, -1 on error (message
 * already printed to stderr). */
int otp_fw_home_dir(char *out, size_t out_size);

/* Ensures ~/.otp/firewall_keychain exists, ensures ~/.otp/.keychain is a
 * symlink to it (refusing to touch anything already there that isn't
 * exactly that symlink), then chdir()s into ~/.otp so every keychain.c/
 * cipher.c call (which always resolves ".keychain" relative to CWD, see
 * src/keychain.c:66-75) transparently operates on firewall_keychain.
 * Returns 0 on success, -1 on error (message already printed to stderr). */
int otp_fw_setup_keychain_dir(void);

#endif /* OTP_FW_KEYCHAIN_SETUP_H */
