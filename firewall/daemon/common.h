#ifndef OTP_FW_COMMON_H
#define OTP_FW_COMMON_H

#define OTP_FW_HOME_SUBDIR ".otp"
#define OTP_FW_KEYCHAIN_DIRNAME "firewall_keychain"
#define OTP_FW_KEYCHAIN_LINK ".keychain"
#define OTP_FW_CONFIG_NAME "firewall.config"
#define OTP_FW_AUTH_LOG_NAME "authorized.log"
#define OTP_FW_RESTRICT_LOG_NAME "restricted.log"

#define OTP_FW_PROC_ENABLED "/proc/otp_firewall/enabled"
#define OTP_FW_PROC_CANDIDATES "/proc/otp_firewall/candidates"

#define OTP_FW_MAX_CONFIG_ENTRIES 40000
#define OTP_FW_MAX_PINS 4096
#define OTP_FW_MAX_CANDIDATES 10001 /* one per keychain contact, +1 headroom */
#define OTP_FW_IPSTR_LEN 46        /* fits "::ffff:255.255.255.255\0" */
#define OTP_FW_HOST_LEN 256

typedef enum
{
  OTP_FW_MODE_ENFORCE = 0,
  OTP_FW_MODE_LOGONLY = 1
} otp_fw_mode_t;

typedef enum
{
  OTP_FW_DIR_EGRESS = 0,
  OTP_FW_DIR_INGRESS = 1
} otp_fw_direction_t;

typedef enum
{
  OTP_FW_OK = 0,
  OTP_FW_NO_CONTACT,
  OTP_FW_AUTH_FAIL,
  OTP_FW_PIN_MISMATCH,
  OTP_FW_KEY_EXHAUSTED,
  OTP_FW_PENDING_RECOVERY,
  OTP_FW_PARSE_ERROR,
  OTP_FW_NOT_EVALUATED,
  OTP_FW_INTERNAL_ERROR
} otp_fw_result_t;

static inline const char *otp_fw_result_reason(otp_fw_result_t r)
{
  switch (r)
  {
  case OTP_FW_OK:
    return "validated";
  case OTP_FW_NO_CONTACT:
    return "no-matching-contact";
  case OTP_FW_AUTH_FAIL:
    return "meta-mismatch";
  case OTP_FW_PIN_MISMATCH:
    return "pin-mismatch";
  case OTP_FW_KEY_EXHAUSTED:
    return "key-exhausted";
  case OTP_FW_PENDING_RECOVERY:
    return "pending-recovery";
  case OTP_FW_PARSE_ERROR:
    return "parse-error";
  case OTP_FW_NOT_EVALUATED:
    return "not-evaluated-log-only";
  default:
    return "internal-error";
  }
}

#endif /* OTP_FW_COMMON_H */
