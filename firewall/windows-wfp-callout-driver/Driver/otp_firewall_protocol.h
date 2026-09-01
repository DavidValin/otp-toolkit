/*
 * otp_firewall_protocol.h - the wire format for talking to
 * \\.\OTPFirewall, shared verbatim between the kernel driver and every
 * userspace consumer (Service/, Ctl/). Deliberately dependency-free
 * (just <stdint.h>) so it compiles unchanged in both kernel and
 * userspace translation units - no WDK-only or Win32-only types here.
 *
 * UNVERIFIED, like everything else in this directory - see ../README.md.
 * This specific file is comparatively low-risk (it's just POD structs
 * and IOCTL codes, no API calls), but CTL_CODE() itself needs
 * <winioctl.h> (Win32) or <devioctl.h> (kernel, via wdm.h's own
 * includes) already visible wherever this header is included - not
 * provided here, since which one applies depends on which side is
 * including it.
 */

#ifndef OTP_FW_PROTOCOL_H
#define OTP_FW_PROTOCOL_H

#include <stdint.h>

#define OTP_FW_NT_DEVICE_NAME L"\\Device\\OTPFirewall"
#define OTP_FW_WIN32_SYMLINK_NAME L"\\DosDevices\\OTPFirewall"
#define OTP_FW_WIN32_DEVICE_PATH "\\\\.\\OTPFirewall"

#define OTP_FW_IOCTL_DEVICE_TYPE 0x8000

/* METHOD_BUFFERED throughout: simplest, safest choice for a driver this
 * unverified - the I/O manager copies the whole buffer in and out
 * itself rather than this code having to validate and map user-mode
 * pointers by hand (METHOD_IN_DIRECT/METHOD_OUT_DIRECT), at the cost of
 * an extra copy that doesn't matter at these packet rates. */
#define OTP_FW_IOCTL_SET_ENABLED \
  CTL_CODE(OTP_FW_IOCTL_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define OTP_FW_IOCTL_GET_ENABLED \
  CTL_CODE(OTP_FW_IOCTL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define OTP_FW_IOCTL_SET_CANDIDATES \
  CTL_CODE(OTP_FW_IOCTL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define OTP_FW_IOCTL_DEQUEUE_PACKET \
  CTL_CODE(OTP_FW_IOCTL_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define OTP_FW_IOCTL_SUBMIT_VERDICT \
  CTL_CODE(OTP_FW_IOCTL_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Comfortably covers the largest possible IP packet (65535 bytes for
 * IPv6 payload + a 40-byte fixed header) plus OTP growth headroom, same
 * reasoning as OTP_FW_BRIDGE_BUF_CAP in the macOS port. */
#define OTP_FW_MAX_PACKET 70000

/* Deliberately small and fixed: one contact-name-sized (MAX_NAME_LENGTH,
 * see src/keychain.h) string buffer, since a dequeued packet only needs
 * to travel with enough context for the service to log/decide, not a
 * duplicate of the whole candidate table. */
#define OTP_FW_MAX_CANDIDATE_TEXT (1 << 20) /* matches the other platforms' generous config-push cap */

/* Named otp_fw_pkt_direction_t, not otp_fw_direction_t: firewall/daemon
 * /common.h - included by Service/ alongside this header - already
 * defines its own otp_fw_direction_t (OTP_FW_DIR_EGRESS/INGRESS) for
 * the platform-portable codec API, and the two enums must not collide
 * in a translation unit that includes both. */
typedef enum
{
  OTP_FW_PKT_OUTBOUND = 0,
  OTP_FW_PKT_INBOUND = 1
} otp_fw_pkt_direction_t;

typedef enum
{
  OTP_FW_VERDICT_DROP = 0,
  OTP_FW_VERDICT_FORWARD_ORIGINAL = 1,
  OTP_FW_VERDICT_FORWARD_MODIFIED = 2
} otp_fw_verdict_t;

/* Same reasoning as the Linux module's kvmalloc'd candidate table: a
 * generous static cap on how many contact IPs the service can push in
 * one OTP_FW_IOCTL_SET_CANDIDATES call (firewall.config entries, one
 * per resolved contact address). Lives here, not in
 * otp_firewall_driver.h, because it bounds the wire format itself
 * (both the driver's array and the service's push buffer must agree
 * on it), not just the driver's internal storage. */
#define OTP_FW_WIRE_MAX_CANDIDATES 65536

#pragma pack(push, 1)

/* One candidate (contact) IP, as pushed by OTP_FW_IOCTL_SET_CANDIDATES.
 * Defined here rather than in otp_firewall_driver.h because both the
 * kernel driver AND userspace (Service/kernel_ctl_windows.c) need the
 * identical layout, and userspace cannot include
 * otp_firewall_driver.h - that header pulls in kernel-only WDK headers
 * (ntddk.h, fwpsk.h, fwpmk.h) that don't exist for a usermode build. */
typedef struct
{
  uint8_t is_v6;
  uint8_t addr[16]; /* v4 uses only the first 4 bytes */
} otp_fw_candidate_t;

/* Result of OTP_FW_IOCTL_DEQUEUE_PACKET: one candidate packet the driver
 * is holding (classification pended - see otp_firewall_driver.c),
 * waiting for a verdict. A dequeue call blocks (the driver pends the
 * IRP) until either a packet is available or otp_fw_service_shutdown()
 * cancels all pended IRPs on service exit. */
typedef struct
{
  uint64_t packet_id; /* opaque handle the service must echo back verbatim in its verdict */
  uint32_t direction;  /* otp_fw_pkt_direction_t */
  uint32_t data_len;
  uint8_t data[OTP_FW_MAX_PACKET];
} otp_fw_dequeued_packet_t;

/* Input to OTP_FW_IOCTL_SUBMIT_VERDICT. */
typedef struct
{
  uint64_t packet_id;
  uint32_t verdict;   /* otp_fw_verdict_t */
  uint32_t data_len;  /* only meaningful for FORWARD_MODIFIED */
  uint8_t data[OTP_FW_MAX_PACKET];
} otp_fw_verdict_submission_t;

#pragma pack(pop)

#endif /* OTP_FW_PROTOCOL_H */
