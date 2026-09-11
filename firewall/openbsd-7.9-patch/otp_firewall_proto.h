/*
 * otp_firewall_proto.h - the wire format for talking to /dev/otpfw,
 * shared verbatim between the kernel-side code (kernel/otpfw.c - see
 * README.md's "Kernel integration") and userspace (otp_firewalld.c,
 * kernel_ctl.c, otpfwctl.c). Same reasoning as the FreeBSD port's copy
 * of this file: OpenBSD's kernel and userspace C environments both
 * understand plain <sys/types.h> fixed-width integers fine, so one
 * header works for both sides without a special dependency-free split
 * the way Windows needs - the only wrinkle is that kernel code pulls in
 * <sys/ioctl.h>'s _IOWR()-family macros via <sys/ioccom.h> (already
 * present through <sys/param.h> in a kernel build) while userspace
 * includes <sys/ioctl.h> directly; both define the same macros, so no
 * #ifdef is needed in this file itself.
 *
 * UNVERIFIED - see README.md's Status section. Comparatively low-risk
 * (POD structs and ioctl codes only), same reasoning as the FreeBSD/
 * Windows ports' own copies of this kind of header.
 */

#ifndef OTP_FIREWALL_PROTO_H
#define OTP_FIREWALL_PROTO_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/ioccom.h>

#define OTP_FW_DEVICE_NAME "otpfw"
#define OTP_FW_DEVICE_PATH "/dev/otpfw"

/* Must match common.h's OTP_FW_ACK_PORT exactly - the daemon's
 * delivery-acknowledgment side channel (see ack.h) needs this traffic
 * exempted from the encrypt/decrypt pipeline here in the kernel, the
 * same way ICMPv6 is, since neither this header nor common.h can
 * include the other cleanly across the kernel/userspace build boundary
 * - same reasoning as every other platform's own copy of this constant. */
#define OTP_FW_ACK_PORT 34443

/* Comfortably covers the largest possible IP packet (65535 bytes for
 * IPv6 payload + a 40-byte fixed header) plus OTP growth headroom, same
 * reasoning as OTP_FW_MAX_PACKET on every other platform. */
#define OTP_FW_MAX_PACKET 70000

/* Generous static cap on how many contact IPs the daemon can push in one
 * OTP_FW_IOC_SET_CANDIDATES call, same reasoning as
 * OTP_FW_WIRE_MAX_CANDIDATES on Linux/Windows/FreeBSD. */
#define OTP_FW_WIRE_MAX_CANDIDATES 65536

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

/* One candidate (contact) IP, as pushed by OTP_FW_IOC_SET_CANDIDATES. */
typedef struct
{
  uint8_t is_v6;
  uint8_t addr[16]; /* v4 uses only the first 4 bytes */
} otp_fw_candidate_t;

/* read()'s output: one candidate packet the kernel is holding (the
 * otpfw_hook_in()/otpfw_hook_out() call site in ip_input.c/ip_output.c/
 * ip6_input.c/ip6_output.c consumed the mbuf and parked it - see
 * kernel/otpfw.c), waiting for a verdict. A read() on /dev/otpfw blocks
 * until either a packet is queued or the device is closed. Exactly one
 * packet per read() call, same "one message per call" contract every
 * other platform's kernel<->daemon queue has. */
typedef struct
{
  uint64_t packet_id; /* opaque handle the daemon must echo back verbatim in its verdict */
  uint32_t direction;  /* otp_fw_pkt_direction_t */
  uint32_t data_len;
  uint8_t data[OTP_FW_MAX_PACKET];
} otp_fw_dequeued_packet_t;

/* write()'s input: a verdict for one previously-dequeued packet. */
typedef struct
{
  uint64_t packet_id;
  uint32_t verdict;   /* otp_fw_verdict_t */
  uint32_t data_len;  /* only meaningful for FORWARD_MODIFIED */
  uint8_t data[OTP_FW_MAX_PACKET];
} otp_fw_verdict_submission_t;

/* SET_CANDIDATES' ioctl argument: a pointer + count rather than the
 * candidate array embedded directly in the ioctl struct, same BSD
 * variable-length-ioctl-data pattern as the FreeBSD port's identical
 * struct (and `struct ifconf`'s ifc_buf/ifc_len). */
typedef struct
{
  uint32_t count;
  const otp_fw_candidate_t *candidates;
} otp_fw_set_candidates_t;

/* Control operations, kept off the read()/write() packet-verdict path
 * and issued via ioctl() instead - same split bpf(4)'s /dev/bpf uses
 * between configuration (ioctl) and the packet stream itself
 * (read/write); kernel/otpfw.c is deliberately modeled on bpf.c's
 * character-device shape throughout, since bpf is the closest existing
 * in-tree precedent for "a pseudo-device that hands whole packets to a
 * userspace process and takes a verdict back". */
#define OTP_FW_IOC_SET_ENABLED     _IOW('O', 1, uint32_t)
#define OTP_FW_IOC_GET_ENABLED     _IOR('O', 2, uint32_t)
#define OTP_FW_IOC_SET_CANDIDATES  _IOW('O', 3, otp_fw_set_candidates_t)

#endif /* OTP_FIREWALL_PROTO_H */
