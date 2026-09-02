/*
 * otp_firewall_proto.h - the wire format for talking to /dev/otp_firewall,
 * shared verbatim between the KLD (otp_firewall.c) and userspace
 * (otp_firewalld_freebsd.c, kernel_ctl_freebsd.c). Unlike Windows (where
 * kernel-mode and user-mode headers are genuinely incompatible, forcing
 * a dependency-free split header), FreeBSD's kernel and userspace C
 * environments both understand plain <sys/types.h> fixed-width integers
 * fine, so one header works for both sides here without any special
 * care - the only wrinkle is that the KLD includes this via
 * <sys/ioccom.h> (already pulled in by <sys/param.h> in kernel builds)
 * while userspace needs <sys/ioctl.h> instead; both define the same
 * _IOWR()-family macros, so no #ifdef is needed in this file itself.
 *
 * UNVERIFIED - see README.md's confidence table. This file is
 * comparatively low-risk (POD structs and ioctl codes only), same
 * reasoning as the Windows port's own wire-format header.
 */

#ifndef OTP_FIREWALL_PROTO_H
#define OTP_FIREWALL_PROTO_H

#include <sys/types.h>
#include <sys/ioccom.h>

#define OTP_FW_DEVICE_NAME "otp_firewall"
#define OTP_FW_DEVICE_PATH "/dev/otp_firewall"

/* Must match firewall/daemon/common.h's OTP_FW_ACK_PORT exactly - the
 * daemon's delivery-acknowledgment side channel (see ack.h) needs this
 * traffic exempted from the encrypt/decrypt pipeline here in the
 * kernel, the same way ICMPv6 is, since neither this header nor the
 * userspace one can include the other (kernel vs. userspace build) -
 * same reasoning as the Linux module's own copy of this constant in
 * otp_firewall.h. */
#define OTP_FW_ACK_PORT 34443

/* Comfortably covers the largest possible IP packet (65535 bytes for
 * IPv6 payload + a 40-byte fixed header) plus OTP growth headroom, same
 * reasoning as OTP_FW_PACKET_BUF_CAP on Linux and OTP_FW_MAX_PACKET on
 * Windows. */
#define OTP_FW_MAX_PACKET 70000

/* Same reasoning as the Linux module's kvmalloc'd candidate table and
 * the Windows driver's OTP_FW_WIRE_MAX_CANDIDATES: a generous static
 * cap on how many contact IPs the daemon can push in one
 * OTP_FW_IOC_SET_CANDIDATES call. */
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

/* read()'s output: one candidate packet the kernel is holding (pfil
 * consumed the mbuf and parked it - see otp_firewall.c), waiting for a
 * verdict. A read() on /dev/otp_firewall blocks until either a packet
 * is queued or the device is closed (module unload / daemon exit
 * cancels all blocked readers). Exactly one packet per read() call,
 * same "one message per call" contract NFQUEUE's recv() has. */
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
 * candidate array embedded directly in the ioctl struct - ioctl(2)'s
 * argument size is encoded in the command itself (via _IOW's sizeof()),
 * which can't express "however many candidates the caller has right
 * now" as a compile-time constant without wastefully always copying
 * OTP_FW_WIRE_MAX_CANDIDATES entries. Passing a userspace pointer + count and
 * having the driver's own ioctl handler copyin() exactly `count *
 * sizeof(otp_fw_candidate_t)` bytes from `candidates` is the standard
 * BSD pattern for variable-length ioctl data (the same shape
 * `struct ifconf`'s `ifc_buf`/`ifc_len` uses for SIOCGIFCONF). */
typedef struct
{
  uint32_t count;
  const otp_fw_candidate_t *candidates;
} otp_fw_set_candidates_t;

/* Control operations, deliberately kept off the read()/write() data
 * path and issued via ioctl() instead - same split BPF (/dev/bpf) uses
 * between configuration (ioctl) and the packet stream itself
 * (read/write), a well-established BSD device-driver convention. */
#define OTP_FW_IOC_SET_ENABLED     _IOW('O', 1, uint32_t)
#define OTP_FW_IOC_GET_ENABLED     _IOR('O', 2, uint32_t)
#define OTP_FW_IOC_SET_CANDIDATES  _IOW('O', 3, otp_fw_set_candidates_t)

#endif /* OTP_FIREWALL_PROTO_H */
