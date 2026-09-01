/*
 * otp_firewall_driver.h - internal declarations for the WFP callout
 * driver. Mirrors firewall/linux-kernel-module/otp_firewall.h's role:
 * candidate-IP table + kill switch + kernel<->userspace packet queue,
 * expressed with WDM/WFP primitives instead of netfilter's.
 *
 * CONFIDENCE: structurally reasoned from documented WFP concepts
 * (callout registration at the IPPACKET layer, FwpsPendOperation0 /
 * FwpsCompleteOperation0 / FwpsInject*0 for pend-clone-reinject), but
 * NOT built or tested against the real WDK - see ../README.md's
 * confidence table before treating any of this as verified.
 */

#ifndef OTP_FIREWALL_DRIVER_H
#define OTP_FIREWALL_DRIVER_H

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "otp_toolkit_firewall.h"

/* OTP_FW_WIRE_MAX_CANDIDATES itself lives in otp_toolkit_firewall.h (it
 * bounds the wire format, shared with userspace); this NonPagedPoolNx
 * allocation is sized to that same cap rather than kernel-side dynamic
 * growth - simpler to get right in code this hard to test. */
typedef otp_fw_candidate_t OTP_FW_CANDIDATE;

/* One packet the driver has pended a WFP classify for, waiting on a
 * verdict from userspace. Queued on g_pending_list; also tracked by
 * classify_context so FwpsCompleteOperation0 can be called once the
 * verdict comes back. */
typedef struct _OTP_FW_PENDED_PACKET
{
  LIST_ENTRY link;
  UINT64 packet_id;
  otp_fw_pkt_direction_t direction;
  ADDRESS_FAMILY family; /* AF_INET or AF_INET6, needed to pick the v4/v6 reinject path */
  UINT32 data_len;
  UINT8 data[OTP_FW_MAX_PACKET];

  /* Handles needed to complete the classify and reinject later, saved
   * off at pend time since the original classify stack args don't
   * outlive the classify call itself. */
  HANDLE complete_handle;      /* from FwpsPendOperation0 */
  HANDLE inject_handle;        /* from FwpsInjectionHandleCreate0, opened once at DriverEntry */
  UINT32 interface_index;
  UINT32 sub_interface_index;
  COMPARTMENT_ID compartment_id;
} OTP_FW_PENDED_PACKET;

/* Cancel-safe queue (IO_CSQ) bookkeeping for IRPs pended on
 * OTP_FW_IOCTL_DEQUEUE_PACKET while no packet is yet available -
 * IO_CSQ is the documented WDK pattern for exactly this "block a
 * blocking-read IOCTL until a producer has data" shape, rather than
 * hand-rolling IRP cancellation. */
typedef struct _OTP_FW_DEVICE_EXTENSION
{
  IO_CSQ pending_reads_csq;
  LIST_ENTRY pending_reads_list;
  KSPIN_LOCK pending_reads_lock;

  /* Packets that arrived before any reader was waiting; a dequeue IRP
   * drains this first before joining pending_reads_csq. */
  LIST_ENTRY ready_packets_list;
  KSPIN_LOCK ready_packets_lock;

  /* Packets currently pended in WFP (classify not yet completed),
   * keyed by packet_id so SUBMIT_VERDICT can find the right one. */
  LIST_ENTRY inflight_list;
  KSPIN_LOCK inflight_lock;
  volatile LONG64 next_packet_id;

  HANDLE wfp_engine;
  HANDLE injection_handle_v4;
  HANDLE injection_handle_v6;

  volatile LONG enabled; /* kill switch: 0 = fail-open passthrough, matches the other two platforms' default-off posture at load time */

  KSPIN_LOCK candidates_lock;
  OTP_FW_CANDIDATE *candidates; /* NonPagedPoolNx, OTP_FW_WIRE_MAX_CANDIDATES capacity */
  ULONG candidate_count;
} OTP_FW_DEVICE_EXTENSION;

extern OTP_FW_DEVICE_EXTENSION *g_otp_fw_ext;
extern PDEVICE_OBJECT g_otp_fw_device;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD OtpFwDriverUnload;

NTSTATUS OtpFwDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS OtpFwDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* Candidate table (see otp_firewall_driver_candidates.c section in the
 * .c file - kept in the same translation unit, not a separate file,
 * since the table is small enough not to warrant splitting). */
BOOLEAN OtpFwIsCandidate(BOOLEAN is_v6, const UINT8 *addr);
NTSTATUS OtpFwSetCandidates(const OTP_FW_CANDIDATE *list, ULONG count);

/* Fast in-kernel ICMPv6 exemption check, mirroring the Linux module's
 * own kernel-side exemption (see packet_codec_windows.c's forward
 * comment) - Neighbor Discovery must never be queued to userspace,
 * both for correctness (userspace decrypt would corrupt NDP and break
 * IPv6 link-local operation before the daemon is even reachable) and
 * latency. `l4_proto` is the IPv6 Next Header value already resolved
 * past any extension headers the classify code walked. */
BOOLEAN OtpFwIsIcmpv6(UINT8 l4_proto);

/* WFP callout registration/unregistration, called from DriverEntry /
 * OtpFwDriverUnload. */
NTSTATUS OtpFwRegisterCallouts(void);
void OtpFwUnregisterCallouts(void);

#endif /* OTP_FIREWALL_DRIVER_H */
