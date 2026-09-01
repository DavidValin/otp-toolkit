#ifndef OTP_FW_BRIDGE_H
#define OTP_FW_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /* Recommended size for the out_buf passed to
   * otp_fw_bridge_process_outbound()/_inbound(): comfortably covers the
   * largest possible IP packet (65535 bytes for IPv6 payload + a 40-byte
   * fixed header) plus OTP growth headroom. */
#define OTP_FW_BRIDGE_BUF_CAP 70000

  /* What the caller (OTPFirewallProvider.swift) should do with a packet.
   * Mirrors the verdict logic in firewall/daemon/main.c's egress_cb()/
   * ingress_cb() - only here it's a return value instead of an NFQUEUE
   * verdict call, since there's no separate kernel piece to hand a
   * verdict back to; this bridge function IS the enforcement point. */
  typedef enum
  {
    OTP_FW_ACTION_DROP = 0,
    OTP_FW_ACTION_FORWARD_ORIGINAL = 1,  /* pass the packet through byte-for-byte unchanged */
    OTP_FW_ACTION_FORWARD_MODIFIED = 2   /* forward out_buf / *out_len instead of the original */
  } otp_fw_action_t;

  /* Must be called once before any other function here. Sets up
   * ~/.otp/firewall_keychain (see keychain_setup.h), loads the keychain,
   * initializes logging, and loads+resolves ~/.otp/firewall.config.
   * Returns 0 on success. Safe to call from any thread once, at
   * extension startup (NEPacketTunnelProvider.startTunnel). */
  int otp_fw_bridge_setup(void);

  /* Re-parses and re-resolves firewall.config, and reconciles the pin
   * table against it (see main.c's reload_config_and_push() on Linux -
   * same idea, minus the kernel candidate-table push, which has no
   * macOS equivalent: there's no separate kernel-side prefilter here,
   * every packet already reaches this bridge). Call periodically (e.g.
   * every 60s) so hostname-based config entries stay current. */
  void otp_fw_bridge_reload_config(void);

  /* Returns 1 if `pkt` is IPv6 carrying ICMPv6 (Neighbor Discovery,
   * Multicast Listener Discovery, PMTU/error signaling - the rough
   * equivalent of ARP, required just for IPv6 to work on the local link
   * at all), 0 otherwise. The caller must always forward such a packet
   * unchanged, both directions, without involving
   * otp_fw_bridge_process_outbound()/_inbound() at all: ICMPv6 carries
   * no application data for OTP to authenticate, and
   * otp_fw_bridge_process_outbound()/_inbound() would otherwise drop it
   * in enforce mode (parse_packet() only recognizes TCP/UDP), breaking
   * IPv6 entirely - the same unconditional exemption
   * firewall/linux-kernel-module/otp_firewall.c's otp_fw_is_icmpv6()
   * applies. Does not walk IPv6 extension headers (same documented v1
   * scope limit as the rest of this codebase): a packet with a Fragment
   * or other extension header before the real ICMPv6 header will not be
   * recognized here. */
  int otp_fw_bridge_is_icmpv6(const uint8_t *pkt, int pkt_len);

  /* pkt/pkt_len: the outbound IP packet exactly as read from
   * NEPacketTunnelFlow (wire-format bytes). out_buf/out_cap: caller-owned
   * scratch buffer, must be at least pkt_len + ~256 bytes to have room
   * for OTP growth. On OTP_FW_ACTION_FORWARD_MODIFIED, out_buf / *out_len
   * hold the packet to actually send; on FORWARD_ORIGINAL, send pkt/
   * pkt_len unchanged; on DROP, send nothing.
   * enforce_mode: 1 for real enforcement, 0 for log-only (observe/log
   * without ever calling the real cipher - see
   * firewall/daemon/packet_codec.h's classify functions for why). */
  otp_fw_action_t otp_fw_bridge_process_outbound(const uint8_t *pkt, int pkt_len,
                                                 uint8_t *out_buf, int out_cap, int *out_len,
                                                 int enforce_mode);

  /* Same contract, inbound direction: pkt/pkt_len is a packet that
   * arrived from the network (still OTP-wrapped, if it's genuine
   * contact traffic). On FORWARD_MODIFIED, out_buf / *out_len hold the
   * packet shrunk back to its original plaintext form, ready to inject
   * back into the local network stack. */
  otp_fw_action_t otp_fw_bridge_process_inbound(const uint8_t *pkt, int pkt_len,
                                                uint8_t *out_buf, int out_cap, int *out_len,
                                                int enforce_mode);

  /* MOST UNVERIFIED PIECE OF THIS ENTIRE MACOS PORT - see ../README.md.
   *
   * NEPacketTunnelFlow has no "accept this outbound packet, possibly
   * modified, and let it actually reach the network" primitive - writing
   * to packetFlow injects a packet as if RECEIVED (the mechanism
   * otp_fw_bridge_process_inbound()'s FORWARD_MODIFIED/_ORIGINAL results
   * are meant to feed into), not transmitted. An outbound packet this
   * bridge approved (grown-and-encrypted, or passed through unchanged in
   * log-only mode) has to actually be put on the wire some other way.
   * This sends it via a raw IP socket (SOCK_RAW + IP_HDRINCL for IPv4,
   * IPV6_HDRINCL... note for the caller: IPv6 raw sockets typically do
   * NOT support supplying your own IPv6 header this way - only the
   * payload after it - which may mean this function needs a different
   * strategy for the IPv6 case specifically once tested against a real
   * target) so the packet's own already-computed headers/checksums are
   * used verbatim, exactly as constructed. Whether a System Extension's
   * sandbox/entitlements actually permit opening a raw socket at all is
   * itself unverified. Returns 0 on success, -1 on failure (check
   * errno). `pkt`/`pkt_len` is the complete IP packet (header included). */
  int otp_fw_bridge_send_raw(const uint8_t *pkt, int pkt_len, int family);

#ifdef __cplusplus
}
#endif

#endif /* OTP_FW_BRIDGE_H */
