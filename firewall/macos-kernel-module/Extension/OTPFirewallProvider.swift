//
//  OTPFirewallProvider.swift
//
//  UNVERIFIED - written without Xcode/a macOS SDK, see ../README.md for
//  the full picture. Confidence notes on the specific API surface used
//  here, since this is the single riskiest file in the port:
//
//  HIGH confidence (long-stable, extensively documented/sampled APIs):
//    - NEPacketTunnelProvider itself, startTunnel/stopTunnel signatures
//    - NEPacketTunnelNetworkSettings / NEIPv4Settings / NEIPv6Settings
//      and setTunnelNetworkSettings(_:completionHandler:)
//    - packetFlow (inherited property) as the read/write point
//
//  LOWER confidence (exact names/shapes not independently confirmed):
//    - packetFlow.readPacketObjects(completionHandler:) /
//      .writePacketObjects(_:) - the *Data*-based readPackets/writePackets
//      pair is the older, better-established API; these Object-based
//      ones (needed for NEPacket.direction, which this design depends on
//      to tell inbound from outbound) are newer and less thoroughly
//      something this could cross-check from here.
//    - NEPacket.direction / NEPacket.protocolFamily property names and
//      exact types (protocolFamily's declared type - UInt32 vs
//      sa_family_t - is a guess; fix the comparison below if Xcode
//      disagrees).
//    - Whether NEPacket(data:protocolFamily:) is a public initializer
//      you're meant to construct directly (used here for injecting a
//      decrypted inbound packet) - if not, look for whatever the current
//      SDK's supported construction path is.
//
//  See OTPFirewallBridge.h's comment on otp_fw_bridge_send_raw() for the
//  most significant open architecture question: whether
//  NEPacketTunnelProvider even receives genuinely inbound (server-side)
//  connections at all, versus only return traffic for connections this
//  Mac itself initiated. Unverified either way.
//

import NetworkExtension
import os.log

class OTPFirewallProvider: NEPacketTunnelProvider {

  /// Defaults to log-only (observe and log, never drop or modify),
  /// unlike the Linux daemon which defaults to --mode=enforce. On Linux
  /// there's a *separate* kernel kill-switch that stays off until an
  /// operator explicitly flips it, so the daemon's own default doesn't
  /// matter much for initial safety. Here, activating the System
  /// Extension is the only gate there is - so this defaults to the safe
  /// side unless the containing app explicitly asks for enforcement.
  private var enforceMode = false

  private var reloadTimer: DispatchSourceTimer?

  override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    enforceMode = (options?["enforceMode"] as? Bool) ?? false

    guard otp_fw_bridge_setup() == 0 else {
      completionHandler(NSError(
        domain: "OTPFirewall", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "otp_fw_bridge_setup() failed - check ~/.otp/ permissions and firewall.config"]))
      return
    }

    // tunnelRemoteAddress is required by the API but not meaningful here
    // - there's no actual remote VPN endpoint, this tunnel exists purely
    // as a local interception point. Using the loopback address as a
    // placeholder, matching how several sample "local packet processing"
    // NEPacketTunnelProvider implementations do it.
    let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

    let ipv4 = NEIPv4Settings(addresses: ["192.0.2.1"], subnetMasks: ["255.255.255.0"])
    ipv4.includedRoutes = [NEIPv4Route.default()]
    settings.ipv4Settings = ipv4

    let ipv6 = NEIPv6Settings(addresses: ["fd00::1"], networkPrefixLengths: [64])
    ipv6.includedRoutes = [NEIPv6Route.default()]
    settings.ipv6Settings = ipv6

    settings.mtu = 1500

    setTunnelNetworkSettings(settings) { [weak self] error in
      guard let self = self else { return }
      if let error = error {
        completionHandler(error)
        return
      }
      self.startReloadTimer()
      self.readLoop()
      completionHandler(nil)
    }
  }

  override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    reloadTimer?.cancel()
    reloadTimer = nil
    completionHandler()
  }

  private func startReloadTimer() {
    let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
    timer.schedule(deadline: .now() + 60, repeating: 60)
    timer.setEventHandler {
      otp_fw_bridge_reload_config()
    }
    timer.resume()
    reloadTimer = timer
  }

  private func readLoop() {
    packetFlow.readPacketObjects { [weak self] packets in
      guard let self = self else { return }
      let toInject = packets.compactMap { self.handle(packet: $0) }
      if !toInject.isEmpty {
        self.packetFlow.writePacketObjects(toInject)
      }
      self.readLoop()
    }
  }

  /// Returns a packet to inject back into the local stack (inbound
  /// delivery), or nil if nothing should be written to packetFlow for
  /// this packet - either because it was dropped, or because it was an
  /// outbound packet that got sent directly to the network instead (see
  /// OTPFirewallBridge.h's otp_fw_bridge_send_raw() caveat: packetFlow
  /// has no "transmit this outbound packet" primitive, only "inject as
  /// received").
  private func handle(packet: NEPacket) -> NEPacket? {
    var result: NEPacket?
    let isOutbound = (packet.direction == .outbound)
    let family: Int32 = (packet.protocolFamily == UInt32(AF_INET6)) ? 6 : 4

    packet.data.withUnsafeBytes { (rawBuf: UnsafeRawBufferPointer) in
      guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else { return }
      let pktLen = Int32(rawBuf.count)

      // ICMPv6 (Neighbor Discovery, MLD, PMTU/error signaling) carries no
      // application data to authenticate and must always pass through
      // untouched in both directions - otherwise IPv6 breaks entirely,
      // the same reason firewall/linux-kernel-module/otp_firewall.c
      // exempts it unconditionally. Bypasses the bridge entirely, but
      // NOT the raw-send path for outbound: a packet only reaches this
      // read loop at all because the tunnel intercepted it from the
      // normal routing path (it's configured as the default route), so
      // returning nil here for an outbound packet would silently drop
      // it, not "let it through" - it still has to be put on the wire
      // explicitly, same as any other approved outbound packet.
      if otp_fw_bridge_is_icmpv6(base, pktLen) != 0 {
        if isOutbound {
          _ = otp_fw_bridge_send_raw(base, pktLen, family)
          result = nil
        } else {
          result = packet
        }
        return
      }

      var outBuf = [UInt8](repeating: 0, count: Int(OTP_FW_BRIDGE_BUF_CAP))
      var outLen: Int32 = 0
      let enforce: Int32 = enforceMode ? 1 : 0

      let action: otp_fw_action_t = isOutbound
        ? otp_fw_bridge_process_outbound(base, pktLen, &outBuf, Int32(OTP_FW_BRIDGE_BUF_CAP), &outLen, enforce)
        : otp_fw_bridge_process_inbound(base, pktLen, &outBuf, Int32(OTP_FW_BRIDGE_BUF_CAP), &outLen, enforce)

      switch action {
      case OTP_FW_ACTION_DROP:
        result = nil

      case OTP_FW_ACTION_FORWARD_ORIGINAL:
        if isOutbound {
          _ = otp_fw_bridge_send_raw(base, pktLen, family)
          result = nil
        } else {
          result = packet
        }

      case OTP_FW_ACTION_FORWARD_MODIFIED:
        if isOutbound {
          outBuf.withUnsafeBufferPointer { buf in
            _ = otp_fw_bridge_send_raw(buf.baseAddress, outLen, family)
          }
          result = nil
        } else {
          let modifiedData = Data(bytes: outBuf, count: Int(outLen))
          result = NEPacket(data: modifiedData, protocolFamily: packet.protocolFamily)
        }

      default:
        result = nil
      }
    }
    return result
  }
}
