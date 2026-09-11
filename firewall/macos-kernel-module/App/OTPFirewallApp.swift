//
//  OTPFirewallApp.swift
//
//  Minimal host app: a System Extension cannot run standalone, it must
//  be embedded in and activated by a containing app (this one). Kept
//  deliberately small - the actual firewall logic is entirely in
//  Extension/, not here. See ../README.md for the Xcode project setup
//  this assumes (an app target embedding a system extension target).
//
//  UNVERIFIED, same caveat as the rest of this port.
//

import SwiftUI
import SystemExtensions
import NetworkExtension

@main
struct OTPFirewallApp: App {
  var body: some Scene {
    WindowGroup {
      ContentView()
    }
  }
}

/// Wraps OSSystemExtensionManager (activating the .systemextension bundle
/// embedded in this app) and NETunnelProviderManager (configuring and
/// starting/stopping the packet-tunnel VPN configuration the extension
/// runs as). These are two separate activation steps on macOS: the
/// system extension has to be *installed and approved* first (a
/// one-time, user-confirmed step - System Settings > Privacy & Security
/// on Ventura+), and only then can a tunnel configuration referencing it
/// be created and started.
final class OTPFirewallController: NSObject, ObservableObject {
  @Published var statusText: String = "Not activated"

  /// Must match the extension target's bundle identifier exactly
  /// (Info.plist's CFBundleIdentifier there / the Xcode target's
  /// bundle ID setting).
  private let extensionBundleID = "com.example.OTPFirewall.Extension"

  private var tunnelManager: NETunnelProviderManager?

  func activateExtension() {
    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionIdentifier: extensionBundleID, queue: .main)
    request.delegate = self
    OSSystemExtensionManager.shared.submitRequest(request)
  }

  func loadOrCreateTunnelConfiguration(completion: @escaping (Error?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
      guard let self = self else { return }
      if let error = error {
        completion(error)
        return
      }

      let manager = managers?.first ?? NETunnelProviderManager()
      let proto = NETunnelProviderProtocol()
      proto.providerBundleIdentifier = self.extensionBundleID
      proto.serverAddress = "OTP Firewall" // required, not otherwise meaningful here
      manager.protocolConfiguration = proto
      manager.localizedDescription = "OTP Firewall"
      manager.isEnabled = true

      manager.saveToPreferences { error in
        if let error = error {
          completion(error)
          return
        }
        self.tunnelManager = manager
        completion(nil)
      }
    }
  }

  func start(enforce: Bool) {
    guard let manager = tunnelManager else {
      statusText = "No tunnel configuration - activate the extension first"
      return
    }
    do {
      // "enforceMode" here is read by OTPFirewallProvider.startTunnel(options:)
      // on the extension side; defaults to false (log-only) if omitted.
      try manager.connection.startVPNTunnel(options: ["enforceMode": enforce as NSObject])
      statusText = enforce ? "Starting (enforce mode)" : "Starting (log-only mode)"
    } catch {
      statusText = "Failed to start: \(error.localizedDescription)"
    }
  }

  func stop() {
    tunnelManager?.connection.stopVPNTunnel()
    statusText = "Stopped"
  }
}

extension OTPFirewallController: OSSystemExtensionRequestDelegate {
  func request(_ request: OSSystemExtensionRequest,
               didFinishWithResult result: OSSystemExtensionRequest.Result) {
    DispatchQueue.main.async {
      self.statusText = (result == .completed) ? "Extension activated" : "Activation requires approval"
    }
  }

  func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
    DispatchQueue.main.async {
      self.statusText = "Activation failed: \(error.localizedDescription)"
    }
  }

  func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    DispatchQueue.main.async {
      self.statusText = "Approve in System Settings > Privacy & Security, then relaunch"
    }
  }

  func request(_ request: OSSystemExtensionRequest,
               actionForReplacingExtension existing: OSSystemExtensionProperties,
               withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
    .replace
  }
}
