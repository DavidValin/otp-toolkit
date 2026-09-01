//
//  ContentView.swift - minimal control surface: activate the extension,
//  then start/stop enforcement. Not a real settings UI (no
//  firewall.config editor, no log viewer) - those files live under
//  ~/.otp/ and can be edited/tailed with any text editor/`tail -f` in
//  the meantime. See ../README.md.
//

import SwiftUI

struct ContentView: View {
  @StateObject private var controller = OTPFirewallController()
  @State private var enforceMode = false

  var body: some View {
    VStack(spacing: 16) {
      Text("OTP-toolkit Firewall").font(.title)
      Text(controller.statusText).foregroundColor(.secondary)

      Button("1. Activate Extension") {
        controller.activateExtension()
      }

      Button("2. Load Tunnel Configuration") {
        controller.loadOrCreateTunnelConfiguration { error in
          if let error = error {
            DispatchQueue.main.async {
              controller.statusText = "Failed to load configuration: \(error.localizedDescription)"
            }
          }
        }
      }

      Toggle("Enforce (uncheck for log-only)", isOn: $enforceMode)

      HStack {
        Button("Start") { controller.start(enforce: enforceMode) }
        Button("Stop") { controller.stop() }
      }
    }
    .padding(40)
    .frame(minWidth: 360, minHeight: 260)
  }
}
