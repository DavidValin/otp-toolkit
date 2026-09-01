# OTP Firewall — macOS port

## This is not a kernel module

There is no current, Apple-sanctioned kernel-module equivalent for network
filtering on macOS. The old mechanism (KEXTs / Network Kernel Extensions)
is deprecated, barely functional on Apple Silicon without disabling core
security features (Reduced Security mode via the Startup Security Utility
in Recovery), and could stop being loadable at all in a future release.

What this directory actually contains is a **System Extension** running
`NEPacketTunnelProvider` (part of `NetworkExtension.framework`) — the
current Apple-recommended way to intercept and control network traffic.
It runs in **userspace**, not kernel space, with elevated networking
privileges granted through code-signing entitlements and (usually)
explicit user approval in System Settings, not through kernel privilege.
The directory is still named `macos-kernel-module` to mirror
`linux-kernel-module` structurally — think of it as "the piece that plays
the same role," not "the piece with the same privilege level."

## Read this before anything else: what's verified and what isn't

**Nothing in this directory has been compiled, signed, or run.** This was
written in a Linux sandbox with no Xcode, no macOS SDK, no Swift or
Objective-C toolchain, and no way to check any of it against real Apple
headers or documentation. Compare this to the Linux kernel module, which
was at least reasoned about from long-stable, extremely well-documented
kernel APIs — here the uncertainty is broader and includes some
genuinely load-bearing architecture questions, not just API-name
nitpicks. Specifically, in descending order of how much they matter:

1. **Whether `NEPacketTunnelProvider` sees genuinely inbound (server-side)
   connections at all** — someone connecting *to* this Mac, versus only
   return traffic for connections this Mac itself initiated. This API is
   shaped around the VPN-client model (your traffic goes into the
   tunnel, reaches a remote endpoint, replies come back through the same
   tunnel). If it turns out unsolicited inbound traffic never reaches the
   virtual interface at all, this design protects outbound-initiated
   traffic and its replies, but not something like an inbound SSH
   connection to a service running on this Mac. This is the single
   biggest open question and needs to be established on a real Mac
   before trusting this for anything.
2. **`otp_fw_bridge_send_raw()`'s raw-socket approach for actually
   transmitting an approved outbound packet.** `NEPacketTunnelFlow` has
   no "accept this outbound packet, possibly modified" primitive — only
   an "inject as received" one. A raw IP socket with `IP_HDRINCL` (IPv4)
   / `IPV6_HDRINCL` (IPv6) sending the exact bytes this codebase already
   constructs is the mechanism used here, but whether a System
   Extension's sandbox permits opening a raw socket at all, and whether
   the IPv6 header-inclusion path works the way IPv4's does, are both
   unconfirmed. See the extended comment on that function.
3. **Exact Swift API surface** in `OTPFirewallProvider.swift` — method
   names like `readPacketObjects`/`writePacketObjects`, and
   `NEPacket.direction`/`.protocolFamily`'s exact types. See the
   confidence notes at the top of that file.
4. Everything in `Shared/packet_codec_macos.c` (the BSD header struct
   field names — `struct ip`'s `ip_hl`/`ip_p`, `struct tcphdr`'s
   `th_sport`/`th_off`, `struct udphdr`'s `uh_sport`/`uh_ulen`) is
   well-established, decades-stable BSD sockets API — this is the part
   of the whole port with the **highest** confidence, on par with the
   Linux kernel module's netfilter API usage.

Treat this the same way as the Linux kernel module before it was ever
built: a careful, best-effort starting point, not a working deliverable.

## What's reused unmodified vs. what's new

`cipher.c`/`keychain.c`/`commit.c` (the actual OTP crypto/keychain
library) need **zero changes** — `src/compat.h` branches purely on
`_WIN32` vs. real POSIX, and macOS is genuine POSIX (BSD-derived), so
these compile in exactly as they do on Linux.

Of `firewall/daemon/`'s own files, everything is pure POSIX C with no
Linux-specific dependencies **except** `packet_codec.c` (which uses
Linux/glibc struct field names directly). So the Xcode project should
reference these files **directly, by reference, unmodified**:

- `common.h`, `checksum.h`/`.c`, `config.h`/`.c`, `pin.h`/`.c`,
  `trial.h`/`.c`, `keychain_setup.h`/`.c`, `log.h`/`.c`,
  `packet_codec.h` (just the header — its declared API has no
  Linux-specific types)

...and compile `Shared/packet_codec_macos.c` (this directory) **instead
of** `firewall/daemon/packet_codec.c` — same public API, BSD header
field names.

New for macOS, in this directory:

- `Extension/OTPFirewallBridge.h`/`.c` — the C↔Swift bridge; the macOS
  analog of `firewall/daemon/main.c`'s NFQUEUE callbacks, minus the
  NFQUEUE-specific parts (there's no separate kernel piece here to hand
  a verdict back to).
- `Extension/OTPFirewallProvider.swift` — the actual
  `NEPacketTunnelProvider` subclass.
- `Extension/Info.plist`, `Extension/OTPFirewallExtension.entitlements`,
  `Extension/OTPFirewallExtension-Bridging-Header.h`
- `App/*` — a minimal host app that activates the extension and
  starts/stops enforcement. Not a real settings UI.

There is **no macOS analog of `kernel_ctl.c`** or the Linux kernel
module's in-kernel candidate prefilter: on macOS there's no separate
kernel-side process to push a candidate list to, and no fast in-kernel
"is this even worth looking at" filter ahead of the extension — every
packet that reaches the tunnel goes through the full bridge logic
directly. Simpler architecture, no separate enforcement-point split, but
also no equivalent of that Linux-side performance optimization.

## Setup

No `.xcodeproj` is included — hand-generating Xcode's project file format
correctly, unverified, seemed more likely to produce something that fails
to open than something useful. Create the project shell yourself and add
these files as source:

1. **Prerequisites**: an Apple Developer Program membership (required for
   the NetworkExtension entitlement and code signing — this doesn't work
   unsigned or with a free account), Xcode.
2. In the Apple Developer portal, enable the **Network Extensions**
   capability for both an App ID (the host app) and a second App ID (the
   extension, typically `<app-id>.Extension`).
3. In Xcode: **File > New > Project > App**, then **File > New > Target >
   Network Extension** (choose Packet Tunnel) to add the extension
   target, embedded in the app.
4. Add the reused `firewall/daemon/*` files listed above, plus everything
   in this directory's `Shared/` and `Extension/`, to the extension
   target. Add `App/*` to the app target.
5. Set the extension target's **Objective-C Bridging Header** build
   setting to `OTPFirewallExtension-Bridging-Header.h`.
6. Set both targets' entitlements file (Signing & Capabilities) to the
   `.entitlements` files provided, and enable the Network Extensions
   capability with the matching provider type in each target's Signing &
   Capabilities tab.
7. Update `OTPFirewallController.extensionBundleID` in `App/OTPFirewallApp.swift`
   to match your actual extension target's bundle identifier.
8. Build, run the app, click through activation. macOS will prompt for
   approval in **System Settings > Privacy & Security > Login Items &
   Extensions** — this is a real, user-visible OS prompt, not something
   that can be scripted around.

## Configuration

Same files, same format, same location as the Linux daemon — see
`docs/FIREWALL.md`. `~/.otp/firewall_keychain/`, `~/.otp/firewall.config`,
`~/.otp/authorized.log`, `~/.otp/restricted.log` all work identically,
since `otp_fw_setup_keychain_dir()`/`log.c`/`config.c` are the same
unmodified POSIX code. Manage contacts the same way: `cd ~/.otp && otp
-ac ...`.

## Known gaps beyond the "unverified" list above

- **No kill switch equivalent to the Linux side's `/proc/otp_firewall/enabled`.**
  Stopping enforcement means calling `stopVPNTunnel()` (or the Stop
  button in the sample app) — there's no separate "loaded but disabled"
  state the way `insmod`-without-`echo 1` gives you on Linux, since
  activating the extension and starting the tunnel are close together in
  this design.
- **IPv6 extension headers, IP fragmentation**: same v1 scope limits as
  the Linux side (see `docs/FIREWALL.md`), not specifically re-verified
  for the BSD parsing path here.
- **No equivalent of the Linux daemon's test suite.** `firewall/linux-kernel-module/tests/`
  builds and runs against a real POSIX toolchain (this Linux sandbox);
  nothing here has been exercised the same way, because there's no way
  to build or run Swift/Xcode-project code from this environment at all.
