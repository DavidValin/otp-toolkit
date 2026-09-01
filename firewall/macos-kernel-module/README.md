# OTP-toolkit Firewall — macOS

A System Extension running `NEPacketTunnelProvider` (part of
`NetworkExtension.framework`). For what the firewall actually does — what
gets encrypted, how a packet is authenticated, what gets logged — see
[`../README.md`](../README.md). This page covers building, configuring, and
turning the macOS port on and off.

There is no supported kernel-module mechanism left on macOS to build this
firewall as actual kernel code: the old mechanism (KEXTs / Network Kernel
Extensions) is deprecated, barely functional on Apple Silicon without
disabling core security features (Reduced Security mode via the Startup
Security Utility in Recovery), and could stop being loadable at all in a
future release. A System Extension is the current Apple-recommended way to
intercept and control network traffic instead. It runs in **userspace**,
not kernel space, with elevated networking privileges granted through
code-signing entitlements and (usually) explicit user approval in System
Settings, not through kernel privilege.

## Status: what's verified and what isn't

**Nothing in this directory has been compiled, signed, or run.** It was
written in a Linux sandbox with no Xcode, no macOS SDK, no Swift or
Objective-C toolchain, and no way to check any of it against real Apple
headers or documentation. In descending order of how much it matters:

1. **Whether `NEPacketTunnelProvider` sees genuinely inbound (server-side)
   connections at all** — someone connecting *to* this Mac, versus only
   return traffic for connections this Mac itself initiated. This API is
   shaped around the VPN-client model (your traffic goes into the tunnel,
   reaches a remote endpoint, replies come back through the same tunnel). If
   it turns out unsolicited inbound traffic never reaches the virtual
   interface at all, this design protects outbound-initiated traffic and its
   replies, but not something like an inbound SSH connection to a service
   running on this Mac. This is the single biggest open question and needs
   to be established on a real Mac before trusting this for anything.
2. **`otp_fw_bridge_send_raw()`'s raw-socket approach for actually
   transmitting an approved outbound packet.** `NEPacketTunnelFlow` has
   no "accept this outbound packet, possibly modified" primitive — only
   an "inject as received" one. A raw IP socket with `IP_HDRINCL` (IPv4)
   / `IPV6_HDRINCL` (IPv6) sending the exact bytes this codebase already
   constructs is the mechanism used here, but whether a System
   Extension's sandbox permits opening a raw socket at all, and whether
   the IPv6 header-inclusion path works the way IPv4's does, are both
   unconfirmed. See the extended comment on that function.
3. **Exact Swift API surface** in `Extension/OTPFirewallProvider.swift` —
   method names like `readPacketObjects`/`writePacketObjects`, and
   `NEPacket.direction`/`.protocolFamily`'s exact types. See the
   confidence notes at the top of that file.
4. Everything in `Shared/packet_codec_macos.c` (the BSD header struct
   field names — `struct ip`'s `ip_hl`/`ip_p`, `struct tcphdr`'s
   `th_sport`/`th_off`, `struct udphdr`'s `uh_sport`/`uh_ulen`) is
   well-established, decades-stable BSD sockets API — this is the part
   of the whole port with the highest confidence.

Treat this as a careful, best-effort starting point, not a working
deliverable.

## Architecture

```
                         ┌──────────────────────────────────────────┐
                         │   OTPFirewallExtension  (System          │
                         │   Extension, userspace)                  │
                         │                                          │
                         │  NEPacketTunnelProvider set as the       │
                         │  default route - captures all outgoing   │
                         │  traffic and (if reached at all - see    │
                         │  the open question above) incoming       │
                         │                                          │
  outgoing packet ───────►  ICMPv6? ─ yes ──► pass through as-is    │
                         │     │ no                                 │
                         │     ▼                                    │
                         │  encrypt for the matched contact, or     │
                         │  block if none is matched - then a raw   │
                         │  IP socket puts it on the wire           │
                         │                                          │
  incoming packet ───────►  ICMPv6? ─ yes ──► pass through as-is    │
                         │     │ no                                 │
                         │     ▼                                    │
                         │  try to decrypt against your contacts'   │
                         │  keys; on success, inject back into the  │
                         │  local stack via packetFlow, otherwise   │
                         │  block                                   │
                         └──────────────────────────────────────────┘
```

There is no separate fast-path prefilter ahead of this — every packet that
reaches the tunnel goes through the logic above directly. `NEPacketTunnelFlow`
has no packet-queue equivalent to build one on top of.

## What's reused unmodified vs. what's new

`cipher.c`/`keychain.c`/`commit.c` (the actual OTP crypto/keychain library)
need **zero changes** — `src/compat.h` branches purely on `_WIN32` vs. real
POSIX, and macOS is genuine POSIX (BSD-derived).

Of `firewall/daemon/`'s own files, everything is pure POSIX C **except**
`packet_codec.c`, which uses Linux/glibc struct field names directly. So the
Xcode project references these files **directly, by reference, unmodified**:

- `common.h`, `checksum.h`/`.c`, `config.h`/`.c`, `pin.h`/`.c`,
  `trial.h`/`.c`, `keychain_setup.h`/`.c`, `log.h`/`.c`,
  `packet_codec.h` (just the header — its declared API has no
  platform-specific types)

...and compiles `Shared/packet_codec_macos.c` (this directory) **instead
of** `firewall/daemon/packet_codec.c` — same public API, BSD header field
names.

New for macOS, in this directory:

- `Extension/OTPFirewallBridge.h`/`.c` — the C↔Swift bridge; where the
  actual encrypt/decrypt/candidate logic gets driven from Swift, and where
  the ICMPv6 exemption lives (`otp_fw_bridge_is_icmpv6()`).
- `Extension/OTPFirewallProvider.swift` — the actual
  `NEPacketTunnelProvider` subclass.
- `Extension/Info.plist`, `Extension/OTPFirewallExtension.entitlements`,
  `Extension/OTPFirewallExtension-Bridging-Header.h`
- `App/*` — a minimal host app that activates the extension and
  starts/stops enforcement. Not a real settings UI.

There is no separate kernel-side process here to push a candidate list to —
every packet that reaches the tunnel goes through the full trial-decryption
logic directly, with no cheap pre-check ahead of it.

## Compile

No `.xcodeproj` is included — hand-generating Xcode's project file format
correctly, unverified, seemed more likely to produce something that fails
to open than something useful. Create the project shell yourself:

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
7. Update `OTPFirewallController.extensionBundleID` in
   `App/OTPFirewallApp.swift` to match your actual extension target's bundle
   identifier.
8. Build the app target in Xcode.

## Configure

Same files, same format, same location described in
[`../README.md`](../README.md): `~/.otp/firewall_keychain/`,
`~/.otp/firewall.config`, `~/.otp/authorized.log`, `~/.otp/restricted.log`
all work exactly as documented there, since `otp_fw_setup_keychain_dir()`/
`config.c`/`log.c` are unmodified POSIX code. Manage contacts the normal
way:

```
cd ~/.otp
otp -nk 100 me alice
otp -ac alice <enc-key-file> <dec-key-file>
```

## Activate

Run the app, click through activation. macOS will prompt for approval in
**System Settings > Privacy & Security > Login Items & Extensions** — this
is a real, user-visible OS prompt, not something that can be scripted
around. The sample app's Toggle chooses log-only vs. enforce mode before you
press Start. Activating the extension and starting the tunnel are close
together in this design, so there's no separate "installed but disabled"
state the way a kernel module's load step is separate from its own enable
switch — starting the tunnel *is* turning enforcement on.

## Deactivate

Press Stop in the app (calls `stopVPNTunnel()`). There is no separate kill
switch independent of the tunnel itself — stopping the tunnel is the only
way to stop enforcement, and it also stops the extension from processing
any traffic at all (rather than continuing to run in a disabled/passthrough
state). To fully remove it, also revoke the extension's approval in System
Settings.

## Known gaps beyond the "what's verified" list above

- **IPv6 extension headers, IP fragmentation**: same scope limits described
  in [`../README.md`'s "Limitations"](../README.md#limitations), not
  specifically re-verified for the BSD parsing path here.
- **No test suite.** Nothing here has been exercised the way
  `firewall/linux-kernel-module/tests/` exercises the Linux daemon's code,
  because there's no way to build or run Swift/Xcode-project code from the
  environment this was written in at all.
- **No independent code review.** This port hasn't been reviewed at all
  yet.
