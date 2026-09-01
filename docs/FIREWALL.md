# OTP Firewall

## Index

1. [What is OTP Firewall](#what-is-otp-firewall)
2. Linux Kernel Module
   - [How it works (Linux)](#how-it-works-linux)
   - [How to install/use it (Linux)](#how-to-installuse-it-linux)
   - [Technical details (Linux)](#technical-details-linux)
3. macOS Kernel Module
   - [How it works (macOS)](#how-it-works-macos)
   - [How to install/use it (macOS)](#how-to-installuse-it-macos)
   - [Technical details (macOS)](#technical-details-macos)
4. Windows WFP Callout Driver
   - [How it works (Windows)](#how-it-works-windows)
   - [How to install/use it (Windows)](#how-to-installuse-it-windows)
   - [Technical details (Windows)](#technical-details-windows)

## What is OTP Firewall

OTP Firewall is a system-wide network firewall, built on top of
otp-toolkit's one-time-pad keychain, available on **Linux**
(`firewall/linux-kernel-module/` + `firewall/daemon/`), **macOS**
(`firewall/macos-kernel-module/`), and **Windows**
(`firewall/windows-wfp-callout-driver/`). Once active, it blocks all incoming and
outgoing network traffic by default, and only allows traffic to and from the
contacts in your keychain. There's no separate password, certificate, or
shared secret to set up — the same one-time-pad keys you already use with the
`otp` command are what authenticate and encrypt this traffic.

In short:

- **Default deny** — every connection is blocked unless it's proven to come
  from, or is going to, a known contact.
- **Contact-based** — "known" means a contact in your `otp` keychain, sharing
  a one-time-pad key pair with you.
- **Transparent** — once set up, ordinary applications (browsers, SSH, and so
  on) don't need to know anything changed. Traffic to and from your contacts
  keeps working normally; everything else is silently dropped.

All three platforms share the same core logic — the same
`cipher.c`/`keychain.c`/`commit.c` crypto library unmodified, and the same
packet-parsing/config/pin/trial-ordering code in `firewall/daemon/` reused
directly across all of them — with a thin, platform-specific layer on top
doing the actual traffic interception (a kernel module on Linux, a System
Extension on macOS, a WFP callout driver on Windows). The sections below are
split by platform because that interception layer — and therefore how you
install, run, and control it — genuinely differs between them; the underlying
protocol behavior (what gets encrypted, how a packet is authenticated, what
gets logged and why) is identical across all three.

**Maturity differs sharply across the three.** The Linux side has been
built, compiled, and unit-tested (`firewall/linux-kernel-module/tests/`,
4,273 checks) — though its kernel module specifically has still never been
loaded on a real machine. The macOS side has never been compiled at all
(written without access to Xcode or a macOS SDK) and carries real open
architecture questions, not just unverified API calls — see ["Technical
details (macOS)"](#technical-details-macos) for specifics. The Windows side
has also never been compiled (no WDK/MSVC access) and, on top of that, its
kernel↔userspace packet queue was designed from scratch with no existing
mechanism to lean on the way Linux's module leans on NFQUEUE — see
["Technical details (Windows)"](#technical-details-windows) before relying
on any of the three for anything.

## How it works (Linux)

### Outgoing traffic

When your computer sends a packet to an address that's mapped to one of your
contacts (see ["How to install/use it (Linux)"](#how-to-installuse-it-linux)
below), the firewall encrypts that packet's contents using your one-time-pad
key for that contact before it leaves your machine. The packet keeps its
original source, destination, and port — only its contents change. Traffic to
any address that isn't mapped to a contact is dropped outright.

### Incoming traffic

A packet can only ever reach the point of being decrypted if its source
address is one the firewall already has a reason to consider: either an
address listed in your configuration, or one already proven to belong to a
contact from an earlier packet. Traffic from any other address is dropped
immediately, before any decryption is attempted, so that a stranger
(a random scan, an attacker) can't force your machine to spend effort trying
your keychain against their traffic. In practice this means every contact
you actually want to receive traffic from needs an entry in your
configuration — an address that was never mentioned there gets no chance at
all, however good its key is.

For a packet from a recognized address, the firewall tries to decrypt it
using your contacts' keys, one at a time, until one succeeds:

1. If that address was already proven to belong to a specific contact
   recently, only that contact's key is tried.
2. Otherwise, if the address is mapped to a specific contact in your
   configuration, that contact's key is tried first.
3. If that doesn't work, every other contact's key is tried in turn.

If any key successfully decrypts the packet, it's accepted, restored to its
original contents, and delivered normally — and that source address is now
remembered as belonging to that contact, speeding up future packets from it.
If no key works, the packet is dropped and logged.

### Every packet is checked individually

The firewall doesn't establish an ongoing "trusted session" — every single
packet has to prove itself on its own. This has one real-world consequence:
if packets from a contact happen to arrive out of order (which can happen on
real networks), the out-of-order packet is rejected, even though it's
genuinely from that contact. For most applications, which use TCP, this
corrects itself automatically — the application notices something didn't
arrive and resends it, and the resend is checked fresh. Applications using
UDP with no retry logic of their own can lose data in this situation.

### Key material is consumed as you go

One-time-pad keys are, as the name implies, used once and then gone —
encrypting data with them destroys the key bytes involved. Since the firewall
encrypts everything going to a contact, sending or receiving a lot of data
uses up that contact's key material accordingly. If a contact's key runs out,
the firewall does not fall back to sending things in the clear — it simply
blocks further traffic to and from that contact until you supply more key
material.

### IPv6 still works

IPv6 depends on a background protocol (the rough equivalent of ARP in IPv4)
just to find other devices on the network and locate your router. The
firewall always allows that protocol through untouched, since it carries no
application data to authenticate, and blocking it would break IPv6 entirely.
Everything else that isn't ordinary TCP or UDP traffic is blocked.

## How to install/use it (Linux)

### 1. Install the kernel headers

The firewall's kernel module needs to be built against your exact running
kernel. Install the matching headers package first:

```
# Arch:           sudo pacman -S linux-headers
# Debian/Ubuntu:  sudo apt install linux-headers-$(uname -r)
# Fedora:         sudo dnf install kernel-devel
```

### 2. Build

From the repository root:

```
make firewall-daemon   # builds the background service, otp-firewalld
make firewall-kmod     # builds the kernel module, otp_firewall.ko
```

### 3. Set up your contacts

The firewall uses its own keychain, kept separate from any keychain you use
for everyday `otp` encrypt/decrypt work, at `~/.otp/firewall_keychain`. To add
a contact to it, run the normal `otp` keychain commands from inside `~/.otp`
specifically — that's what points them at the firewall's keychain instead of
whatever keychain you might have elsewhere:

```
cd ~/.otp
otp -nk 100 me alice       # generates a mirrored one-time-pad key pair for you and alice
otp -ac alice <enc-key-file> <dec-key-file>   # add alice as a contact using her half
```

Send your contact their half of the key pair through a trusted channel out of
band, and have them do the equivalent on their end. See `otp --help` for the
full set of keychain commands.

### 4. Tell the firewall which addresses belong to which contact

Create `~/.otp/firewall.config`:

```
# contact-name   ip-or-hostname [ip-or-hostname ...]
alice            203.0.113.5 alice.example.com
bob              198.51.100.9
```

Each line maps a contact to one or more IP addresses or hostnames. This
decides who outgoing traffic gets encrypted for, and gives incoming traffic a
fast first guess at who sent it.

### 5. Load the kernel module

The module requires IP defragmentation to be active (so it only ever sees
whole, reassembled packets — never a raw fragment it can't safely parse),
using the same standard modules the rest of the kernel's connection-tracking
machinery depends on. Load those first — they ship with every mainline
kernel, so this is just loading what's already installed:

```
sudo modprobe nf_defrag_ipv4 nf_defrag_ipv6
sudo insmod firewall/linux-kernel-module/otp_firewall.ko
```

(If you skip this, `insmod` will fail with an "unknown symbol" error rather
than loading in a degraded state.)

The module starts **disabled** — nothing about your network changes yet.
Confirm it loaded:

```
lsmod | grep otp_firewall
dmesg | tail -1
```

### 6. Start the background service

Start it in log-only mode first, so you can see what it *would* do before it
can actually block anything:

```
sudo otp-firewalld --mode=log-only
```

Watch `~/.otp/authorized.log` and `~/.otp/restricted.log` to confirm it's
making the decisions you expect. When you're satisfied, restart it in
enforcing mode:

```
sudo otp-firewalld --mode=enforce
```

### 7. Turn the firewall on

Enforcement is a separate step from starting the service, so you always have
a fast way back if something looks wrong:

```
echo 1 | sudo tee /proc/otp_firewall/enabled   # turn on
echo 0 | sudo tee /proc/otp_firewall/enabled   # turn off instantly
cat /proc/otp_firewall/enabled                 # check current state
```

Turning it off this way takes effect immediately, on the very next packet,
and doesn't require restarting the service or removing the kernel module —
it's the fastest way to get your normal network back if anything looks wrong.

### 8. Removing it

```
sudo rmmod otp_firewall
```

This unloads the kernel module (which also turns enforcement off). Then stop
`otp-firewalld` however you started it (`Ctrl-C`, `systemctl stop`, etc.).

## Technical details (Linux)

### Architecture

The firewall has two parts:

- **A kernel module** (`otp_firewall.ko`) that watches outgoing and incoming
  traffic. For outgoing packets it checks whether the destination matches a
  known contact; for incoming packets, whether the source does. Traffic that
  clearly doesn't match anything is dropped immediately, without ever leaving
  the kernel. Traffic that might be relevant is handed off to the background
  service for a real decision.
- **A background service** (`otp-firewalld`) that does the actual encryption,
  decryption, and contact matching, and writes the log files.

```
                         ┌────────────────────────────────────────┐
                         │   otp_firewall.ko  (kernel module)     │
                         │                                        │
  outgoing packet ───────►  known destination? ─ no ──► blocked   │
                         │           │ maybe                      │
                         │           ▼                            │
  incoming packet ───────►  known source? ─ no ──► blocked        │
                         │           │ maybe                      │
                         └───────────┼────────────────────────────┘
                                     ▼
                         ┌────────────────────────────────────────┐
                         │   otp-firewalld  (background service)  │
                         │                                        │
                         │  outgoing: encrypt for the matched     │
                         │  contact, or block if none is matched  │
                         │                                        │
                         │  incoming: try to decrypt against your │
                         │  contacts' keys; allow through on the  │
                         │  first one that works, otherwise block │
                         └────────────────────────────────────────┘
```

Only TCP and UDP traffic is affected. Every other protocol is blocked, except
IPv6's Neighbor Discovery traffic (see ["How it works
(Linux)"](#how-it-works-linux)), which always passes through untouched.

Advanced: the kernel module and the daemon communicate over a pair of
numbered queues (0 for outgoing, 1 for incoming, by default). If you need to
change these — e.g. to avoid clashing with another NFQUEUE-based tool — pass
matching `queue_egress=`/`queue_ingress=` module parameters to `insmod` and
`--queue-egress=`/`--queue-ingress=` flags to `otp-firewalld`.

### File locations

| Path | Purpose |
|---|---|
| `~/.otp/firewall_keychain/` | The firewall's own keychain (separate from any keychain you use elsewhere) |
| `~/.otp/.keychain` | Internal link to `firewall_keychain` — this is what lets you manage firewall contacts with the ordinary `otp` command by running it from inside `~/.otp` |
| `~/.otp/firewall.config` | Contact → address mapping (see ["How to install/use it (Linux)"](#how-to-installuse-it-linux)) |
| `~/.otp/authorized.log` | One line per packet that was let through |
| `~/.otp/restricted.log` | One line per packet that was blocked |

### Log format

Each line looks like:

```
<timestamp> <direction> <contact-or-"-"> <source>:<port> <destination>:<port> <protocol> <reason>
```

`direction` is `egress` (outgoing) or `ingress` (incoming). In
`authorized.log`, `reason` is always `validated`. In `restricted.log`,
`reason` is one of:

| Reason | Meaning |
|---|---|
| `no-matching-contact` | This address isn't mapped to any contact |
| `meta-mismatch` | Decryption was attempted but didn't validate against any contact tried |
| `pin-mismatch` | This address was already tied to a specific contact, and this packet didn't validate against that contact's key |
| `key-exhausted` | That contact's key material has run out |
| `pending-recovery` | That contact has an unfinished operation left over from a previous `otp` command; run `otp --status <contact>` and resolve it before firewall traffic for that contact will flow again |
| `parse-error` | The packet couldn't be parsed as ordinary TCP/UDP traffic |

### How traffic is transformed

Each packet's contents are individually encrypted before it leaves your
machine, and decrypted after it arrives at the other end, using your
one-time-pad key material — the same encryption `otp` itself uses. Because
this makes each packet's contents slightly larger, the firewall grows the
packet just before it leaves the machine and shrinks it back to its original
size just as it arrives on the other end. That change is invisible to both
computers' own network software and to the applications using the
connection — only the two firewalls involved ever see the grown form.

### Limitations

- **Packet size:** if OTP-wrapping pushes a packet past your network's
  maximum packet size, it's handled by ordinary IP fragmentation rather than
  anything special.
- **Key usage:** every packet sent to a contact — even ones carrying no data,
  like a bare acknowledgment — consumes some key material. Chatty connections
  cost more key material than their actual data volume alone would suggest.
- **IPv6 extension headers** aren't inspected; packets using them are blocked
  rather than potentially misread.
- **Packet reordering** causes a genuinely valid packet to be rejected if it
  arrives out of order (see ["How it works (Linux)"](#how-it-works-linux)
  above) — expected behavior, not a malfunction.

## How it works (macOS)

The protocol itself — what's authenticated, what's encrypted, what gets
logged and why — is identical to the [Linux version](#how-it-works-linux):
same trial-decryption order (pinned contact → configured contact → the rest
of the keychain), same "every packet checked individually" tradeoff, same
key-consumption behavior, same IPv6 handling. What differs is the mechanics
of how traffic reaches that logic, because there's no kernel-level piece on
macOS the way there is on Linux:

- **No fast in-kernel prefilter.** Linux's kernel module drops obviously
  irrelevant traffic before it ever reaches the daemon. macOS has no
  equivalent: a System Extension running `NEPacketTunnelProvider` (see
  ["Technical details (macOS)"](#technical-details-macos) for why this
  instead of a kernel extension) captures traffic by presenting itself as a
  virtual network interface and being set as the default route — every
  packet that reaches it goes through the full trial-decryption logic
  directly, with no cheap pre-check ahead of it.
- **No separate kernel-vs-userspace split.** On Linux, packet interception
  (kernel module) and the actual crypto/decision-making (`otp-firewalld`)
  are two different processes talking over NFQUEUE. On macOS both live in
  one process — the System Extension.
- **Outgoing packets need an explicit re-transmit step.** Apple's tunnel API
  has no "accept this outbound packet, possibly modified, and let it
  continue to the network" primitive — only "inject this packet as if it
  had just arrived from the network." An approved outbound packet (grown
  and encrypted, or passed through unchanged in log-only mode) is put on
  the wire with a raw IP socket instead. See ["Technical details
  (macOS)"](#technical-details-macos) for why this specific piece is the
  least-confident part of the whole port.
- **Whether unsolicited inbound connections are even visible to this
  design at all is genuinely unverified** — not just an unconfirmed API
  detail, but an open architecture question. `NEPacketTunnelProvider` is
  shaped around the VPN-client model (your traffic goes into the tunnel,
  reaches a remote endpoint, replies come back through the same tunnel). If
  it turns out unsolicited inbound traffic — someone connecting *to* this
  Mac, not a reply to something it sent — never reaches the virtual
  interface at all, this design protects outbound-initiated traffic and its
  replies, but not something like an inbound SSH connection to a service
  running on this Mac. This needs to be established on a real Mac before
  relying on it for anything.

## How to install/use it (macOS)

**This has never been built.** Written without access to Xcode, a macOS SDK,
or any Apple toolchain — see ["Technical details
(macOS)"](#technical-details-macos) for exactly what is and isn't verified
before following these steps.

### 1. Prerequisites

An Apple Developer Program membership (required for the NetworkExtension
entitlement and code signing — this doesn't work unsigned or with a free
account), and Xcode.

### 2. Create the Xcode project

No `.xcodeproj` is included in this repository — hand-generating Xcode's
project file format correctly, unverified, seemed more likely to produce
something that fails to open than something useful. Create the project shell
yourself:

1. In the Apple Developer portal, enable the **Network Extensions**
   capability for both an App ID (the host app) and a second App ID (the
   extension, typically `<app-id>.Extension`).
2. In Xcode: **File > New > Project > App**, then **File > New > Target >
   Network Extension** (choose Packet Tunnel) to add the extension target,
   embedded in the app.
3. Add the reused `firewall/daemon/*` files — `common.h`, `checksum.h`/`.c`,
   `config.h`/`.c`, `pin.h`/`.c`, `trial.h`/`.c`, `keychain_setup.h`/`.c`,
   `log.h`/`.c`, `packet_codec.h` (just the header) — plus everything in
   `firewall/macos-kernel-module/Shared/` and `Extension/`, to the extension
   target. Compile `Shared/packet_codec_macos.c` **instead of**
   `firewall/daemon/packet_codec.c` (same public API, macOS-native BSD
   struct field names instead of Linux/glibc ones). Add
   `firewall/macos-kernel-module/App/*` to the app target.
4. Set the extension target's **Objective-C Bridging Header** build setting
   to `OTPFirewallExtension-Bridging-Header.h`.
5. Set both targets' entitlements file (Signing & Capabilities) to the
   `.entitlements` files provided, and enable the Network Extensions
   capability with the matching provider type in each target's Signing &
   Capabilities tab.
6. Update `OTPFirewallController.extensionBundleID` in
   `App/OTPFirewallApp.swift` to match your actual extension target's bundle
   identifier.

### 3. Set up your contacts and configuration

Identical to Linux: same files, same format, same location, since
`otp_fw_setup_keychain_dir()`/`config.c`/`log.c` are the exact same
unmodified POSIX code on both platforms. See steps 3–4 of ["How to
install/use it (Linux)"](#how-to-installuse-it-linux) — `~/.otp/firewall_keychain/`,
`~/.otp/firewall.config`, `cd ~/.otp && otp -ac ...` all work the same way.

### 4. Build, activate, and run

Build and run the host app in Xcode, then click through activation. macOS
will prompt for approval in **System Settings > Privacy & Security > Login
Items & Extensions** — this is a real, user-visible OS prompt, not something
that can be scripted around. The sample app's Toggle chooses log-only vs.
enforce mode before you press Start; unlike the Linux side, activating the
extension and starting the tunnel are close together in this design, so
there's no separate "loaded but disabled" state — see ["Technical details
(macOS)"](#technical-details-macos) for what that means for a kill switch.

### 5. Removing it

Press Stop in the app (calls `stopVPNTunnel()`), then remove the extension's
approval in System Settings if you want it fully uninstalled.

## Technical details (macOS)

### This is not a kernel module

There is no current, Apple-sanctioned kernel-module equivalent for network
filtering on macOS. The old mechanism (KEXTs / Network Kernel Extensions) is
deprecated, barely functional on Apple Silicon without disabling core
security features (Reduced Security mode via the Startup Security Utility in
Recovery), and could stop being loadable at all in a future release.

What `firewall/macos-kernel-module/` actually contains is a **System
Extension** running `NEPacketTunnelProvider` (part of
`NetworkExtension.framework`) — the current Apple-recommended way to
intercept and control network traffic. It runs in **userspace**, not kernel
space, with elevated networking privileges granted through code-signing
entitlements and (usually) explicit user approval in System Settings, not
through kernel privilege. The directory is still named `macos-kernel-module`
to mirror `linux-kernel-module` structurally — think of it as "the piece
that plays the same role," not "the piece with the same privilege level."

### What's verified and what isn't

**Nothing in `firewall/macos-kernel-module/` has been compiled, signed, or
run.** It was written in a Linux sandbox with no Xcode, no macOS SDK, no
Swift or Objective-C toolchain, and no way to check any of it against real
Apple headers or documentation. Compare this to the Linux kernel module,
which was at least reasoned about from long-stable, extremely well-documented
kernel APIs — here the uncertainty is broader and includes some genuinely
load-bearing architecture questions, not just API-name nitpicks. In
descending order of how much they matter:

1. **Whether `NEPacketTunnelProvider` sees genuinely inbound (server-side)
   connections at all** — see ["How it works (macOS)"](#how-it-works-macos)
   above. The single biggest open question.
2. **`otp_fw_bridge_send_raw()`'s raw-socket approach** for actually
   transmitting an approved outbound packet: `NEPacketTunnelFlow` has no
   "accept this outbound packet, possibly modified" primitive, only an
   "inject as received" one. A raw IP socket with `IP_HDRINCL` (IPv4) /
   `IPV6_HDRINCL` (IPv6) sending the exact bytes already constructed is the
   mechanism used, but whether a System Extension's sandbox permits opening
   a raw socket at all, and whether the IPv6 header-inclusion path works the
   way IPv4's does, are both unconfirmed. See the extended comment on that
   function in `Extension/OTPFirewallBridge.h`.
3. **Exact Swift API surface** in `Extension/OTPFirewallProvider.swift` —
   method names like `readPacketObjects`/`writePacketObjects`, and
   `NEPacket.direction`/`.protocolFamily`'s exact types. See the confidence
   notes at the top of that file.
4. Everything in `Shared/packet_codec_macos.c` (the BSD header struct field
   names — `struct ip`'s `ip_hl`/`ip_p`, `struct tcphdr`'s
   `th_sport`/`th_off`, `struct udphdr`'s `uh_sport`/`uh_ulen`) is
   well-established, decades-stable BSD sockets API — this is the part of
   the whole port with the **highest** confidence, on par with the Linux
   kernel module's netfilter API usage.

Treat this the same way as the Linux kernel module before it was ever built:
a careful, best-effort starting point, not a working deliverable.

### Architecture

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

Unlike the Linux side, there is no separate fast-path prefilter ahead of this
— every packet that reaches the tunnel goes through the logic above directly.

### What's reused unmodified vs. what's new

`cipher.c`/`keychain.c`/`commit.c` (the actual OTP crypto/keychain library)
need **zero changes** — `src/compat.h` branches purely on `_WIN32` vs. real
POSIX, and macOS is genuine POSIX (BSD-derived), so these compile in exactly
as they do on Linux.

Of `firewall/daemon/`'s own files, everything is pure POSIX C with no
Linux-specific dependencies **except** `packet_codec.c` (which uses
Linux/glibc struct field names directly). So the Xcode project references
`common.h`, `checksum.h`/`.c`, `config.h`/`.c`, `pin.h`/`.c`, `trial.h`/`.c`,
`keychain_setup.h`/`.c`, `log.h`/`.c`, and `packet_codec.h` (just the header)
**directly, by reference, unmodified**, and compiles
`firewall/macos-kernel-module/Shared/packet_codec_macos.c` **instead of**
`firewall/daemon/packet_codec.c` — same public API, BSD header field names.

New for macOS, all under `firewall/macos-kernel-module/`:

- `Extension/OTPFirewallBridge.h`/`.c` — the C↔Swift bridge; the macOS analog
  of `firewall/daemon/main.c`'s NFQUEUE callbacks, minus the NFQUEUE-specific
  parts (there's no separate kernel piece here to hand a verdict back to).
  Also where the ICMPv6 exemption lives (`otp_fw_bridge_is_icmpv6()`),
  mirroring `firewall/linux-kernel-module/otp_firewall.c`'s
  `otp_fw_is_icmpv6()`.
- `Extension/OTPFirewallProvider.swift` — the actual `NEPacketTunnelProvider`
  subclass.
- `Extension/Info.plist`, `Extension/OTPFirewallExtension.entitlements`,
  `Extension/OTPFirewallExtension-Bridging-Header.h`
- `App/*` — a minimal host app that activates the extension and
  starts/stops enforcement. Not a real settings UI.

There is **no macOS analog of `kernel_ctl.c`**: on macOS there's no separate
kernel-side process to push a candidate list to.

### File locations

Identical to [Linux](#file-locations) — `~/.otp/firewall_keychain/`,
`~/.otp/.keychain`, `~/.otp/firewall.config`, `~/.otp/authorized.log`,
`~/.otp/restricted.log` — since the code that reads and writes them is the
same unmodified POSIX code on both platforms.

### Log format

Identical to [Linux](#log-format) — same line format, same `reason` values.

### Known gaps beyond the "what's verified" list above

- **No kill switch equivalent to the Linux side's
  `/proc/otp_firewall/enabled`.** Stopping enforcement means calling
  `stopVPNTunnel()` (or the Stop button in the sample app) — there's no
  separate "loaded but disabled" state the way `insmod`-without-`echo 1`
  gives you on Linux, since activating the extension and starting the
  tunnel are close together in this design.
- **IPv6 extension headers, IP fragmentation**: same v1 scope limits as the
  Linux side (see ["Limitations"](#limitations)), not specifically
  re-verified for the BSD parsing path here.
- **No equivalent of the Linux daemon's test suite.**
  `firewall/linux-kernel-module/tests/` builds and runs against a real
  POSIX toolchain; nothing on the macOS side has been exercised the same
  way, because there's no way to build or run Swift/Xcode-project code from
  the environment this was written in at all.
- **No independent code review.** The Linux side has been through four
  rounds of independent review with real bugs found and fixed each time;
  the macOS port hasn't been reviewed at all yet.

## How it works (Windows)

The protocol itself — what's authenticated, what's encrypted, what gets
logged and why — is identical to the [Linux version](#how-it-works-linux):
same trial-decryption order (pinned contact → configured contact → the rest
of the keychain), same "every packet checked individually" tradeoff, same
key-consumption behavior, same IPv6 handling. Unlike macOS, the Windows port
*does* have a genuine kernel-mode piece, the same shape as Linux's:

- **A fast in-kernel prefilter, same as Linux.** A custom kernel driver
  built on the Windows Filtering Platform (WFP) watches outgoing and
  incoming IP packets at the packet layer and immediately drops anything
  that obviously doesn't match a known contact, before it ever reaches
  userspace — see ["Technical details (Windows)"](#technical-details-windows)
  for why this is a real callout driver and not
  [WinDivert](https://github.com/basil00/Divert) or the lighter-weight
  ALE/connection-authorization layer.
- **A kernel↔userspace packet queue, invented for this project.** Windows
  has no NFQUEUE equivalent. Traffic that might be relevant is pended in the
  kernel and handed to the background service over a custom device
  (`\\.\OTPFirewall`), which is genuinely the least-proven piece of this
  entire three-platform project — see ["Technical details
  (Windows)"](#technical-details-windows) before relying on it.
- **ICMPv6 (Neighbor Discovery) is exempted in the kernel driver itself**,
  the same place it's exempted on Linux — never in userspace — so it always
  passes through untouched and IPv6 keeps working.

## How to install/use it (Windows)

**This has never been built.** Written without access to the Windows Driver
Kit (WDK), MSVC, or any Windows toolchain — see ["Technical details
(Windows)"](#technical-details-windows) for exactly what is and isn't
verified before following these steps.

### 1. Build the driver

Install the WDK matching your Visual Studio version and build
`firewall/windows-wfp-callout-driver/Driver/` as a WDM driver project — no
project file is included, same reasoning as the macOS port's missing
`.xcodeproj`. See `firewall/windows-wfp-callout-driver/README.md` for the
exact file list.

### 2. Test-sign it — no Microsoft enrollment involved

This project deliberately does not enroll in Microsoft's production
driver-signing program (that needs an EV certificate and Hardware Dev
Center attestation submission — out of scope here). Instead it uses
Windows' own built-in test-signing mode, entirely self-service on your own
machine:

```
bcdedit /set testsigning on          # as Administrator, then reboot
```

Secure Boot must also be disabled in your machine's UEFI firmware settings
first — it blocks test-signed drivers regardless of this setting. Then
create a self-signed certificate and sign the built `.sys` — the exact
`New-SelfSignedCertificate`/`signtool sign` commands are in
`firewall/windows-wfp-callout-driver/README.md`.

### 3. Load the driver

```
sc create OTPFirewall type= kernel binPath= "C:\path\to\otp_firewall_driver.sys"
sc start OTPFirewall
```

The driver starts **disabled** — nothing about your network changes yet.

### 4. Set up your contacts and configuration

Identical to Linux: same files, same format, same location, since
`otp_fw_setup_keychain_dir()`/`config.c`/`log.c` need only small
`_WIN32` guards, not logic changes. See steps 3–4 of ["How to install/use
it (Linux)"](#how-to-installuse-it-linux) — `~/.otp/firewall_keychain/`,
`~/.otp/firewall.config`, `cd ~/.otp && otp -ac ...` all work the same way.
(`~/.otp` resolves via `%USERPROFILE%` when `$HOME` isn't set.) One
Windows-specific wrinkle: creating the `.keychain` link needs either
Administrator rights or Developer Mode enabled (Settings > Privacy &
Security > For developers).

### 5. Build and start the background service

```
sc create OTPFirewallSvc binPath= "C:\path\to\otp_firewall_svc.exe" start= demand
sc start OTPFirewallSvc
```

### 6. Turn the firewall on

Enforcement is a separate step from starting the driver and service, so you
always have a fast way back if something looks wrong — the Windows
equivalent of Linux's `/proc/otp_firewall/enabled`:

```
otpfwctl.exe status    # check current state
otpfwctl.exe enable    # turn on
otpfwctl.exe disable   # turn off instantly
```

Turning it off this way takes effect immediately and doesn't require
stopping the service or unloading the driver.

### 7. Removing it

```
otpfwctl.exe disable
sc stop OTPFirewallSvc
sc stop OTPFirewall
sc delete OTPFirewallSvc
sc delete OTPFirewall
```

Then, if you're done testing, revert test-signing mode
(`bcdedit /set testsigning off`) and re-enable Secure Boot.

## Technical details (Windows)

### Why a custom callout driver, not WinDivert or ALE

Two existing, more established alternatives were deliberately not used.
[WinDivert](https://github.com/basil00/Divert) is a pre-built, pre-signed
WFP-based packet capture library — using it would have meant the
kernel-mode piece of this project wasn't actually this project's own code,
unlike the Linux kernel module. The lighter-weight ALE layer
(`FWPM_LAYER_ALE_AUTH_CONNECT_V4`) only supports connection-level
allow/block decisions, not access to packet payloads — it can't do the
OTP wrap/unwrap this firewall needs. So this is a genuine custom callout
driver registered at the IP packet layer
(`FWPM_LAYER_{OUTBOUND,INBOUND}_IPPACKET_V{4,6}`), the same category of
thing as the Linux kernel module, just built on a different kernel
packet-filtering framework.

### What's verified and what isn't

**Nothing in `firewall/windows-wfp-callout-driver/` has been compiled,
signed, or run.** It was written in a Linux sandbox with no WDK, no MSVC,
and no way to check any of it against real WDK headers, a kernel debugger,
or a real Windows machine. In descending order of how much it matters:

1. **The kernel driver's classify pend/clone/reinject path** — the
   mechanism that hands a candidate packet to userspace and later
   re-transmits userspace's verdict (`FwpsPendOperation0`,
   `FwpsAllocateCloneNetBufferList0`, `FwpsCompleteOperation0`,
   `FwpsInjectNetworkSendAsync0`/`FwpsInjectNetworkReceiveAsync0`). There is
   no NFQUEUE equivalent on Windows to lean on — this is a from-scratch
   reconstruction of the documented "data-modifying callout" pattern, not
   something built or traced through a kernel debugger.
   **This is the single riskiest piece of the entire three-platform
   project** — more speculative even than macOS's open questions, since
   this is a protocol being invented, not an existing framework being
   called into.
2. **WFP callout/filter/sublayer registration shape** — the call sequence
   (`FwpmEngineOpen0`, `FwpsCalloutRegister0`, `FwpmCalloutAdd0`,
   `FwpmFilterAdd0`, `FwpmSubLayerAdd0`) is right in outline (well-documented
   Microsoft sample-code shape) but not checked against a real
   `fwpmk.h`/`fwpsk.h`.
3. **A known structural bug, left in deliberately rather than silently
   glossed over:** the in-kernel pended-packet struct currently reuses a
   single list-entry field for two different lists (the in-flight-by-ID
   table and the ready-for-dequeue queue) — flagged inline in the driver
   source as something to fix before this compiles correctly.
4. **The IOCTL dispatch, candidate table, and pending-read queue** —
   ordinary, well-trodden WDM patterns. Highest-confidence part of the
   driver, on par with the Linux module's own netfilter-hook bookkeeping.
5. **The background service and control utility** — ordinary Win32
   (`DeviceIoControl`, SCM service boilerplate). The one genuine
   architecture decision here (not just an API-verification risk): the
   service needs two threads where Linux's daemon needs one, since a
   blocking `DeviceIoControl` call has no signal-interrupt equivalent to
   lean on for periodic config reload — every access to the shared
   keychain/config state is serialized with an explicit lock as a result.

Treat this the same way the Linux kernel module was treated before it was
ever built: a careful, best-effort starting point that needs real WDK
test-signing hardware and a kernel debugger to finish, not a working
deliverable.

### Architecture

```
                         ┌─────────────────────────────────────────┐
                         │   otp_firewall_driver.sys (WFP callout  │
                         │   driver, kernel mode)                  │
                         │                                         │
  outgoing packet ───────►  known destination? ─ no ──► blocked    │
                         │           │ maybe                       │
                         │           ▼                             │
  incoming packet ───────►  known source? ─ no ──► blocked         │
                         │           │ maybe                       │
                         │           ▼                             │
                         │  ICMPv6? ─ yes ──► pass through as-is   │
                         └───────────┼─────────────────────────────┘
                                     │ \\.\OTPFirewall (custom IOCTL queue)
                         ┌───────────▼─────────────────────────────┐
                         │   otp_firewall_svc.exe  (Windows        │
                         │   Service, userspace)                   │
                         │                                         │
                         │  outgoing: encrypt for the matched      │
                         │  contact, or block if none is matched   │
                         │                                         │
                         │  incoming: try to decrypt against your  │
                         │  contacts' keys; allow through on the   │
                         │  first one that works, otherwise block  │
                         └─────────────────────────────────────────┘
```

Only TCP and UDP traffic is affected. Every other protocol is blocked,
except IPv6 Neighbor Discovery, which always passes through untouched.

### What's reused unmodified vs. what's new

`cipher.c`/`keychain.c`/`commit.c` need **zero changes** — `src/compat.h`
already branches cleanly on `_WIN32` vs. real POSIX, and this project's own
`make mingw` target already proves out warning-free MinGW-w64
cross-compilation of the core library.

Of `firewall/daemon/`'s own files, small additive `#ifdef _WIN32` guards
(header swaps, `_mkdir`/`_chdir`, `CreateSymbolicLinkA` in place of
`symlink()`) were enough to make `common.h`, `checksum.h`/`.c`,
`config.h`/`.c`, `pin.h`/`.c`, `trial.h`/`.c`, `keychain_setup.h`/`.c`,
`log.h`/`.c`, `packet_codec.h`, and `kernel_ctl.h` build for Windows too,
reused **directly, unmodified beyond those guards**.
`firewall/windows-wfp-callout-driver/Shared/packet_codec_windows.c` and
`Service/kernel_ctl_windows.c` compile **instead of**
`firewall/daemon/packet_codec.c` and `firewall/daemon/kernel_ctl.c`
respectively — same public APIs, Windows-specific bodies (this project's
own `#pragma pack(push,1)` header structs instead of an OS-provided one,
since Windows has no standard `struct iphdr`; `DeviceIoControl` instead of
a `/proc` file write).

New for Windows, all under `firewall/windows-wfp-callout-driver/`:

- `Driver/otp_firewall_protocol.h` — the wire format shared verbatim by the
  driver and every userspace consumer.
- `Driver/otp_firewall_driver.h`/`.c` — the WFP callout driver: the
  Windows equivalent of `firewall/linux-kernel-module/otp_firewall.c`.
- `Service/otp_firewall_svc.c` — the background Windows Service playing
  `otp-firewalld`'s role.
- `Ctl/otpfwctl.c` — the kill-switch control utility.

### File locations

Identical to [Linux](#file-locations) — `~/.otp/firewall_keychain/`,
`~/.otp/.keychain`, `~/.otp/firewall.config`, `~/.otp/authorized.log`,
`~/.otp/restricted.log` — since the code that reads and writes them needs
only small `_WIN32` guards, not logic changes.

### Log format

Identical to [Linux](#log-format) — same line format, same `reason` values.

### Known gaps beyond the "what's verified" list above

- **Secure Boot must be disabled** for test-signed drivers to load at all —
  a real, machine-wide security reduction for as long as you're testing
  this driver, not just a one-line command. Revert it when you're done (see
  ["How to install/use it (Windows)"](#how-to-installuse-it-windows)).
- **No equivalent of the Linux daemon's test suite.**
  `firewall/linux-kernel-module/tests/` builds and runs against a real
  POSIX toolchain; nothing on the Windows side has been exercised the same
  way, because there's no WDK/MSVC toolchain available in the environment
  this was written in at all.
- **IPv6 extension header walking, IP fragmentation**: same v1 scope
  limits as the other two platforms (see ["Limitations"](#limitations)),
  not re-verified for the WFP packet-layer path here.
- **No independent code review.** The Linux side has been through four
  rounds of independent review with real bugs found and fixed each time;
  the Windows port hasn't been reviewed at all yet.
