# OTP Firewall — Windows port

## What this is

A genuine kernel-mode driver, the same category of thing as
`firewall/linux-kernel-module` (not the userspace-only shape the macOS port
had to settle for). It uses the **Windows Filtering Platform (WFP)**, the
only supported way on modern Windows to intercept and modify IP packets
from kernel mode — this is a **custom WFP callout driver**, not
[WinDivert](https://github.com/basil00/Divert) (an existing, pre-built,
already-signed WFP-based tool this project deliberately did not adopt, so
that the kernel-mode piece is genuinely this project's own code, same as
the Linux module) and not the lighter-weight ALE/`FWPM_LAYER_ALE_AUTH_CONNECT_V4`
layer (connection-level allow/block only — no packet payload access, so
it can't do the OTP wrap/unwrap this project needs).

## Read this before anything else: what's verified and what isn't

**Nothing in this directory has been compiled, signed, or run.** This was
written in a Linux sandbox with no Windows Driver Kit (WDK), no MSVC, and
no way to check any of it against real WDK headers, a kernel debugger, or
a real Windows machine. In descending order of how much it matters:

1. **`Driver/otp_firewall_driver.c`'s classify pend/clone/reinject path**
   (`FwpsPendOperation0`, `FwpsAllocateCloneNetBufferList0`,
   `FwpsCompleteOperation0`, `FwpsInjectNetworkSendAsync0`/
   `FwpsInjectNetworkReceiveAsync0`). There is no NFQUEUE equivalent on
   Windows to lean on the way the Linux module does — this is a from-scratch
   reconstruction of the documented "data-modifying callout" pattern, and
   is explicitly flagged inline (search that file for "CONFIDENCE: LOWEST")
   everywhere it's a sketch rather than a finished call. **This is the
   single riskiest piece of the entire three-platform project** — more
   speculative even than the macOS port's open questions, since this is a
   protocol being invented, not an existing framework being called into.
2. **WFP callout/filter/sublayer registration shape** (`FwpmEngineOpen0`,
   `FwpsCalloutRegister0`, `FwpmCalloutAdd0`, `FwpmFilterAdd0`,
   `FwpmSubLayerAdd0`, at `FWPM_LAYER_{OUTBOUND,INBOUND}_IPPACKET_V{4,6}`)
   — the call sequence is right in outline (this is well-documented Microsoft
   sample-code shape), but exact struct field names/required flags were not
   checked against a real `fwpmk.h`/`fwpsk.h`.
3. **`OTP_FW_PENDED_PACKET`'s single `link` field being reused for two
   different lists** (the in-flight-by-`packet_id` table and the
   ready-for-dequeue queue) — flagged directly in
   `OtpFwEnqueuePacket()`'s comment as a real structural bug to fix (split
   into two `LIST_ENTRY` fields) before this compiles correctly against
   real WDK headers.
4. **`Driver/otp_firewall_protocol.h`, the IOCTL dispatch, the IO_CSQ-based
   pending-read queue, and the candidate table** — ordinary, well-trodden
   WDM patterns (`IoCreateDevice`, `IRP_MJ_DEVICE_CONTROL`, `IoCsqInitializeEx`,
   a spinlock-protected array). This is the highest-confidence part of the
   driver, on par with the Linux module's own netfilter-hook bookkeeping.
5. **`Service/otp_firewall_svc.c` and `Ctl/otpfwctl.c`** — ordinary Win32
   (SCM service boilerplate, `DeviceIoControl`, `CreateFileA`). Medium-high
   confidence in the API usage itself; the genuinely new design point (not
   a portability risk, a real architecture decision) is that this service
   needs two threads where Linux's daemon needs one — see the comment at
   the top of `otp_firewall_svc.c` for why, and the resulting
   `CRITICAL_SECTION` covering every `g_keychain`/`FwContext` access.

Treat this the same way the Linux kernel module was treated before it was
ever built: a careful, best-effort starting point that needs real WDK
test-signing hardware and a kernel debugger to finish, not a working
deliverable.

## What's reused unmodified vs. what's new

`cipher.c`/`keychain.c`/`commit.c` need **zero changes** — `src/compat.h`
already branches cleanly on `_WIN32` vs. real POSIX, and this project's own
`make mingw` target already proves out warning-free MinGW-w64
cross-compilation of the core library.

Of `firewall/daemon/`'s own files, small additive `#ifdef _WIN32` guards
(header swaps, `gmtime_s` vs. `gmtime_r`, `_mkdir`/`_chdir`,
`CreateSymbolicLinkA` in place of `symlink()`) were enough to make these
build for Windows too — reused **directly, unmodified beyond those
guards**:

- `common.h`, `checksum.h`/`.c`, `config.h`/`.c`, `pin.h`/`.c`,
  `trial.h`/`.c`, `keychain_setup.h`/`.c`, `log.h`/`.c`,
  `packet_codec.h`, `kernel_ctl.h` (just the headers where only a `.c`
  needed a platform-specific body)

...and compile **instead of** `firewall/daemon/packet_codec.c` and
`firewall/daemon/kernel_ctl.c` respectively:

- `Shared/packet_codec_windows.c` — same public API as `packet_codec.h`,
  but with this project's own `#pragma pack(push,1)` IPv4/IPv6/TCP/UDP
  wire-format structs instead of relying on any OS-provided header (Windows
  has no standard `struct iphdr`/`struct ip` the way POSIX systems do).
- `Service/kernel_ctl_windows.c` — same public API as `kernel_ctl.h`, but
  pushes the candidate IP set to `\\.\OTPFirewall` via `DeviceIoControl`
  instead of writing text to a `/proc` file.

New for Windows, in this directory:

- `Driver/otp_firewall_protocol.h` — the wire format shared verbatim by
  the driver and every userspace consumer (dependency-free: just
  `<stdint.h>`, so it compiles unchanged in kernel and usermode
  translation units).
- `Driver/otp_firewall_driver.h`/`.c` — the WFP callout driver itself: the
  Windows equivalent of `firewall/linux-kernel-module/otp_firewall.c`.
  Candidate-IP table, the kernel-side ICMPv6 exemption
  (`OtpFwIsIcmpv6()` — Neighbor Discovery is exempted here, in the kernel
  fast path, never in userspace, exactly mirroring where the Linux
  module's own exemption lives), the kill switch, and the packet
  pend/queue/verdict machinery.
- `Service/otp_firewall_svc.c` — the userspace Windows Service playing
  `firewall/daemon/main.c`'s role: startup, config/keychain reload, and
  the loop moving packets between the driver and the codec/cipher/keychain
  code.
- `Ctl/otpfwctl.c` — `otpfwctl.exe {enable|disable|status}`, the kill
  switch control utility (see below).

## Kill switch

Unlike Linux's `/proc/otp_firewall/enabled` (a plain file any shell can
`echo`/`cat`) and unlike macOS (which has **no** equivalent — see that
port's README), Windows gets a small dedicated tool: `otpfwctl.exe`, talking
to the driver directly over the same `\\.\OTPFirewall` device the service
uses, via `OTP_FW_IOCTL_SET_ENABLED`/`GET_ENABLED`. It does not touch the
service at all — the driver's kill switch and the service's own
running/stopped state are independent, same as `insmod`-without-`echo 1`
being independent of whether `otp-firewalld` happens to be running on
Linux. **The driver loads with enforcement off by default** (fail-open
passthrough) — an operator must explicitly run `otpfwctl.exe enable` after
confirming the driver and service are both healthy, never the reverse.

## Setup: building and loading, test-signing only

**This project deliberately does not enroll in Microsoft's driver-signing
program.** Production driver signing requires an EV code-signing
certificate and submitting the driver to the Microsoft Hardware Dev Center
for attestation signing — real cost, real paperwork, and a review process
outside this project's scope. Instead, the steps below use Windows'
built-in **test-signing mode**, which lets a self-signed driver load on a
machine that has explicitly opted into it. This is standard practice for
driver development and is entirely something you run yourself, on your own
machine — there is nothing here to submit to Microsoft or wait on.

1. **Install the WDK** (Windows Driver Kit) matching your installed Visual
   Studio version, and build `Driver/` as a KMDF/WDM driver project
   (`.inf`/`.sys`) — no project file is included here, same reasoning as
   the macOS port's missing `.xcodeproj`: hand-generating one unverified
   seemed more likely to produce something that fails to load in Visual
   Studio than something useful. Create a new "Empty WDM Driver" project
   and add `Driver/otp_firewall_driver.c`/`.h` and
   `Driver/otp_firewall_protocol.h` as source.
2. **Enable test signing** (as Administrator, then reboot):
   ```
   bcdedit /set testsigning on
   ```
   If Secure Boot is enabled, it will block test-signed drivers regardless
   of this setting — disable Secure Boot in your machine's UEFI firmware
   settings first. (This is a genuine security tradeoff on the machine
   you're testing on, not a formality — see "Known gaps" below.)
3. **Create a self-signed certificate** and sign the built `.sys` (in an
   elevated PowerShell / Developer Command Prompt):
   ```powershell
   $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=OTP Firewall Test" `
     -KeyUsage DigitalSignature -FriendlyName "OTP Firewall Test Cert" `
     -CertStoreLocation "Cert:\CurrentUser\My" `
     -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3","2.5.29.19={text}")
   Export-Certificate -Cert $cert -FilePath otpfw_test.cer
   Import-Certificate -FilePath otpfw_test.cer -CertStoreLocation "Cert:\LocalMachine\Root"
   Import-Certificate -FilePath otpfw_test.cer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"
   signtool sign /v /s My /n "OTP Firewall Test" /fd SHA256 otp_firewall_driver.sys
   ```
4. **Install and start the driver**:
   ```
   sc create OTPFirewall type= kernel binPath= "C:\path\to\otp_firewall_driver.sys"
   sc start OTPFirewall
   ```
5. **Build and register the service and control tool**: compile
   `Service/otp_firewall_svc.c` (plus the reused `firewall/daemon/*` files
   and `Shared/packet_codec_windows.c`, same file list as the macOS setup
   section but for a normal Win32 console/service project instead of
   Xcode) into `otp_firewall_svc.exe`, and `Ctl/otpfwctl.c` into
   `otpfwctl.exe`.
   ```
   sc create OTPFirewallSvc binPath= "C:\path\to\otp_firewall_svc.exe" start= demand
   sc start OTPFirewallSvc
   ```
6. **Verify and enable**:
   ```
   otpfwctl.exe status
   otpfwctl.exe enable
   otpfwctl.exe status
   ```
7. **To unload**: `otpfwctl.exe disable`, then `sc stop OTPFirewallSvc`,
   `sc stop OTPFirewall`, `sc delete OTPFirewallSvc`, `sc delete OTPFirewall`.
8. **To revert test-signing mode** once you're done (re-enables normal
   signature enforcement and lets you turn Secure Boot back on):
   ```
   bcdedit /set testsigning off
   ```
   then re-enable Secure Boot in firmware settings and reboot.

## Configuration

Same files, same format, same location as the Linux daemon — see
`docs/FIREWALL.md`. `~/.otp/firewall_keychain/` (via `%USERPROFILE%` when
`$HOME` isn't set — see `keychain_setup.c`'s `_WIN32` branch),
`~/.otp/firewall.config`, `~/.otp/authorized.log`, `~/.otp/restricted.log`
all work the same way, since `config.c`/`log.c` need only header-swap
guards, no logic changes. One genuine platform difference: creating the
`.keychain -> firewall_keychain` link needs either Administrator rights or
Windows 10+'s Developer Mode enabled (Settings > Privacy & Security > For
developers) — unprivileged symlink creation is not available by default on
Windows the way it is on POSIX. `otp_fw_setup_keychain_dir()` surfaces this
as an actionable error (`ERROR_PRIVILEGE_NOT_HELD`) rather than failing
silently.

## Known gaps beyond the "unverified" list above

- **Secure Boot must be disabled** for test-signed drivers to load at all
  — a real, machine-wide security reduction for as long as you're testing
  this driver, not just a one-line command. Revert it (step 8 above) when
  you're done.
- **No equivalent of the Linux daemon's test suite.**
  `firewall/linux-kernel-module/tests/` builds and runs against a real
  POSIX toolchain (this Linux sandbox); nothing here has been exercised
  the same way, because there's no WDK/MSVC toolchain available in this
  environment at all.
- **IPv6 extension header walking, IP fragmentation**: same v1 scope
  limits as the other two platforms (see `docs/FIREWALL.md`), not
  re-verified for the WFP packet-layer path here — the driver's classify
  function reads the IPv6 Next Header field directly rather than walking
  extension headers to find the real upper-layer protocol.
- **`NdisGetDataBuffer`'s multi-MDL (non-contiguous) case is not
  implemented**, only flagged inline in `OtpFwClassifyCommon()` — a real
  implementation needs `NdisCopyFromNetBufferList` into the packet's own
  heap buffer rather than assuming a single contiguous buffer view is
  always available.
