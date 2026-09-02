# OTP-toolkit Firewall — Windows

A kernel-mode WFP (Windows Filtering Platform) callout driver plus a
background Windows Service, talking to each other over a custom IOCTL
device (`\\.\OTPFirewall`). For what the firewall actually does — what
gets encrypted, how a packet is authenticated, what gets logged — see
[`../README.md`](../README.md). This page covers building, test-signing,
configuring, and turning the Windows port on and off.

## Why a custom callout driver, not WinDivert or ALE

Two existing, more established alternatives were deliberately not used.
[WinDivert](https://github.com/basil00/Divert) is a pre-built, pre-signed
WFP-based packet capture library — using it would have meant the
kernel-mode piece of this port wasn't actually this project's own code.
The lighter-weight ALE layer (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`) only
supports connection-level allow/block decisions, not access to packet
payloads — it can't do the OTP wrap/unwrap this firewall needs. So this is
a genuine custom callout driver registered at the IP packet layer
(`FWPM_LAYER_{OUTBOUND,INBOUND}_IPPACKET_V{4,6}`), with real packet-level
modification capability.

## Status: what's verified and what isn't

**Nothing in this directory has been compiled, signed, or run.** This was
written in a Linux sandbox with no Windows Driver Kit (WDK), no MSVC, and
no way to check any of it against real WDK headers, a kernel debugger, or
a real Windows machine. It has been through one round of independent code
review (10 findings, all fixed — see git history), which caught a real
build-breaking bug (invalid C in `DriverEntry`) and a real security issue
(the keychain-link validation accepted any junction whose target directory
happened to share a name with the expected one); review can catch issues
like that but cannot substitute for actually compiling and running this. In
descending order of how much the remaining uncertainty matters:

1. **`Driver/otp_firewall_driver.c`'s classify pend/clone/reinject path**
   (`FwpsPendOperation0`, `FwpsAllocateCloneNetBufferList0`,
   `FwpsCompleteOperation0`, `FwpsInjectNetworkSendAsync0`/
   `FwpsInjectNetworkReceiveAsync0`) — a from-scratch reconstruction of the
   documented "data-modifying callout" pattern, explicitly flagged inline
   (search that file for "CONFIDENCE: LOWEST") everywhere it's a sketch
   rather than a finished call. This is the single riskiest piece of this
   port.
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
4. **`Driver/otp_toolkit_firewall.h`, the IOCTL dispatch, the IO_CSQ-based
   pending-read queue, and the candidate table** — ordinary, well-trodden
   WDM patterns (`IoCreateDevice`, `IRP_MJ_DEVICE_CONTROL`,
   `IoCsqInitializeEx`, a spinlock-protected array). Highest-confidence part
   of the driver.
5. **`Service/otp_firewall_svc.c` and `Ctl/otpfwctl.c`** — ordinary Win32
   (SCM service boilerplate, `DeviceIoControl`, `CreateFileA`). Medium-high
   confidence in the API usage itself; the genuinely new design point (not
   a portability risk, a real architecture decision) is that the service
   needs three threads — a blocking `DeviceIoControl` call has no
   signal-interrupt equivalent to lean on for periodic config reload or
   for driving the delivery-ack mechanism (see below), so a dedicated
   thread handles each, and every access to the shared keychain/config
   state is serialized with an explicit `CRITICAL_SECTION`.
6. **`ack.h`/`.c`** (the delivery-acknowledgment mechanism — see
   [`../README.md`'s "Delivery acknowledgment"](../README.md#delivery-acknowledgment))
   is reused completely unmodified from `firewall/daemon/` — its table
   logic, including crash/restart recovery via `ack_recover_outstanding()`
   (exercised with the real `otp` library, not mocks), is covered by
   `firewall/linux-kernel-module/tests/test_ack.c` (10,000+ checks
   passing as part of the Linux daemon's own test suite), and its
   `_WIN32`-guarded WinSock socket calls (`ack_socket_open()`
   etc.) follow the same patterns already established elsewhere in this
   port. What's specifically unverified here is the Windows-side wiring
   around it: the driver's ack-port exemption (item 2 above covers the
   general WFP registration risk it shares) and `AckThreadProc`'s use of
   WinSock's `select()`.

Treat this as a careful, best-effort starting point that needs real WDK
test-signing hardware and a kernel debugger to finish, not a working
deliverable.

## Architecture

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

The driver keeps a small in-kernel table of candidate IPs (pushed by the
service) and drops anything that obviously doesn't match without ever
queuing it to userspace; anything that might be relevant is pended and
handed to the service over `\\.\OTPFirewall` for the actual encrypt/decrypt
decision. IPv6 Neighbor Discovery is exempted directly in the driver
(`OtpFwIsIcmpv6()`) and never reaches the service at all - so is the
service's own delivery-acknowledgment traffic (see [`../README.md`'s
"Delivery acknowledgment"](../README.md#delivery-acknowledgment)), a
small UDP side channel on a fixed port the driver's classify function
lets through untouched in both directions.

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
  `trial.h`/`.c`, `keychain_setup.h`/`.c`, `log.h`/`.c`, `ack.h`/`.c`
  (the delivery-acknowledgment mechanism, including its `_WIN32`-guarded
  WinSock socket calls), `packet_codec.h`, `kernel_ctl.h` (just the
  headers where only a `.c` needed a platform-specific body)

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

- `Driver/otp_toolkit_firewall.h` — the wire format shared verbatim by
  the driver and every userspace consumer (dependency-free: just
  `<stdint.h>`, so it compiles unchanged in kernel and usermode
  translation units).
- `Driver/otp_firewall_driver.h`/`.c` — the WFP callout driver itself:
  candidate-IP table, the kernel-side ICMPv6 and delivery-ack-port
  exemptions, the kill switch, and the packet pend/queue/verdict
  machinery.
- `Service/otp_firewall_svc.c` — the userspace Windows Service: startup,
  config/keychain reload, the loop moving packets between the driver
  and the codec/cipher/keychain code, and a third thread
  (`AckThreadProc`) driving `ack.h`'s delivery-acknowledgment mechanism
  via WinSock's `select()`.
- `Ctl/otpfwctl.c` — `otpfwctl.exe {enable|disable|status}`, the kill
  switch control utility (see "Deactivate" below).

## Compile

### 1. Build the driver

Install the WDK matching your installed Visual Studio version, and build
`Driver/` as a KMDF/WDM driver project (`.inf`/`.sys`) — no project file is
included here, since hand-generating one unverified seemed more likely to
produce something that fails to load in Visual Studio than something
useful. Create a new "Empty WDM Driver" project and add
`Driver/otp_firewall_driver.c`/`.h` and `Driver/otp_toolkit_firewall.h` as
source.

### 2. Build the service and control tool

Compile `Service/otp_firewall_svc.c` (plus the reused `firewall/daemon/*`
files listed above and `Shared/packet_codec_windows.c`, `Service/kernel_ctl_windows.c`)
into `otp_firewall_svc.exe` using a normal Win32 console/service project,
and `Ctl/otpfwctl.c` into `otpfwctl.exe`. `Shared/packet_codec_windows.c`
uses `fmemopen()`/`open_memstream()` (POSIX.1-2008), which MinGW-w64
provides but raw MSVC's CRT does not — building the service with MinGW
(the same toolchain this project's own `make mingw` target already
cross-compiles the core library with) is assumed throughout that file.

## Test-sign and load the driver

**This project deliberately does not enroll in Microsoft's driver-signing
program.** Production driver signing requires an EV code-signing
certificate and submitting the driver to the Microsoft Hardware Dev Center
for attestation signing — real cost, real paperwork, and a review process
outside this project's scope. Instead, the steps below use Windows'
built-in **test-signing mode**, which lets a self-signed driver load on a
machine that has explicitly opted into it. This is standard practice for
driver development and is entirely something you run yourself, on your own
machine — there is nothing here to submit to Microsoft or wait on.

1. **Enable test signing** (as Administrator, then reboot):
   ```
   bcdedit /set testsigning on
   ```
   If Secure Boot is enabled, it will block test-signed drivers regardless
   of this setting — disable Secure Boot in your machine's UEFI firmware
   settings first. (This is a genuine security tradeoff on the machine
   you're testing on, not a formality — see "Known gaps" below.)
2. **Create a self-signed certificate** and sign the built `.sys` (in an
   elevated PowerShell / Developer Command Prompt):
   ```powershell
   $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=OTP-toolkit Firewall Test" `
     -KeyUsage DigitalSignature -FriendlyName "OTP-toolkit Firewall Test Cert" `
     -CertStoreLocation "Cert:\CurrentUser\My" `
     -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3","2.5.29.19={text}")
   Export-Certificate -Cert $cert -FilePath otpfw_test.cer
   Import-Certificate -FilePath otpfw_test.cer -CertStoreLocation "Cert:\LocalMachine\Root"
   Import-Certificate -FilePath otpfw_test.cer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"
   signtool sign /v /s My /n "OTP-toolkit Firewall Test" /fd SHA256 otp_firewall_driver.sys
   ```
3. **Install and start the driver**:
   ```
   sc create OTPFirewall type= kernel binPath= "C:\path\to\otp_firewall_driver.sys"
   sc start OTPFirewall
   ```
   The driver starts **disabled** — nothing about your network changes yet.

## Configure

Same files, same format, same location described in
[`../README.md`](../README.md): `~/.otp/firewall_keychain/` (via
`%USERPROFILE%` when `$HOME` isn't set — see `keychain_setup.c`'s `_WIN32`
branch), `~/.otp/firewall.config`, `~/.otp/authorized.log`,
`~/.otp/restricted.log` all work as documented there, since `config.c`/
`log.c` need only header-swap guards, no logic changes. One genuine
platform wrinkle: creating the `.keychain -> firewall_keychain` link needs
either Administrator rights or Windows 10+'s Developer Mode enabled
(Settings > Privacy & Security > For developers) — unprivileged symlink
creation is not available by default on Windows. `otp_fw_setup_keychain_dir()`
surfaces this as an actionable error (`ERROR_PRIVILEGE_NOT_HELD`) rather
than failing silently. Manage contacts the normal way, from inside `~/.otp`:

```
otp -nk 100 me alice
otp -ac alice <enc-key-file> <dec-key-file>
```

## Activate

### 1. Start the service

```
sc create OTPFirewallSvc binPath= "C:\path\to\otp_firewall_svc.exe" start= demand
sc start OTPFirewallSvc
```

### 2. Turn the firewall on

Enforcement is a separate step from loading the driver and starting the
service, so you always have a fast way back if something looks wrong:

```
otpfwctl.exe status    # check current state
otpfwctl.exe enable    # turn on
```

`otpfwctl.exe` talks to the driver directly over `\\.\OTPFirewall`; it does
not touch the service at all.

## Deactivate

```
otpfwctl.exe disable   # turn off instantly
otpfwctl.exe status    # confirm
```

This takes effect immediately and doesn't require stopping the service or
unloading the driver — it's the fastest way to get your normal network back
if anything looks wrong.

To fully remove it:

```
otpfwctl.exe disable
sc stop OTPFirewallSvc
sc stop OTPFirewall
sc delete OTPFirewallSvc
sc delete OTPFirewall
```

Then, if you're done testing, revert test-signing mode
(`bcdedit /set testsigning off`) and re-enable Secure Boot.

## Known gaps beyond the "what's verified" list above

- **Secure Boot must be disabled** for test-signed drivers to load at all
  — a real, machine-wide security reduction for as long as you're testing
  this driver, not just a one-line command. Revert it (see "Deactivate"
  above) when you're done.
- **No test suite.** Nothing here has been exercised the way
  `firewall/linux-kernel-module/tests/` exercises the Linux daemon's code,
  because there's no WDK/MSVC toolchain available in the environment this
  was written in at all.
- **IPv6 extension header walking, IP fragmentation**: same scope limits
  described in [`../README.md`'s "Limitations"](../README.md#limitations),
  not re-verified for the WFP packet-layer path here — the driver's
  classify function reads the IPv6 Next Header field directly rather than
  walking extension headers to find the real upper-layer protocol.
- **`NdisGetDataBuffer`'s multi-MDL (non-contiguous) case is not
  implemented**, only flagged inline in `OtpFwClassifyCommon()` — a real
  implementation needs `NdisCopyFromNetBufferList` into the packet's own
  heap buffer rather than assuming a single contiguous buffer view is
  always available.
