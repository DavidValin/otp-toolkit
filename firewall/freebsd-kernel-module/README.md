# OTP-toolkit Firewall — FreeBSD

A genuine kernel module (`otp_firewall.ko`, built via FreeBSD's own KLD
framework — no deprecation story here the way macOS's KEXTs have) plus a
userspace background daemon (`otp_firewalld`) and control CLI (`otpfwctl`), talking to each
other over a custom character device (`/dev/otp_firewall`). For what the
firewall actually does — what gets encrypted, how a packet is
authenticated, what gets logged — see [`../README.md`](../README.md).
This page covers building, configuring, and turning the FreeBSD port on
and off.

## Status: what's verified and what isn't

**None of the kernel-mode code in this directory has been compiled or
loaded** — this was written without access to a FreeBSD machine or its
kernel headers/source tree. The userspace daemon and control CLI are the
exception (see item 7 below): they compile, link, and run successfully on
Linux against the real `otp` library, which is the most verification
possible without a real FreeBSD machine. In descending order of how much
the remaining uncertainty matters:

1. **The exact `pfil(9)` registration KPI.** This file targets the
   FreeBSD 14 KPI (`pfil_head_get()` + `struct pfil_hook_args`/
   `pfil_link()`). FreeBSD 11–13 used an older, simpler
   `pfil_add_hook(pfil_func_t, arg, flags, head)` signature directly —
   if building against an older base, `otp_fw_register_pfil()` needs
   adjusting to that signature (the hook function bodies themselves
   don't change).
2. **A known structural bug, left in deliberately rather than silently
   glossed over:** `otp_fw_pending`'s single `link` `TAILQ_ENTRY` is
   reused for both the ready-queue and the in-flight-by-`packet_id`
   table in `otp_fw_hook()` — inserting the same node onto two different
   `TAILQ`s with one linkage field corrupts both lists the moment either
   remove call runs. A real build needs two separate `TAILQ_ENTRY`
   fields here before this is safe to load, the same class of bug the
   Windows port's `OTP_FW_PENDED_PACKET` has and documents for the same
   reason.
3. **Packet reinjection via `ip_output()`/`ip6_output()` (outbound) and
   `netisr_dispatch()` (inbound)** — both are long-stable, well-documented
   FreeBSD KPIs used throughout the base kernel for exactly this "hand a
   packet back to the stack from other kernel code" need, genuinely
   higher confidence than the Windows port's `FwpsInject*` reconstruction
   (Windows has no equivalently well-trodden public API for this). The
   specific argument shapes used here (`ip_output()`'s route/inpcb/flags
   arguments in particular) were not checked against a real header.
4. **Loop avoidance via `M_SKIP_FIREWALL`.** This is the same mbuf flag
   `pf`/`ipfw` set on packets they've already processed, for exactly this
   "don't re-evaluate a packet I just reinjected" reason — the mechanism
   is standard, but this specific usage of it was not tested.
5. **The character device (`cdevsw`, `d_open`/`d_read`/`d_write`/
   `d_ioctl`), the `cv_wait`/`cv_signal`-based queue, the candidate
   table, and the sysctl kill switch** — ordinary, well-documented
   FreeBSD device-driver patterns (the same shape `/dev/bpf` and similar
   drivers use). Highest-confidence part of the module.
6. **`Shared/packet_codec.c`** — the highest-confidence file
   dealing with wire-format bytes in this port: glibc (on the Linux
   machine this was written on) optionally provides the same BSD-compat
   `struct ip`/`struct tcphdr`/`struct udphdr` definitions FreeBSD uses
   natively (via `__FAVOR_BSD`/`__USE_MISC`), which let this file
   compile and run against `firewall/linux-kernel-module/tests/test_packet_codec.c`'s
   full 78-check suite unmodified, all passing. That run caught a real
   bug shared with the macOS port this file was based on (both now
   fixed): `resolve_egress_contact()` wasn't setting `*contact_out`
   before returning `OTP_FW_KEY_EXHAUSTED`/`OTP_FW_PENDING_RECOVERY`,
   so a `restricted.log` entry for an exhausted or pending-recovery
   contact would log `-` instead of the contact's name. This is still
   not the same as running on real FreeBSD (glibc's BSD-compat structs
   and FreeBSD's native ones could still diverge in some field this
   test suite doesn't exercise), but it's meaningfully more verified
   than everything else in this port.
7. **The entire userspace side** (`otp_firewalld.c`,
   `kernel_ctl.c`, plus `ack.h`/`.c` — the delivery-acknowledgment
   mechanism, see [`../README.md`'s "Delivery
   acknowledgment"](../README.md#delivery-acknowledgment)) is the most
   verified part of this entire port, not just reasoned about: with
   `<sys/ioccom.h>` stubbed out (the one genuinely FreeBSD-only header
   this code touches, since `ioctl(2)` command-encoding macros differ
   from Linux's) it compiles warning-free and **links successfully**
   against the real `cipher.c`/`keychain.c`/`commit.c` on this Linux
   machine, runs (including a real call to `ack_recover_outstanding()` on
   startup, per its identical wiring on every platform), opens both
   delivery-ack sockets without error, and fails at exactly the expected
   point (`/dev/otp_firewall` doesn't exist here, since the kernel module
   can't be loaded outside FreeBSD). `ack.c`'s own table logic — including
   crash/restart recovery, exercised with the real `otp` library, not
   mocks — is additionally covered by
   `firewall/linux-kernel-module/tests/test_ack.c` (10,000+ checks,
   reused unmodified). What a link test can't confirm is the one thing
   that's genuinely FreeBSD-specific here: whether the real `ioctl(2)`
   command values (built from `_IOW`/`_IOR` in `otp_firewall_proto.h`)
   actually match what the kernel side expects.

Treat this the same way the Windows and macOS ports were treated before
ever being built: a careful, best-effort starting point that needs a real
FreeBSD machine and its kernel source tree to finish, not a working
deliverable.

## Architecture

```
                         ┌────────────────────────────────────────┐
                         │   otp_firewall.ko  (KLD, kernel mode)   │
                         │                                        │
  outgoing packet ───────►  known destination? ─ no ──► blocked   │
                         │           │ maybe                      │
                         │           ▼                            │
  incoming packet ───────►  known source? ─ no ──► blocked        │
                         │           │ maybe                      │
                         │           ▼                            │
                         │  ICMPv6? ─ yes ──► pass through as-is  │
                         └───────────┼────────────────────────────┘
                                     │ /dev/otp_firewall (custom read/write/ioctl queue)
                         ┌───────────▼────────────────────────────┐
                         │   otp_firewalld  (daemon,               │
                         │   userspace)                            │
                         │                                        │
                         │  outgoing: encrypt for the matched      │
                         │  contact, or block if none is matched   │
                         │                                        │
                         │  incoming: try to decrypt against your  │
                         │  contacts' keys; allow through on the   │
                         │  first one that works, otherwise block  │
                         └────────────────────────────────────────┘
```

The module registers `pfil(9)` hooks at IPv4/IPv6 input and output. It
keeps a small in-kernel table of candidate IPs (pushed by the daemon) and
drops anything that obviously doesn't match without ever queuing it to
userspace; anything that might be relevant is consumed from the normal
packet path and handed to the daemon over `/dev/otp_firewall` for the
actual encrypt/decrypt decision, then reinjected on verdict. IPv6
Neighbor Discovery is exempted directly in the module and never reaches
the daemon at all - so is the daemon's own delivery-acknowledgment
traffic (see [`../README.md`'s "Delivery
acknowledgment"](../README.md#delivery-acknowledgment)), a small UDP
side channel on a fixed port the module lets through untouched in both
directions.

## What's identical to Linux vs. what's new

Every platform's firewall code lives entirely in its own directory now —
there is no shared `firewall/daemon/` directory anywhere in this
repository. Instead, the platform-agnostic daemon-support files started
as Linux's implementation and are duplicated, filename-for-filename, into
every platform's own folder; keeping them byte-identical across platforms
(verified by diffing against Linux's copies) is a convention this project
follows, not something the build system enforces.

`cipher.c`/`keychain.c`/`commit.c` (from `src/`, one directory further up)
need **zero changes** — `src/compat.h` already branches purely on `_WIN32`
vs. real POSIX, and FreeBSD is genuine POSIX.

Of the daemon-support files in this directory, everything is pure POSIX C
with no Linux-specific dependencies **except** `packet_codec.c` (Linux/glibc
struct field names) and `kernel_ctl.c` (writes to a Linux `/proc` file) and
`otp_firewalld.c` (NFQUEUE-specific) — Linux's own versions of those three.
These files are byte-identical to Linux's copies, unmodified:

- `common.h`, `checksum.h`/`.c`, `config.h`/`.c`, `pin.h`/`.c`,
  `trial.h`/`.c`, `keychain_setup.h`/`.c`, `log.h`/`.c`, `ack.h`/`.c`
  (the delivery-acknowledgment mechanism — see [`../README.md`'s
  "Delivery acknowledgment"](../README.md#delivery-acknowledgment)),
  `packet_codec.h`, `kernel_ctl.h` (just the headers — their declared
  APIs have no platform-specific types)

...and this directory provides FreeBSD-specific bodies for the three that
need one, named identically to their Linux counterparts (no `_freebsd`
suffix — the containing directory is what identifies the platform now):

- `Shared/packet_codec.c` — same public API as `packet_codec.h`,
  BSD header field names (see the Status section above).
- `kernel_ctl.c` — same public API as `kernel_ctl.h`, pushes
  candidates via `ioctl(OTP_FW_IOC_SET_CANDIDATES)` instead of a
  `/proc` write.
- `otp_firewalld.c` — plays Linux's `otp_firewalld.c`'s role, reading/writing
  `/dev/otp_firewall` instead of an NFQUEUE socket.

New for FreeBSD, in this directory:

- `otp_firewall_proto.h` — the wire format shared verbatim by the kernel
  module and userspace, since FreeBSD's kernel and userspace C
  environments (unlike Windows') are compatible enough that one header
  works for both sides without a special dependency-free split.
- `otp_firewall.c` — the KLD itself: `pfil(9)` hooks, the character
  device, the candidate table, the kill switch, and the packet
  queue/verdict/reinject machinery.
- `otpfwctl.c` — the kill-switch control utility, named the same as every
  other platform's control CLI.

## Compile

### 1. Install the kernel source/headers

The module needs to be built against your exact running kernel's build
tree — normally already present at `/usr/src` on a FreeBSD install, or
installable via:

```
sudo pkg install freebsd-src   # FreeBSD 14+
```

### 2. Build the kernel module

```
cd firewall/freebsd-kernel-module
make
```

Produces `otp_firewall.ko`. See the Status section above regarding the
`pfil(9)` KPI version sensitivity if this is built against FreeBSD 11–13.

### 3. Build the daemon and control tool

Everything the daemon needs lives directly in this directory now — no
other directory's sources are involved except the core library in `src/`.
From the repository root:

```
cc -O2 -Wall -Isrc -Ifirewall/freebsd-kernel-module \
   -o otp_firewalld \
   firewall/freebsd-kernel-module/otp_firewalld.c \
   firewall/freebsd-kernel-module/kernel_ctl.c \
   firewall/freebsd-kernel-module/Shared/packet_codec.c \
   firewall/freebsd-kernel-module/config.c firewall/freebsd-kernel-module/pin.c \
   firewall/freebsd-kernel-module/trial.c firewall/freebsd-kernel-module/checksum.c \
   firewall/freebsd-kernel-module/log.c firewall/freebsd-kernel-module/keychain_setup.c \
   firewall/freebsd-kernel-module/ack.c \
   src/cipher.c src/keychain.c src/commit.c

cc -O2 -Wall -Ifirewall/freebsd-kernel-module \
   -o otpfwctl firewall/freebsd-kernel-module/otpfwctl.c
```

## Configure

### 1. Set up your contacts

The firewall uses its own keychain, kept separate from any keychain you
use for everyday `otp` encrypt/decrypt work, at `~/.otp/firewall_keychain`.
Add a contact the normal way, from inside `~/.otp`:

```
cd ~/.otp
otp -nk 100 me alice       # generates a mirrored one-time-pad key pair for you and alice
otp -ac alice <enc-key-file> <dec-key-file>   # add alice as a contact using her half
```

Send your contact their half of the key pair through a trusted channel
out of band, and have them do the equivalent on their end.

### 2. Tell the firewall which addresses belong to which contact

Create `~/.otp/firewall.config` — see [`../README.md`'s "Configuration
file format"](../README.md#configuration-file-format) for the exact
format.

## Activate

### 1. Load the kernel module

```
sudo kldload ./otp_firewall.ko
```

(or `sudo make load` from this directory). The module starts
**disabled** — nothing about your network changes yet. Confirm it
loaded:

```
kldstat | grep otp_firewall
sysctl net.otp_firewall.enabled
```

### 2. Start the background daemon

Start it in log-only mode first, so you can see what it *would* do
before it can actually block anything:

```
sudo ./otp_firewalld --mode=log-only
```

Watch `~/.otp/authorized.log` and `~/.otp/restricted.log` (see
[`../README.md`'s "Log format"](../README.md#log-format)) to confirm
it's making the decisions you expect. When you're satisfied, restart it
in enforcing mode:

```
sudo ./otp_firewalld --mode=enforce
```

Full flag list: `otp_firewalld --help`. Notably: `--config=PATH`
to use a config file other than `~/.otp/firewall.config`, and
`--resolve-interval=SECONDS` to change how often `firewall.config`
hostnames are re-resolved (60s by default).

### 3. Turn the firewall on

Enforcement is a separate step from loading the module and starting the
daemon, so you always have a fast way back if something looks wrong:

```
sudo ./otpfwctl enable
```

or, equivalently, directly via sysctl:

```
sudo sysctl net.otp_firewall.enabled=1
```

## Deactivate

```
sudo ./otpfwctl disable
```

or:

```
sudo sysctl net.otp_firewall.enabled=0
```

Either takes effect immediately, on the very next packet, and doesn't
require restarting the daemon or unloading the kernel module — it's the
fastest way to get your normal network back if anything looks wrong.

To fully remove it:

```
sudo kldunload otp_firewall
```

This unloads the kernel module (which also turns enforcement off, and
drains any packets still queued at unload time — see `otp_fw_modevent()`'s
`MOD_UNLOAD` handler). Then stop `otp_firewalld` however you
started it (`Ctrl-C`, an rc.d script, etc.).
