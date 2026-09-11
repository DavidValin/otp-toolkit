# OTP-toolkit Firewall — OpenBSD

A real kernel-resident hook, statically compiled into a custom OpenBSD
kernel (`kernel/otpfw.c`, patched into `ip_input.c`/`ip_output.c`/
`ip6_input.c`/`ip6_output.c` - see "Kernel integration" below), plus a
userspace background daemon (`otp_firewalld`) and control CLI
(`otpfwctl`), talking to each other over a custom character device
(`/dev/otpfw`). For what the firewall actually does — what gets
encrypted, how a packet is authenticated, what gets logged — see
[`../README.md`](../README.md). This page covers building (both the
kernel patch and the userspace pieces), configuring, and turning the
OpenBSD port on and off.

**Target: OpenBSD 7.9** (released 2026-05-19, confirmed via a live web
lookup while writing this — the actual current release, not a guess).
This patch is version-specific, not portable-by-construction the way the
userspace-only ports are: it assumes the `pf_test()`/`pf_test6()` call
sites in `ip_output.c`/`ip_input.c`/`ip6_output.c`/`ip6_input.c` and the
mbuf/`tsleep`/`cdevsw` kernel APIs it uses look the way they did in that
release. Porting to a different release means re-checking every item in
the Status section below against that release's actual kernel source,
not just applying this directory's files as-is; rename the directory
(and update this line) if you do.

Naming 7.9 is *not* a claim that anything below was checked against it —
this project's knowledge predates 7.9's release, so nothing here reflects
specific knowledge of it. Every kernel-API assumption in `kernel/otpfw.c`
comes from general, long-stable BSD conventions instead, the same basis
this patch would rest on no matter which recent release it named. Read
the version number as "verify the patch against this release before
trusting it," not "this was verified against this release" — if
anything, the gap between what this project knows and 7.9's actual state
is larger than it would be for an older release.

## Why this is a kernel patch, not a loadable module

Every other platform with a real kernel-level hook (Linux, Windows,
FreeBSD) has one core file that gets **loaded** into a running kernel -
`insmod`, `kldload`, `sc.exe start`. OpenBSD has nothing equivalent to
load in the first place: the old loadable kernel module framework
(`lkm(4)`, `modload(8)`/`modunload(8)`) was removed from the OpenBSD
kernel in OpenBSD 5.7 (2015), and nothing replaced it — there is no
supported way to load arbitrary third-party code into a running modern
OpenBSD kernel at all. (This is stated from general knowledge of
OpenBSD's history, not verified against a live system in this session -
see the Status section's item 1.)

What OpenBSD does have is the same thing every in-tree pseudo-device
(`pf(4)` itself, `vmm(4)`, `tun`/`tap`, `bpf(4)`) already uses: static
compilation into the kernel binary via `config(8)`, selected by a
`pseudo-device` line in a kernel config file, built from the real kernel
source tree. This port follows that exact pattern instead of inventing
something new:

- **`kernel/otpfw.c`** is a new, self-contained kernel source file — a
  character device (`/dev/otpfw`) modeled directly on `bpf(4)`'s
  `sys/net/bpf.c` (the closest existing in-tree precedent for "a
  pseudo-device that hands whole packets to a userspace process and takes
  a verdict back"), holding the candidate-IP table, the kill switch, the
  pending-packet queue, and the actual encrypt/decrypt hand-off logic.
- **The only patch to OpenBSD's own existing source** is one line each in
  `ip_output.c`, `ip_input.c`, `ip6_output.c`, `ip6_input.c`, placed
  immediately next to the call that's already there for exactly this kind
  of thing: `pf(4)`'s own `pf_test()`/`pf_test6()` — `pf` is not a loaded
  module either, it's wired into those same four functions via one call
  site each. This project's hook is added the same way, as a sibling
  call, not a replacement.
- Everything else (the candidate table, the ICMPv6/ack-port exemptions,
  the pending-packet queue, the kill switch) lives entirely inside
  `otpfw.c`, the same way essentially all of `pf`'s own logic lives in
  `pf.c`, not in `ip_input.c`/`ip_output.c` themselves.

See "Kernel integration" below for the exact, step-by-step patch — this
project does not (and, without a real OpenBSD source tree in hand, cannot
honestly) ship a literal `.patch`/`.diff` file for the four existing
files; what it ships instead is new, self-contained files plus precise
instructions anchored on the `pf_test()`/`pf_test6()` call sites, which
are stable, load-bearing, and guaranteed to exist in any real OpenBSD
kernel source tree.

## Status: what's verified and what isn't

**None of this has been built, loaded, or run on a real OpenBSD
machine** — this was written without access to one, or to OpenBSD's
kernel source tree/headers. In descending order of how much the
remaining uncertainty matters:

1. **Whether OpenBSD genuinely has no loadable-kernel-module mechanism
   left at all**, which this entire port's architecture (a kernel patch
   rather than a loaded module) is premised on. Stated from general
   knowledge (`lkm(4)` removed in OpenBSD 5.7, 2015), not verified live.
   If some narrower module-loading mechanism has been reintroduced since,
   it would likely be a better fit than a kernel patch — worth checking
   before investing in building a custom kernel.
2. **The four kernel-integration patch points and the
   `OTPFW_HOOK_OUT`/`OTPFW_HOOK_IN` call convention.** This project can't
   see the real, current `ip_output.c`/`ip_input.c`/`ip6_output.c`/
   `ip6_input.c` to confirm the `pf_test()`/`pf_test6()` call sites still
   look the way this was written assuming — see "Kernel integration"
   below for exactly what to look for and why that anchor was chosen over
   a literal diff.
3. **`ip_output()`/`ip_input()`/`ip6_output()`/`ip6_input()`'s exact
   signatures**, used for recursive reinjection in `otpfw.c`'s
   `otpfw_apply_verdict()`. Reconstructed from general, long-stable BSD
   networking knowledge, explicitly NOT checked against real
   `<netinet/ip_var.h>`/`<netinet6/ip6_var.h>` — see the pointed-out
   uncertainty directly in `otpfw.c`'s own comments at those declarations
   (`ip6_input()`'s arity in particular is a guess, not a reconstruction).
4. **`msleep_nsec()`/`tsleep_nsec()`, `mtx_enter`/`mtx_leave`,
   `rw_enter_read`/`rw_enter_write`, `mallocarray()`/`malloc(9)`/`free(9)`,
   the mbuf API (`m_pullup`/`m_copydata`/`m_copyback`/`m_gethdr`/
   `m_freem`/`m_length`/`m_tag_get`/`m_tag_find`/`m_tag_delete`/
   `m_tag_prepend`), and `otpfwattach()`/`otpfwopen()`/.../`otpfwioctl()`'s
   `cdevsw` entry-point signatures** in `otpfw.c` — ordinary, believed-
   correct OpenBSD kernel APIs from general knowledge, in the same
   confidence band as the FreeBSD port's own `cdevsw`/`mtx_lock`/mbuf
   calls, but none of it checked against real OpenBSD kernel headers.
5. **An mbuf tag (`OTPFW_MTAG_REINJECTED`, via `m_tag_get()`/
   `m_tag_find()`/`m_tag_delete()`) as this port's loop-avoidance
   marker** — the kernel's own general mechanism for attaching
   transient, subsystem-private metadata to one packet (the same
   category of tool `pf` itself uses its own `PACKET_TAG_PF_*` tags for),
   chosen specifically to avoid the collision risk a shared mbuf flag bit
   like FreeBSD's `M_SKIP_FIREWALL` would carry on OpenBSD, where no
   equivalent fixed-meaning flag exists for this purpose. What's still
   unconfirmed: the exact `m_tag_get()`/`m_tag_prepend()` argument shapes,
   and whether `OTPFW_MTAG_REINJECTED`'s value (a large, arbitrary
   constant, not a small integer) avoids colliding with an in-tree
   `PACKET_TAG_*` constant this port has no way to enumerate without real
   headers.
6. **Hardening added by an independent review pass, unverified the same
   way as the rest of this file (no real kernel to test it against):**
   `otpfw_apply_verdict()` now bounds-checks `v->data_len` before using
   it as an `m_copyback()` length (an unchecked value there could have
   read past `v->data[]`'s end and leaked adjacent kernel memory into a
   reinjected packet) and verifies the copy actually landed via
   `m_length()` before trusting `m->m_pkthdr.len` and reinjecting,
   dropping instead of forwarding a short/failed copy; the pending-packet
   queue is now capped (`OTPFW_MAX_QUEUED`), with new candidate packets
   dropped past the cap rather than growing kernel memory without bound
   if `otp_firewalld` stalls or dies; `otpfwclose()` now drains both
   queues instead of leaking every still-queued node on each daemon
   restart; and `/dev/otpfw` now enforces single-open (`EBUSY` on a
   second concurrent open), which is *also* what makes
   `otpfwread()`/`otpfwwrite()`'s shared `static` buffers safe at all -
   without it, two concurrent openers could race those buffer fills and
   splice one packet's data with another's verdict. `kernel_ctl.c`'s
   candidate-list push buffer was also undersized relative to
   `OTP_FW_MAX_CONFIG_ENTRIES`'s documented maximum (would have silently
   pushed zero candidates - blackholing every contact - for a
   `firewall.config` near that limit) and is now sized from the actual
   constants instead of a round number.
7. **`sys/conf/files` entry and the per-architecture `majors.<arch>`
   `cdevsw` wiring** (see "Kernel integration", steps 2 and 3) —
   `kernel/files.otpfw` is modeled on `bpf(4)`'s own real, well-known
   entry, but not checked against a current `sys/conf/files`. Step 3 is
   the least confident of the whole kernel-integration procedure: unlike
   the FreeBSD port's driver-local `make_dev()`, this project's
   understanding is that OpenBSD's character devices are wired into a
   centrally-assembled `cdevsw` table via `majors.<arch>` and a
   `cdev_decl(otpfw)`-style declaration - genuine general BSD knowledge,
   not confirmed against a current source tree, and specifically not
   confirmed to still be exactly this mechanism on 7.9. If it's changed,
   `otpfw.c`'s `otpfwopen()`/`otpfwclose()`/`otpfwread()`/`otpfwwrite()`/
   `otpfwioctl()` themselves shouldn't need to change - only how they get
   connected to `/dev/otpfw` would.
8. **`otpfwctl.c`, `kernel_ctl.c`, `otp_firewalld.c`, and every
   byte-identical daemon-support file** — the same POSIX
   `open()`/`read()`/`write()`/`ioctl()`/`select()` shape the FreeBSD
   port's userspace pieces use, and verified the same way: this project
   **compiled and linked all of it** (`otp_firewalld` and `otpfwctl`,
   full binaries) against the real `cipher.c`/`keychain.c`/`commit.c` in
   `src/` on this project's Linux build machine, with `<sys/ioccom.h>`
   stubbed out to `<sys/ioctl.h>` (the one genuinely OpenBSD-only header
   this userspace code touches — same workaround, same reasoning, as the
   FreeBSD port's README documents for its own identical situation).
   Both resulting binaries were then actually run, not just linked:
   `otpfwctl status` failed exactly where expected with a clear error
   message, and `otp_firewalld --mode=log-only` (pointed at a scratch
   `$HOME` so it wouldn't touch a real one) ran its full startup sequence
   for real - creating the keychain directory, loading the keychain,
   binding the real delivery-ack UDP socket on port 34443, loading and
   resolving `firewall.config`, attempting (and correctly warning, not
   crashing, on) the candidate push to a nonexistent `/dev/otpfw` - before
   failing at exactly the expected final point, opening `/dev/otpfw`
   itself, with a clear error message. This is the same "runs and fails
   at exactly the expected point" bar the FreeBSD port's own README holds
   its daemon to. This pass did catch one real, since-fixed bug:
   `otp_firewall_proto.h` used
   `uint8_t`/`uint32_t`/`uint64_t` without including `<stdint.h>`,
   relying entirely on `<sys/types.h>` to provide them - true on real
   BSD systems, not reliably true elsewhere, and not something a kernel-
   only build would ever have caught either.
9. **`packet_codec.c`** and the fully byte-identical files (`common.h`,
   `checksum.h`/`.c`, `config.h`/`.c`, `pin.h`/`.c`, `trial.h`/`.c`,
   `keychain_setup.h`/`.c`, `log.h`/`.c`, `ack.h`/`.c`) — same highest-
   confidence verification as every other BSD-family port: compiles and
   links cleanly, plus `ack.c`'s table logic and `packet_codec.c`'s
   parsing are covered respectively by
   `firewall/linux-kernel-module/tests/test_ack.c` (10,000+ checks) and
   `test_packet_codec.c` (78 checks), both reused unmodified against
   these exact files, all passing.

Treat this the same way the Windows, macOS, and FreeBSD ports were
treated before ever being built: a careful, best-effort starting point
that needs a real OpenBSD machine and its kernel source tree to finish,
not a working deliverable. Building and booting into a custom kernel
carries real risk (a broken kernel can fail to boot) — do this on a
machine/VM you can recover, and back up your current known-good kernel
first (`cp /bsd /bsd.GENERIC`, before running `make install` below) so
you have a named fallback to boot from if the new one doesn't come up —
standard practice for any custom OpenBSD kernel, not specific to this
project. `make install` also preserves whatever kernel it's replacing as
`/obsd` on its own, and the boot prompt's `ls`/`h` commands list what's
actually bootable if you don't remember a name.

## Architecture

```
                     sys/netinet/ip_output.c, ip_input.c
                     sys/netinet6/ip6_output.c, ip6_input.c
                     (existing OpenBSD kernel source, patched -
                      one line each, next to pf_test()/pf_test6())
                                    │
                     ┌──────────────▼───────────────────────────────────┐
                     │   otpfw.c  (sys/net/otpfw.c, statically          │
                     │   compiled into the kernel - "Kernel             │
                     │   integration" below)                            │
                     │                                                  │
 outgoing packet ────►  kill switch off? ─ yes ──► pass through         │
                     │        │ no                                      │
                     │        ▼                                         │
                     │  ICMPv6 ND / ack-port UDP? ─ yes ──► pass        │
                     │        through untouched                         │
                     │        │ no                                      │
                     │        ▼                                         │
                     │  known destination? ─ no ──► blocked             │
                     │        │ maybe                                   │
                     │        ▼                                         │
 incoming packet ────►  known source? ─ no ──► blocked                  │
                     │        │ maybe                                   │
                     │        ▼                                         │
                     └───────────────┬──────────────────────────────────┘
                                     │ /dev/otpfw (read/write/ioctl queue)
                     ┌───────────────▼──────────────────────────────────┐
                     │   otp_firewalld  (daemon, userspace)             │
                     │                                                  │
                     │  outgoing: encrypt for the matched contact,      │
                     │  or block if none is matched                     │
                     │                                                  │
                     │  incoming: try to decrypt against your           │
                     │  contacts' keys; allow through on the first      │
                     │  one that works, otherwise block                 │
                     └──────────────────────────────────────────────────┘
```

The candidate-IP prefilter (the `known destination?`/`known source?`
steps above) runs entirely inside `otpfw.c`, in-kernel, before anything
is queued to userspace — same "a stranger's traffic to an address you
never configured can't force the daemon to spend any effort on it"
property every other platform's kernel-side candidate table gives (see
[`../README.md`'s "Incoming traffic"](../README.md#incoming-traffic)).

## What's identical to Linux vs. what's new

Every platform's firewall code lives entirely in its own directory — there
is no shared `firewall/daemon/` directory anywhere in this repository.
Instead, the platform-agnostic daemon-support files started as Linux's
implementation and are duplicated, filename-for-filename, into every
platform's own folder; keeping them byte-identical across platforms
(verified by diffing against Linux's copies) is a convention this project
follows, not something the build system enforces.

`cipher.c`/`keychain.c`/`commit.c` (from `src/`, two directories further
up) need **zero changes** — `src/compat.h` already branches purely on
`_WIN32` vs. real POSIX, and OpenBSD is genuine POSIX.

Of the daemon-support files in this directory, everything is pure POSIX C
with no platform-specific dependencies **except** `packet_codec.c` (BSD
struct field names) and `kernel_ctl.c`/`otp_firewalld.c` (talk to
`/dev/otpfw`). These files are byte-identical to Linux's copies,
unmodified:

- `common.h`, `checksum.h`/`.c`, `config.h`/`.c`, `pin.h`/`.c`,
  `trial.h`/`.c`, `keychain_setup.h`/`.c`, `log.h`/`.c`, `ack.h`/`.c` (the
  delivery-acknowledgment mechanism — see [`../README.md`'s "Delivery
  acknowledgment"](../README.md#delivery-acknowledgment)), `packet_codec.h`,
  `kernel_ctl.h` (just the header — its declared API has no
  platform-specific types)

...and this directory provides OpenBSD-specific bodies for the ones that
need one, named identically to their Linux counterparts — this is
functionally the FreeBSD port's own userspace design, verbatim, just
talking to `/dev/otpfw` (backed by a kernel patch) instead of
`/dev/otp_firewall` (backed by a loadable KLD):

- `packet_codec.c` — same public API as `packet_codec.h`, BSD header
  field names.
- `kernel_ctl.c` — same public API as `kernel_ctl.h`, pushes candidates
  via `ioctl(OTP_FW_IOC_SET_CANDIDATES)` on `/dev/otpfw`.
- `otp_firewalld.c` — reads/writes `/dev/otpfw` instead of an NFQUEUE
  socket or a `pf` divert socket.
- `otp_firewall_proto.h` — the wire format shared verbatim between the
  kernel-side `otpfw.c` and userspace, the same role the FreeBSD port's
  identically-named header plays.
- `otpfwctl.c` — the kill-switch control utility, talking to `/dev/otpfw`
  via `ioctl(OTP_FW_IOC_SET_ENABLED)`/`GET_ENABLED`, the exact shape the
  FreeBSD port's own `otpfwctl.c` has.

New for OpenBSD, in `kernel/` (nothing here has an equivalent on any
other platform, since no other platform's kernel hook is a source patch
rather than a buildable module):

- `kernel/otpfw.c`, `kernel/otpfwvar.h` — the actual kernel-resident hook:
  the candidate table, the kill switch, the pending-packet queue, the
  character device, and the two entry points
  (`otpfw_hook_out()`/`otpfw_hook_in()`) the four patched call sites use.
  Real destination: `sys/net/otpfw.c`/`sys/net/otpfwvar.h` in your kernel
  source tree.
- `kernel/files.otpfw` — the `sys/conf/files` entry tying the
  `pseudo-device otpfw` config line to `otpfw.c` and the `NOTPFW` count
  macro (see "Kernel integration" below).

## Compile

Two independent things get built: the kernel patch (once, produces a
bootable kernel you install and reboot into) and the userspace daemon/CLI
(ordinary binaries, rebuildable anytime without touching the kernel).

### 1. Kernel integration

Do this first — the userspace binaries below will refuse to do anything
useful (`/dev/otpfw` won't exist) until a patched kernel is running.

**Prerequisite**: the OpenBSD kernel source tree, matching your exact
running release, normally at `/usr/src/sys` (installable via the `src.tar.gz`
set, or `cvs`/`git` per the OpenBSD handbook). Do this on a machine or VM
you can recover if the new kernel fails to boot — standard practice for
any custom OpenBSD kernel, not specific to this project.

1. **Copy the new files in** (they don't exist yet in a stock tree):
   ```
   cp firewall/openbsd-7.9-patch/kernel/otpfw.c      /usr/src/sys/net/otpfw.c
   cp firewall/openbsd-7.9-patch/kernel/otpfwvar.h   /usr/src/sys/net/otpfwvar.h
   cp firewall/openbsd-7.9-patch/otp_firewall_proto.h /usr/src/sys/net/otp_firewall_proto.h
   ```

2. **Register the new file** — merge `firewall/openbsd-7.9-patch/kernel/files.otpfw`'s
   two lines into `/usr/src/sys/conf/files` (anywhere among the other
   `pseudo-device`/`file` pairs is fine):
   ```
   pseudo-device	otpfw
   file	net/otpfw.c			otpfw needed
   ```

3. **Wire the character device into the kernel's `cdevsw` table** for
   your architecture, via `/usr/src/sys/arch/<arch>/conf/majors.<arch>`
   (e.g. `majors.amd64`). This is the step that's easy to underestimate:
   unlike FreeBSD's driver-local `make_dev()`/devfs model (used by the
   FreeBSD port's own `otp_firewall.c`), OpenBSD's character devices are
   NOT self-registering - `otpfw.c` deliberately defines no `cdevsw`
   struct of its own, because on OpenBSD that table is assembled
   centrally, keyed by major number, from `majors.<arch>` entries. Find
   the highest major already in use in that file and add one for
   `otpfw`, in the exact format the surrounding entries use there - this
   is what actually connects the major number to `otpfwopen()`/
   `otpfwclose()`/`otpfwread()`/`otpfwwrite()`/`otpfwioctl()` (typically
   via a `cdev_decl(otpfw)`-style declaration macro, which in turn
   usually needs to exist somewhere like `sys/sys/conf.h` alongside the
   other drivers' - check how an existing simple character device, e.g.
   `bpf`, is declared there and mirror it exactly). Both the major-number
   value and the precise mechanics of this step are things only a real
   source tree can settle - this project cannot hand you a "right"
   number, or fully confirm this is still how a recent release wires new
   character devices at all, in advance.

4. **Add `pseudo-device otpfw` to a kernel config.** Don't edit `GENERIC`
   directly — copy it first:
   ```
   cd /usr/src/sys/arch/$(machine)/conf
   cp GENERIC OTPFW
   echo 'pseudo-device otpfw' >> OTPFW
   config OTPFW
   ```

5. **Patch the four call sites.** In each of
   `/usr/src/sys/netinet/ip_output.c`, `ip_input.c`, and
   `/usr/src/sys/netinet6/ip6_output.c`, `ip6_input.c`: locate the
   existing call to `pf_test()` (in the two `ip_output.c`/`ip_input.c`
   files) or `pf_test6()` (in the two `ip6_*.c` files) — a call that
   already exists in every one of these four files, unconditionally
   compiled in, since `pf` itself is wired in exactly this way. Add
   `#include "otpfwvar.h"` near that file's other `#include "..."` lines
   (not `<...>` — it's a sibling file in `sys/net/`, same convention
   `pfvar.h` already follows there), then immediately after the
   `pf_test()`/`pf_test6()` call, add:
   ```c
   if (OTPFW_HOOK_OUT(&m, ifp))   /* ip_output.c, ip6_output.c */
           goto <wherever the neighboring pf_test() failure branch already goes>;
   ```
   or, in the two `*_input.c` files:
   ```c
   if (OTPFW_HOOK_IN(&m, ifp))    /* ip_input.c, ip6_input.c */
           goto <wherever the neighboring pf_test() failure branch already goes>;
   ```
   `m` and `ifp` above are placeholders, not a claim about the real local
   variable names — read them off the neighboring `pf_test()`/`pf_test6()`
   call itself (its mbuf-pointer and interface arguments are exactly
   what `OTPFW_HOOK_OUT`/`OTPFW_HOOK_IN` need) rather than typing `m`/
   `ifp` literally; a real tree may well spell them `m0`, `mp`, or
   something else entirely. Same reasoning as the `goto` target below:
   mirror what's already there, don't guess a new name. The exact target
   of that `goto` (or `return`, or whatever the surrounding function
   uses) must match what the *existing* `pf_test()` failure branch right
   above it already does — mirror it exactly, don't guess a new one.
   The mbuf pointer becomes `NULL` when the hook consumes the packet
   (see `otpfwvar.h`'s doc comment), so nothing past that point may touch
   it again, the same constraint the `pf_test()` failure path already
   respects.

6. **Build and install the new kernel:**
   ```
   cd ../compile/OTPFW
   make
   make install
   reboot
   ```
   Confirm it took:
   ```
   sysctl kern.version
   ```

### 2. Build the daemon and control tool

Everything the daemon needs lives directly in this directory (plus the
core library in `src/`, two directories up) — no kernel headers required
for this half, it's ordinary userspace C:

```
cd firewall/openbsd-7.9-patch
make
```

Produces `otp_firewalld` and `otpfwctl`. Equivalently, from the
repository root:

```
cc -O2 -Wall -Isrc -Ifirewall/openbsd-7.9-patch \
   -o otp_firewalld \
   firewall/openbsd-7.9-patch/otp_firewalld.c \
   firewall/openbsd-7.9-patch/kernel_ctl.c \
   firewall/openbsd-7.9-patch/packet_codec.c \
   firewall/openbsd-7.9-patch/config.c firewall/openbsd-7.9-patch/pin.c \
   firewall/openbsd-7.9-patch/trial.c firewall/openbsd-7.9-patch/checksum.c \
   firewall/openbsd-7.9-patch/log.c firewall/openbsd-7.9-patch/keychain_setup.c \
   firewall/openbsd-7.9-patch/ack.c \
   src/cipher.c src/keychain.c src/commit.c

cc -O2 -Wall -Ifirewall/openbsd-7.9-patch \
   -o otpfwctl firewall/openbsd-7.9-patch/otpfwctl.c
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

### 1. Confirm the patched kernel is running

```
sysctl kern.version
```

should show your custom `OTPFW` build (see "Kernel integration" above).
If `/dev/otpfw` doesn't exist yet, create it the way any new character
device's node is created on OpenBSD — via that architecture's
`MAKEDEV`/`etc/MAKEDEV.local` entry, or `mknod` directly with the major
number you assigned in step 3 above and a minor of `0`. At this point
nothing about your network has changed yet — the kill switch (below)
starts off, matching every other platform's default-off posture at boot.

### 2. Start the background daemon

Start it in log-only mode first, so you can see what it *would* do
before it can actually block anything:

```
doas ./otp_firewalld --mode=log-only
```

Watch `~/.otp/authorized.log` and `~/.otp/restricted.log` (see
[`../README.md`'s "Log format"](../README.md#log-format)) to confirm
it's making the decisions you expect. When you're satisfied, restart it
in enforcing mode:

```
doas ./otp_firewalld --mode=enforce
```

Full flag list: `otp_firewalld --help`. Notably: `--config=PATH` to use a
config file other than `~/.otp/firewall.config`, and
`--resolve-interval=SECONDS` to change how often `firewall.config`
hostnames are re-resolved (60s by default).

### 3. Turn the firewall on

Enforcement is a separate step from having a patched kernel booted and
the daemon running, so you always have a fast way back if something looks
wrong:

```
doas ./otpfwctl enable
```

## Deactivate

```
doas ./otpfwctl disable
```

Takes effect immediately, on the very next packet — flips the same
in-kernel flag `otpfwctl enable` set, via `ioctl(OTP_FW_IOC_SET_ENABLED)`
on `/dev/otpfw` — and doesn't require restarting the daemon or rebooting.
This is the fastest way back to your normal network if anything looks
wrong; it does NOT require rebuilding/rebooting out of the patched
kernel, only rebuilding+rebooting does that (see "Kernel integration"
step 4's `NOTPFW` distinction, documented in `kernel/otpfwvar.h`).

To fully remove it, also stop `otp_firewalld` (however you started it)
and boot back into your previous, unpatched kernel — `boot obsd` at the
boot prompt if you're relying on `make install`'s own automatic backup
(see "Kernel integration" step 6), or `boot bsd.GENERIC` if you made the
explicit backup the Status section recommends before starting. Either
way, `ls`/`h` at the boot prompt lists what's actually available to boot
if you're unsure of the name.
