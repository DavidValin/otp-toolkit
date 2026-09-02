# OTP-toolkit Firewall — Linux

A netfilter kernel module (`otp_firewall.ko`) plus a userspace background
service (`otp-firewalld`), talking to each other over NFQUEUE. For what the
firewall actually does — what gets encrypted, how a packet is authenticated,
what gets logged — see [`../README.md`](../README.md). This page covers
building, configuring, and turning the Linux port on and off.

## Status

Built, compiled, and unit-tested: `tests/` (in this directory) runs 14,348
checks against `otp-firewalld`'s code, all passing, rebuilt and reverified
after every change — including real end-to-end tests (using the actual
`otp` library, not mocks) of crash/restart recovery for the
delivery-acknowledgment mechanism (see [`../README.md`'s "Delivery
acknowledgment"](../README.md#delivery-acknowledgment)). The kernel module
itself (`otp_firewall.ko`) has never
been `insmod`'d on a real machine — its netfilter hook registration and
NFQUEUE hand-off were reasoned about carefully against stable, well-documented
kernel APIs, but treat it as unverified until you've loaded it yourself and
watched `dmesg`.

## Architecture

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

`otp_firewall.ko` hooks `NF_INET_POST_ROUTING` (outgoing) and
`NF_INET_PRE_ROUTING` at a priority ahead of conntrack (incoming). It keeps
a small in-kernel table of candidate IPs (pushed by the daemon) and drops
anything that obviously doesn't match, without ever leaving the kernel;
anything that might be relevant is handed to `otp-firewalld` over a pair of
NFQUEUE queues (0 for outgoing, 1 for incoming, by default) for the actual
encrypt/decrypt decision. IPv6 Neighbor Discovery is exempted directly in
the kernel module and never reaches the daemon at all - so is the
daemon's own delivery-acknowledgment traffic (see [`../README.md`'s
"Delivery acknowledgment"](../README.md#delivery-acknowledgment)), a
small UDP side channel on a fixed port the kernel module lets through
untouched in both directions.

## Compile

### 1. Install the kernel headers

The kernel module needs to be built against your exact running kernel:

```
# Arch:           sudo pacman -S linux-headers
# Debian/Ubuntu:  sudo apt install linux-headers-$(uname -r)
# Fedora:         sudo dnf install kernel-devel
```

### 2. Build

From the repository root:

```
make firewall-daemon   # builds the background service, bin/otp-firewalld
make firewall-kmod     # builds the kernel module, otp_firewall.ko
```

### 3. (Optional) Run the test suite

```
cd firewall/linux-kernel-module/tests && make
```

Builds and runs all five unit-test binaries against the daemon's code
(checksum, pin table, config parsing, trial-decryption ordering, packet
codec). All 4,273 checks should pass.

## Configure

### 1. Set up your contacts

The firewall uses its own keychain, kept separate from any keychain you use
for everyday `otp` encrypt/decrypt work, at `~/.otp/firewall_keychain`. To
add a contact to it, run the normal `otp` keychain commands from inside
`~/.otp` specifically — that's what points them at the firewall's keychain
instead of whatever keychain you might have elsewhere:

```
cd ~/.otp
otp -nk 100 me alice       # generates a mirrored one-time-pad key pair for you and alice
otp -ac alice <enc-key-file> <dec-key-file>   # add alice as a contact using her half
```

Send your contact their half of the key pair through a trusted channel out
of band, and have them do the equivalent on their end. See `otp --help` for
the full set of keychain commands.

### 2. Tell the firewall which addresses belong to which contact

Create `~/.otp/firewall.config` — see [`../README.md`'s "Configuration file
format"](../README.md#configuration-file-format) for the exact format.

## Activate

### 1. Load the kernel module

The module requires IP defragmentation to be active (so it only ever sees
whole, reassembled packets — never a raw fragment it can't safely parse),
using the same standard modules the rest of the kernel's connection-tracking
machinery depends on. Load those first — they ship with every mainline
kernel, so this is just loading what's already installed:

```
sudo modprobe nf_defrag_ipv4 nf_defrag_ipv6
sudo insmod firewall/linux-kernel-module/otp_firewall.ko
```

(If you skip the `modprobe` step, `insmod` fails with an "unknown symbol"
error rather than loading in a degraded state.)

The module starts **disabled** — nothing about your network changes yet.
Confirm it loaded:

```
lsmod | grep otp_firewall
dmesg | tail -1
```

Advanced: the kernel module and the daemon communicate over a pair of
numbered NFQUEUE queues (0/1 by default). To change these — e.g. to avoid
clashing with another NFQUEUE-based tool — pass matching
`queue_egress=`/`queue_ingress=` module parameters to `insmod` and
`--queue-egress=`/`--queue-ingress=` flags to `otp-firewalld` (below).

### 2. Start the background service

Start it in log-only mode first, so you can see what it *would* do before it
can actually block anything:

```
sudo otp-firewalld --mode=log-only
```

Watch `~/.otp/authorized.log` and `~/.otp/restricted.log` (see
[`../README.md`'s "Log format"](../README.md#log-format)) to confirm it's
making the decisions you expect. When you're satisfied, restart it in
enforcing mode:

```
sudo otp-firewalld --mode=enforce
```

Full flag list: `otp-firewalld --help`. Notably: `--config=PATH` to use a
config file other than `~/.otp/firewall.config`, `--resolve-interval=SECONDS`
to change how often `firewall.config` hostnames are re-resolved (60s by
default), and `--ack-timeout=SECONDS` to change how long the daemon waits
for a peer's delivery acknowledgment before retrying (5s by default — see
[`../README.md`'s "Delivery acknowledgment"](../README.md#delivery-acknowledgment)).

### 3. Turn the firewall on

Enforcement is a separate step from starting the service, so you always have
a fast way back if something looks wrong:

```
echo 1 | sudo tee /proc/otp_firewall/enabled   # turn on
```

## Deactivate

```
echo 0 | sudo tee /proc/otp_firewall/enabled   # turn off instantly
cat /proc/otp_firewall/enabled                 # check current state
```

This takes effect immediately, on the very next packet, and doesn't require
restarting the service or removing the kernel module — it's the fastest way
to get your normal network back if anything looks wrong.

To fully remove it:

```
sudo rmmod otp_firewall
```

This unloads the kernel module (which also turns enforcement off). Then stop
`otp-firewalld` however you started it (`Ctrl-C`, `systemctl stop`, etc.).

## Installing system-wide

```
sudo make install-firewall
```

Builds both pieces and installs `otp-firewalld` to `/usr/local/bin/`. It
does not load the kernel module or start the service for you — do that with
the "Activate" steps above.
