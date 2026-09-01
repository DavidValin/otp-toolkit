# OTP Firewall

## What is OTP Firewall

OTP Firewall is a system-wide network firewall for Linux, built on top of
otp-toolkit's one-time-pad keychain. Once active, it blocks all incoming and
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

It's made of two parts working together: a small kernel module that
intercepts network traffic, and a background service (a "daemon") that does
the actual encryption, decryption, and decision-making. Both are covered in
more detail below.

## How it works

### Outgoing traffic

When your computer sends a packet to an address that's mapped to one of your
contacts (see "How to install/use it" below), the firewall encrypts that
packet's contents using your one-time-pad key for that contact before it
leaves your machine. The packet keeps its original source, destination, and
port — only its contents change. Traffic to any address that isn't mapped to
a contact is dropped outright.

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

## How to install/use it

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

## Technical details

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
IPv6's Neighbor Discovery traffic (see "How it works"), which always passes
through untouched.

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
| `~/.otp/firewall.config` | Contact → address mapping (see "How to install/use it") |
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
  arrives out of order (see "How it works" above) — expected behavior, not a
  malfunction.
