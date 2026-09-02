# OTP-toolkit Firewall

## Index

1. [What is OTP-toolkit Firewall](#what-is-otp-toolkit-firewall)
2. [How it works](#how-it-works)
   - [Outgoing traffic](#outgoing-traffic)
   - [Incoming traffic](#incoming-traffic)
   - [Every packet is checked individually](#every-packet-is-checked-individually)
   - [Delivery acknowledgment](#delivery-acknowledgment)
   - [Key material is consumed as you go](#key-material-is-consumed-as-you-go)
   - [IPv6 still works](#ipv6-still-works)
3. [Configuration file format](#configuration-file-format)
4. [File locations](#file-locations)
5. [Log format](#log-format)
6. [Limitations](#limitations)
7. [Platforms](#platforms)

## What is OTP-toolkit Firewall

OTP-toolkit Firewall is a system-wide network firewall, built on top of
otp-toolkit's one-time-pad keychain. Once active, it blocks all incoming
and outgoing network traffic by default, and only allows traffic to and
from the contacts in your keychain. There's no separate password,
certificate, or shared secret to set up — the same one-time-pad keys you
already use with the `otp` command are what authenticate and encrypt this
traffic.

In short:

- **Default deny** — every connection is blocked unless it's proven to come
  from, or is going to, a known contact.
- **Contact-based** — "known" means a contact in your `otp` keychain, sharing
  a one-time-pad key pair with you.
- **Transparent** — once set up, ordinary applications (browsers, SSH, and so
  on) don't need to know anything changed. Traffic to and from your contacts
  keeps working normally; everything else is silently dropped.

This page describes the firewall's behavior — what it encrypts, how it
decides to authenticate a packet, what it logs — which is identical no
matter which platform you're running it on. How you actually build,
configure, and turn it on differs per platform, and is documented in each
platform's own README — see ["Platforms"](#platforms) at the end of this
page.

## How it works

### Outgoing traffic

When your computer sends a packet to an address that's mapped to one of
your contacts (see ["Configuration file
format"](#configuration-file-format) below), the firewall encrypts that
packet's contents using your one-time-pad key for that contact before it
leaves your machine. The packet keeps its original source, destination,
and port — only its contents change. Traffic to any address that isn't
mapped to a contact is dropped outright.

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
packet has to prove itself on its own, using the exact next slice of key
material in sequence. This has a real consequence: if a packet is rejected
(arrived out of order, was lost, anything), the contact's two firewalls are
now out of sync — the sender has moved on to the next slice of key material,
but the receiver is still waiting for the one that got rejected, and one-time-pad
key material can only ever be consumed moving forward, never rewound. An
ordinary TCP retransmission does **not** reliably fix this on its own: a
retransmission is a new outgoing packet, encrypted fresh with whatever key
material the sender has reached by then — not the exact slice the receiver
is still stuck expecting. See ["Delivery
acknowledgment"](#delivery-acknowledgment) below for how the firewall
actually prevents this from happening.

### Delivery acknowledgment

Because the consequence above is real, the firewall doesn't just encrypt a
message and hope it arrived — it waits for proof. After decrypting a message
successfully, the receiving firewall sends a small reference back to the
sender (the message's `source_id`, a value that's safe to reveal after the
fact since it was never used to encrypt anything — see `otp --help`'s
`--with-ack-file` documentation for the same mechanism the manual CLI
exposes). The sending firewall will not encrypt and send another message to
that contact until it has seen that reference come back. This is what keeps
the two sides' key material genuinely in sync, instead of just assuming it.

The direct cost: each contact is effectively limited to one message in
flight at a time, waiting roughly one network round-trip before the next can
even be encrypted — noticeably slower than raw TCP for a contact carrying a
lot of traffic (a page load, a large file transfer). This is a deliberate
tradeoff, not an oversight: closing the desync gap above is worth more than
raw throughput.

If the acknowledgment doesn't arrive within a few seconds, the firewall
automatically resends the exact same already-encrypted message (not a fresh
one — that would spend new key material and only make the gap worse) and
keeps waiting. This repeats until the acknowledgment comes back, so a
transient loss recovers on its own without operator intervention.

This tracking survives a crash or restart of the firewall itself, not just a
network hiccup. The underlying `otp` library already keeps a durable copy of
the last message sent to each contact on disk, precisely so that an
unconfirmed message is never silently forgotten; the firewall reuses that
existing mechanism (rather than inventing a new one) to reconstruct, on
startup, which contacts still had a message genuinely awaiting acknowledgment
when the process last stopped, and correctly keeps blocking new traffic to
them until a real acknowledgment is seen. In the ordinary case (the last
message to a contact was already acknowledged before the restart), this
recovery step is a no-op and traffic resumes immediately — it only holds a
contact back when there was genuinely something still unconfirmed. One
narrower case remains a known limitation: if the disk record that also holds
the acknowledgment reference doesn't survive the crash (as opposed to the
durable copy above, which reliably does), the firewall correctly keeps
blocking that contact but can no longer automatically resend the message —
an operator has to resolve it manually, or simply wait for the two sides to
notice and recover through their own application-level retry.

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

## Configuration file format

Every platform reads the same `~/.otp/firewall.config` file, in the same
format:

```
# contact-name   ip-or-hostname [ip-or-hostname ...]
alice            203.0.113.5 alice.example.com
bob              198.51.100.9
```

Each line maps a contact to one or more IP addresses or hostnames. This
decides who outgoing traffic gets encrypted for, and gives incoming traffic
a fast first guess at who sent it. Hostnames are re-resolved periodically,
so DNS changes are picked up without restarting anything.

## File locations

| Path | Purpose |
|---|---|
| `~/.otp/firewall_keychain/` | The firewall's own keychain (separate from any keychain you use elsewhere) |
| `~/.otp/.keychain` | Internal link to `firewall_keychain` — this is what lets you manage firewall contacts with the ordinary `otp` command by running it from inside `~/.otp` |
| `~/.otp/firewall.config` | Contact → address mapping (see ["Configuration file format"](#configuration-file-format) above) |
| `~/.otp/authorized.log` | One line per packet that was let through |
| `~/.otp/restricted.log` | One line per packet that was blocked |

## Log format

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

## Limitations

- **Packet size:** if OTP-wrapping pushes a packet past your network's
  maximum packet size, it's handled by ordinary IP fragmentation rather than
  anything special.
- **Key usage:** every packet sent to a contact — even ones carrying no data,
  like a bare acknowledgment — consumes some key material. Chatty connections
  cost more key material than their actual data volume alone would suggest.
- **IPv6 extension headers** aren't inspected; packets using them are blocked
  rather than potentially misread.
- **Packet reordering** causes a genuinely valid packet to be rejected if it
  arrives out of order (see ["Every packet is checked
  individually"](#every-packet-is-checked-individually) above) — expected
  behavior, not a malfunction, and recovered from automatically by the
  mechanism described in ["Delivery
  acknowledgment"](#delivery-acknowledgment).
- **Throughput:** delivery acknowledgment (see above) limits each contact to
  one message in flight at a time — noticeably slower than raw TCP for a
  contact carrying a lot of traffic. This is deliberate, not a bug.
- Only TCP and UDP traffic is ever admitted. Every other protocol is
  blocked, except IPv6 Neighbor Discovery, which always passes through
  untouched (see ["IPv6 still works"](#ipv6-still-works) above).

## Platforms

The behavior above is identical everywhere; what differs per platform is
the mechanism that intercepts traffic and hands it to the encryption logic,
and therefore how you build, configure, and turn the firewall on and off.
Each platform has its own README with complete, self-contained
compile/configure/activate/deactivate instructions:

- **[Linux Kernel Module](linux-kernel-module/README.md)** — a real
  netfilter kernel module plus a userspace daemon, talking over NFQUEUE.
  Built, compiled, and unit-tested.
- **[macOS System Extension](macos-kernel-module/README.md)** — a
  `NEPacketTunnelProvider` System Extension (there is no supported
  kernel-module mechanism left on macOS). Never compiled — written without
  access to a Mac.
- **[Windows WFP Callout Driver](windows-wfp-callout-driver/README.md)** —
  a custom Windows Filtering Platform callout driver plus a background
  Windows Service. Never compiled — written without access to the Windows
  Driver Kit.
- **[FreeBSD Kernel Module](freebsd-kernel-module/README.md)** — a real
  `pfil(9)`-based kernel module plus a userspace daemon, talking over a
  custom character device. Never compiled — written without access to a
  FreeBSD machine.

Maturity differs sharply between them — see each platform's own README for
exactly what is and isn't verified before relying on it for anything.
