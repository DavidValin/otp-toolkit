# OTP_TOOLKIT_FIREWALL tests

## Userspace tests (run these)

```
cd firewall/linux-kernel-module/tests
make test
```

This builds and runs standalone unit tests against the real daemon logic
in `firewall/daemon/*.c`, linking the same unmodified core library
(`src/cipher.c`, `src/keychain.c`, `src/commit.c`) the daemon itself
links — never a mock or a reimplementation of either. No root, no kernel
module, no NFQUEUE needed: these test pure logic and the packet
encrypt/decrypt round trip using real (throwaway, scratch-directory)
keychains, not the network stack.

| File | Covers |
|---|---|
| `test_checksum.c` | `checksum.c` - RFC1071 conformance, IPv4/pseudo-header checksums |
| `test_pin.c` | `pin.c` - the IP→contact pin table |
| `test_config.c` | `config.c` - `firewall.config` parsing, resolution, candidate IP list, and the reload-preserves-resolved-IP fix |
| `test_trial.c` | `trial.c` - pin → config → keychain-scan candidate ordering, exclusivity |
| `test_packet_codec.c` | `packet_codec.c` - full encrypt/decrypt round trip over hand-built IPv4/IPv6 TCP/UDP packets, checksum correctness, the log-only classify functions never spending key material, the empty-payload (bare ACK) fix, and the length-field-ceiling pre-check never spending key material either |

`main.c` (the NFQUEUE event loop itself) isn't covered here: it's a thin
wrapper around the logic above, and exercising it for real needs an
actual kernel + netfilter environment - see `../README.md`'s "Activate"
section for the real insmod/`otp-firewalld`/kill-switch steps instead.

`make clean` removes the built test binaries and any scratch keychain
directories left in `/tmp`.

## Kernel-side test (not runnable here)

`kunit/test_candidates.c` is a [KUnit](https://docs.kernel.org/dev-tools/kunit/)
test for the one piece of `otp_firewall.c` that's pure, self-contained
logic: `otp_fw_is_candidate()`, the in-kernel IP-matching table lookup
the netfilter hooks use to decide whether a packet is even worth queuing
to userspace. Everything else in that file (the hooks themselves, the
proc handlers) needs a real `struct sk_buff`/`struct file`/VFS context to
exercise meaningfully, which isn't something a unit test can construct in
isolation - see `../README.md`'s "Activate" section for the
insmod/rmmod-based real-world steps that actually cover those.

This file could not be built or run in the environment it was written
in (no `linux-headers` package installed, so no `/lib/modules/$(uname
-r)/build` to build a KUnit module against - see `../README.md`'s
"Compile" section for the kernel-headers prerequisite). Once you have kernel headers and `CONFIG_KUNIT` enabled,
wire it up with a `Kbuild` fragment like:

```
obj-$(CONFIG_KUNIT) += otp_firewall_test.o
```

or run it via kernel's `kunit_tool`:

```
tools/testing/kunit/kunit.py run --kunitconfig=firewall/linux-kernel-module/tests/kunit
```

(you'll need a `.kunitconfig` enabling `CONFIG_OTP_FIREWALL` and
`CONFIG_KUNIT` for that invocation - not included here, since it depends
on how you've set up your kernel build tree). Treat this file as
reviewed-but-unverified: read it before trusting it blindly, the way you
would the kernel module itself.
