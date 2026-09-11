# Builds otp_firewalld and otpfwctl - see README.md. This does NOT
# build the kernel-side hook (kernel/otpfw.c) - that gets copied into
# your OpenBSD kernel source tree and built as part of the kernel itself
# (see README.md's "Kernel integration"); there is no separate module
# artifact to produce, and no loadable-module mechanism to build one for
# in the first place. Deliberately plain enough to run under either
# OpenBSD's own bmake or GNU make - no conditionals, no shell-function
# macros.
#
# Usage (on an OpenBSD machine, once the kernel patch in kernel/ has been
# applied and you've rebooted into the patched kernel):
#   make
#   doas make install     # installs both binaries into /usr/local/sbin
#   make clean

CC ?= cc
CFLAGS ?= -O2 -Wall
SRC_ROOT = ../..
PREFIX ?= /usr/local

DAEMON_SRCS = otp_firewalld.c config.c pin.c trial.c packet_codec.c \
	checksum.c log.c kernel_ctl.c keychain_setup.c ack.c \
	$(SRC_ROOT)/src/cipher.c $(SRC_ROOT)/src/keychain.c $(SRC_ROOT)/src/commit.c

all: otp_firewalld otpfwctl

otp_firewalld: $(DAEMON_SRCS)
	$(CC) $(CFLAGS) -I$(SRC_ROOT)/src -o otp_firewalld $(DAEMON_SRCS)

otpfwctl: otpfwctl.c otp_firewall_proto.h
	$(CC) $(CFLAGS) -o otpfwctl otpfwctl.c

install: all
	install -m 0755 otp_firewalld $(PREFIX)/sbin/otp_firewalld
	install -m 0755 otpfwctl $(PREFIX)/sbin/otpfwctl

clean:
	rm -f otp_firewalld otpfwctl

.PHONY: all install clean
