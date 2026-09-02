# Userspace unit tests for the OTP_TOOLKIT_FIREWALL daemon logic
# (../*.c, i.e. firewall/linux-kernel-module/*.c) - see ../README.md and
# README.md in this directory. Run with `make` or `make test`.
#
# These link the real, unmodified core library (src/cipher.c,
# src/keychain.c, src/commit.c) exactly as the daemon itself does, plus
# whichever daemon-side .c files each test needs - never a reimplemented
# or mocked version of either.

CC := gcc
CFLAGS := -O0 -g -Wall -D_FILE_OFFSET_BITS=64
DAEMON := ..
SRC := ../../../src
INCLUDES := -I. -I$(DAEMON) -I$(SRC)

CORE := $(SRC)/cipher.c $(SRC)/keychain.c $(SRC)/commit.c

.PHONY: test clean

test: test_checksum test_pin test_config test_trial test_packet_codec test_ack
	@echo
	@echo " - Running firewall daemon unit tests..."
	@rc=0; \
	for t in test_checksum test_pin test_config test_trial test_packet_codec test_ack; do \
		./$$t || rc=1; \
	done; \
	echo; \
	if [ $$rc -eq 0 ]; then echo " - All firewall daemon tests passed!"; else echo " - FIREWALL DAEMON TESTS FAILED"; fi; \
	exit $$rc

test_checksum: test_checksum.c $(DAEMON)/checksum.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_checksum.c $(DAEMON)/checksum.c

test_pin: test_pin.c $(DAEMON)/pin.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_pin.c $(DAEMON)/pin.c

test_ack: test_ack.c $(DAEMON)/ack.c $(DAEMON)/config.c $(CORE)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_ack.c $(DAEMON)/ack.c $(DAEMON)/config.c $(CORE)

test_config: test_config.c $(DAEMON)/config.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_config.c $(DAEMON)/config.c

test_trial: test_trial.c $(DAEMON)/trial.c $(DAEMON)/config.c $(DAEMON)/pin.c $(CORE)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_trial.c $(DAEMON)/trial.c $(DAEMON)/config.c $(DAEMON)/pin.c $(CORE)

test_packet_codec: test_packet_codec.c $(DAEMON)/packet_codec.c $(DAEMON)/checksum.c $(DAEMON)/config.c $(DAEMON)/trial.c $(DAEMON)/pin.c $(CORE)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_packet_codec.c $(DAEMON)/packet_codec.c $(DAEMON)/checksum.c \
		$(DAEMON)/config.c $(DAEMON)/trial.c $(DAEMON)/pin.c $(CORE)

clean:
	rm -f test_checksum test_pin test_config test_trial test_packet_codec test_ack
	rm -rf /tmp/otp_fw_test_*
