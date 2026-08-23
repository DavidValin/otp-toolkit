OS := $(shell uname -s 2>/dev/null)
ifeq ($(OS),)
  OS := Windows_NT
endif

ifeq ($(OS),Windows_NT)
  CC := cl
  BIN_EXT := .exe
  BUILD_FLAGS := /O2 /Wall
else
  CC := gcc
  BIN_EXT :=
  # Enable Large File Support (LFS) for files >2GB on 32-bit systems
  BUILD_FLAGS := -O2 -Wall -D_FILE_OFFSET_BITS=64
endif

BIN := bin/otp$(BIN_EXT)

VERSION := $(shell sed -n 's/.*otp-toolkit v\([0-9][0-9.]*\).*/\1/p' src/cli.c 2>/dev/null | head -1)
ifeq ($(VERSION),)
  VERSION := (unknown version)
endif

.PHONY: build test install

build:
	@echo
	@echo " - Building..."
	@mkdir -p bin
	@if [ "$(OS)" = "Windows_NT" ]; then \
		$(CC) $(BUILD_FLAGS) /Fe:$(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c || exit 1; \
	else \
		$(CC) $(BUILD_FLAGS) -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c || exit 1; \
	fi
	@echo " - Built!"
	@echo " - Testing..."
	@sh test/report.sh || { rm -f $(BIN); exit 1; }
	@echo " - Tested!"
	@echo
	@echo "otp-toolkit $(VERSION) command is built in ./$(BIN)"
	@echo "Run 'sudo make install' now to install it system wide."
	@echo

test:
	@echo " - Testing..."
	@sh test/report.sh
	@echo " - Tested!"
	@echo

install:
	@if [ ! -f $(BIN) ]; then \
		echo "Error: $(BIN) not found - run 'make' first, then 'sudo make install'"; \
		exit 1; \
	fi
	@echo
	@echo " - Installing..."
	@if [ "$(OS)" = "Windows_NT" ]; then \
		mv ./bin/otp.exe /usr/local/bin/otp.exe; \
	else \
		mv ./bin/otp /usr/local/bin/otp; \
	fi
	@echo " - Installed! You can use \"otp\" now"
	@echo
	@mkdir -p /usr/local/share/man/man1
	@cp otp.1 /usr/local/share/man/man1/otp.1
	@echo " - Man page installed to /usr/local/share/man/man1/otp.1"

ifneq ($(OS),Windows_NT)
musl:
	@echo
	@echo " - Building musl static binary..."
	@mkdir -p bin
	@musl-gcc -static -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built!"
	@echo " - Testing..."
	@sh test/report.sh || { rm -f $(BIN); exit 1; }
	@echo " - Tested!"
	@echo

mingw:
	@echo
	@echo " - Cross-compiling Windows binary with MinGW-w64..."
	@mkdir -p bin
	@x86_64-w64-mingw32-gcc -Wall -Wextra -O2 -o bin/otp.exe src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp.exe!"
	@echo

arm64:
	@echo
	@echo " - Cross-compiling Linux arm64 binary..."
	@mkdir -p bin
	@aarch64-linux-gnu-gcc -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp (arm64)!"
	@echo

arm32:
	@echo
	@echo " - Cross-compiling Linux arm32 (hard-float) static binary..."
	@mkdir -p bin
	@arm-linux-gnueabihf-gcc -static -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp (arm32)!"
	@echo

riscv64:
	@echo
	@echo " - Cross-compiling Linux riscv64 static binary..."
	@mkdir -p bin
	@riscv64-linux-gnu-gcc -static -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp (riscv64)!"
	@echo

test-arm32: arm32
	@echo " - Testing arm32 binary under qemu..."
	@QEMU=$$(command -v qemu-arm || command -v qemu-arm-static); \
	[ -n "$$QEMU" ] || { echo "Error: qemu-arm not found (install qemu-user or qemu-user-static)"; exit 1; }; \
	mv bin/otp bin/otp.target; \
	printf '#!/bin/sh\nexec %s "$$(dirname "$$0")/otp.target" "$$@"\n' "$$QEMU" > bin/otp; \
	chmod +x bin/otp; \
	rc=0; \
	for t in otp xor keychain commit lock metadata msgmeta confirm ackfile truncate; do \
	  bash test/$$t.test.sh || rc=1; \
	done; \
	mv bin/otp.target bin/otp; \
	if [ $$rc -eq 0 ]; then echo " - Tested!"; else rm -f bin/otp; fi; \
	exit $$rc

test-riscv64: riscv64
	@echo " - Testing riscv64 binary under qemu..."
	@QEMU=$$(command -v qemu-riscv64 || command -v qemu-riscv64-static); \
	[ -n "$$QEMU" ] || { echo "Error: qemu-riscv64 not found (install qemu-user or qemu-user-static)"; exit 1; }; \
	mv bin/otp bin/otp.target; \
	printf '#!/bin/sh\nexec %s "$$(dirname "$$0")/otp.target" "$$@"\n' "$$QEMU" > bin/otp; \
	chmod +x bin/otp; \
	rc=0; \
	for t in otp xor keychain commit lock metadata msgmeta confirm ackfile truncate; do \
	  bash test/$$t.test.sh || rc=1; \
	done; \
	mv bin/otp.target bin/otp; \
	if [ $$rc -eq 0 ]; then echo " - Tested!"; else rm -f bin/otp; fi; \
	exit $$rc

install-musl: musl
	@echo
	@echo " - Installing musl binary..."
	@mv ./bin/otp /usr/local/bin/otp-musl
	@echo " - Installed! You can use \"otp-musl\" now"
	@echo
	@mkdir -p /usr/local/share/man/man1
	@cp otp.1 /usr/local/share/man/man1/otp.1
	@echo " - Man page installed to /usr/local/share/man/man1/otp.1"
	@echo
	@echo
endif
