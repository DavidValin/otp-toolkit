#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# --xor (-x) is the raw plumbing mode: stdin XORed against a key file's
# bytes from offset 0, straight to stdout, deliberately outside the
# keychain. The expected bytes are computed independently of the binary
# under test (test/xor.helper.sh), and the key file must come out
# byte-identical afterwards - what separates this mode from
# -c <contact> --encrypt is precisely that nothing is consumed, tracked
# or truncated. The failure paths matter as much: a key shorter than the
# input must fail loudly rather than silently emit unprotected bytes.

. test/xor.helper.sh

echo ""
echo "   - Raw XOR mode (--xor / -x)"

rm -rf x_key.tmp x_plain.tmp x_cipher.tmp x_expected.tmp x_back.tmp \
       x_short.tmp x_out.tmp x_err.tmp x_keycopy.tmp

# -----------------------------------------------------------------------------
#  the output is exactly plaintext XOR key, computed by different code
# -----------------------------------------------------------------------------
echo "     Testing stdin is XORed against the key file..."

dd if=/dev/urandom of=x_key.tmp bs=1024 count=64 2>/dev/null
printf 'the quick brown fox jumps over the lazy dog' > x_plain.tmp
cp x_key.tmp x_keycopy.tmp

# The suite shares one working directory, so a .keychain left by an
# earlier script may already exist: snapshot it rather than assuming it
# is absent, and assert --xor changed nothing about it either way.
keychain_snapshot() {
  if [ -d .keychain ]; then
    find .keychain -type f -exec cksum {} \; | sort
  else
    echo "NO KEYCHAIN"
  fi
}
KEYCHAIN_BEFORE=$(keychain_snapshot)

./bin/otp --xor x_key.tmp < x_plain.tmp > x_cipher.tmp 2> x_err.tmp
XOR_RC=$?
xor_with_key x_key.tmp x_plain.tmp x_expected.tmp

if [ $XOR_RC -eq 0 ] && cmp -s x_cipher.tmp x_expected.tmp; then
  echo "     - ${GREEN}PASS${NC} - output equals the independently computed plaintext XOR key"
else
  echo "     ! ${RED}FAIL${NC} - output did not match the expected XOR (exit $XOR_RC): $(cat x_err.tmp)"
  exit 1
fi

if cmp -s x_key.tmp x_keycopy.tmp; then
  echo "     - ${GREEN}PASS${NC} - the key file is byte-identical afterwards (nothing consumed)"
else
  echo "     ! ${RED}FAIL${NC} - the key file was modified by --xor"
  exit 1
fi

if [ "$(keychain_snapshot)" = "$KEYCHAIN_BEFORE" ]; then
  echo "     - ${GREEN}PASS${NC} - the keychain is untouched (nothing created, nothing recorded)"
else
  echo "     ! ${RED}FAIL${NC} - --xor changed the keychain"
  exit 1
fi

# -----------------------------------------------------------------------------
#  XOR is its own inverse: the same invocation decrypts, and -x is the
#  same command as --xor
# -----------------------------------------------------------------------------
echo "     Testing the same invocation reverses itself..."

./bin/otp -x x_key.tmp < x_cipher.tmp > x_back.tmp 2> x_err.tmp
BACK_RC=$?

if [ $BACK_RC -eq 0 ] && cmp -s x_back.tmp x_plain.tmp; then
  echo "     - ${GREEN}PASS${NC} - re-XORing the output with the same key returns the input"
else
  echo "     ! ${RED}FAIL${NC} - round trip did not return the original (exit $BACK_RC): $(cat x_err.tmp)"
  exit 1
fi

# -----------------------------------------------------------------------------
#  binary safety: every byte value, NUL included, must survive
# -----------------------------------------------------------------------------
echo "     Testing arbitrary binary input..."

dd if=/dev/urandom of=x_plain.tmp bs=1024 count=32 2>/dev/null
./bin/otp --xor x_key.tmp < x_plain.tmp > x_cipher.tmp 2>/dev/null
./bin/otp --xor x_key.tmp < x_cipher.tmp > x_back.tmp 2>/dev/null

if cmp -s x_back.tmp x_plain.tmp; then
  echo "     - ${GREEN}PASS${NC} - 32KB of random bytes round-trip unchanged"
else
  echo "     ! ${RED}FAIL${NC} - binary input did not round-trip"
  exit 1
fi

# -----------------------------------------------------------------------------
#  a key shorter than the input is an error, not a silent short read
# -----------------------------------------------------------------------------
echo "     Testing a key file shorter than the input..."

printf 'tiny' > x_short.tmp
./bin/otp --xor x_short.tmp < x_plain.tmp > x_out.tmp 2> x_err.tmp
SHORT_RC=$?

if [ $SHORT_RC -ne 0 ] && grep -q "shorter than the input" x_err.tmp; then
  echo "     - ${GREEN}PASS${NC} - a short key fails with an explanatory error"
else
  echo "     ! ${RED}FAIL${NC} - expected a short-key rejection (exit $SHORT_RC): $(cat x_err.tmp)"
  exit 1
fi

if [ ! -s x_out.tmp ]; then
  echo "     - ${GREEN}PASS${NC} - no bytes were emitted for a chunk the key cannot cover"
else
  echo "     ! ${RED}FAIL${NC} - $(wc -c < x_out.tmp) bytes were emitted despite the short key"
  exit 1
fi

# -----------------------------------------------------------------------------
#  usage errors
# -----------------------------------------------------------------------------
echo "     Testing usage errors..."

printf 'x' | ./bin/otp --xor > x_out.tmp 2> x_err.tmp
NOARG_RC=$?
if [ $NOARG_RC -ne 0 ] && [ ! -s x_out.tmp ] && grep -q "requires <bytes>" x_err.tmp; then
  echo "     - ${GREEN}PASS${NC} - --xor without a <bytes> argument fails with usage"
else
  echo "     ! ${RED}FAIL${NC} - expected a usage error (exit $NOARG_RC): $(cat x_err.tmp)"
  exit 1
fi

printf 'x' | ./bin/otp -x x_missing_key.tmp > x_out.tmp 2> x_err.tmp
MISSING_RC=$?
if [ $MISSING_RC -ne 0 ] && [ ! -s x_out.tmp ] && grep -q "Cannot open" x_err.tmp; then
  echo "     - ${GREEN}PASS${NC} - a nonexistent <bytes> file fails without emitting output"
else
  echo "     ! ${RED}FAIL${NC} - expected an open error (exit $MISSING_RC): $(cat x_err.tmp)"
  exit 1
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -f x_key.tmp x_plain.tmp x_cipher.tmp x_expected.tmp x_back.tmp \
      x_short.tmp x_out.tmp x_err.tmp x_keycopy.tmp
exit 0
