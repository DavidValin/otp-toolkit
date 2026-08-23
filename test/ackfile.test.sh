#!/bin/sh

# colors for PASS/FAIL output (disabled when stdout is not a terminal)
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; NC=
fi

# --with-ack-file writes the message's source_id - the 16-byte chunk at
# the head of its key range, spent with that range but never used as pad
# - as lowercase hex, so the two correspondents can confirm delivery by
# comparing values out of band. The property that makes it a proof and
# not just a token is pinned here directly: the value written must equal
# the sender's own key bytes at the message's offset, computed from a
# copy of the key file taken before the encrypt, and the receiver's
# decrypt must independently produce the identical value from the
# ciphertext alone.

rm -rf .keychain

echo ""
echo "   - Ack reference files (--with-ack-file)"

OTP_ASSUME_DELIVERED=1
export OTP_ASSUME_DELIVERED

rm -f ack_enc.txt ack_dec.txt ack_keycopy.txt ack_plain.txt ack_cipher.bin \
      ack_out.txt ack_err.txt ack_expected.txt \
      acksender_*_ack_ref.sent.txt ackreceiver_*_ack.received.txt

dd if=/dev/urandom of=ack_enc.txt bs=1 count=2000 2>/dev/null
dd if=/dev/urandom of=ack_dec.txt bs=1 count=2000 2>/dev/null
cp ack_enc.txt ack_keycopy.txt

# The two contacts are the two ends of one pad pair: what acksender
# encrypts with is exactly what ackreceiver decrypts with.
./bin/otp --add-contact acksender ack_enc.txt ack_dec.txt > /dev/null 2>&1
./bin/otp --add-contact ackreceiver ack_dec.txt ack_enc.txt > /dev/null 2>&1

printf 'a message worth acknowledging' > ack_plain.txt

# -----------------------------------------------------------------------------
#  encrypt writes <contact>_<seq>_ack_ref.sent.txt holding the source_id
# -----------------------------------------------------------------------------
echo "     Testing the sent reference file..."

./bin/otp -c acksender --encrypt --with-ack-file < ack_plain.txt > ack_cipher.bin 2> ack_err.txt
ENC_RC=$?

if [ $ENC_RC -eq 0 ] && [ -f acksender_1_ack_ref.sent.txt ]; then
  echo "     - ${GREEN}PASS${NC} - encrypt wrote acksender_1_ack_ref.sent.txt"
else
  echo "     ! ${RED}FAIL${NC} - no sent reference file (exit $ENC_RC): $(cat ack_err.txt)"
  exit 1
fi

# The source_id is the first 16 bytes of the key range this message
# spent - taken from the copy made before the key file was truncated, so
# the expectation comes from the key material itself, not from the binary.
dd if=ack_keycopy.txt bs=1 count=16 2>/dev/null | od -An -v -tx1 | tr -d ' \n' > ack_expected.txt
echo "" >> ack_expected.txt

if cmp -s acksender_1_ack_ref.sent.txt ack_expected.txt; then
  echo "     - ${GREEN}PASS${NC} - the reference is the key's own 16 bytes at the message offset, in hex"
else
  echo "     ! ${RED}FAIL${NC} - reference $(cat acksender_1_ack_ref.sent.txt) != expected $(cat ack_expected.txt)"
  exit 1
fi

if grep -q "Ack reference written to" ack_err.txt && grep -q "send you their value" ack_err.txt; then
  echo "     - ${GREEN}PASS${NC} - stderr explains what to do with the value"
else
  echo "     ! ${RED}FAIL${NC} - stderr did not explain the reference: $(cat ack_err.txt)"
  exit 1
fi

# -----------------------------------------------------------------------------
#  decrypt extracts the same value into <contact>_<seq>_ack.received.txt
# -----------------------------------------------------------------------------
echo "     Testing the received reference file..."

./bin/otp -c ackreceiver --decrypt --with-ack-file < ack_cipher.bin > ack_out.txt 2> ack_err.txt
DEC_RC=$?

if [ $DEC_RC -eq 0 ] && cmp -s ack_out.txt ack_plain.txt; then
  echo "     - ${GREEN}PASS${NC} - the message decrypted correctly"
else
  echo "     ! ${RED}FAIL${NC} - decrypt failed (exit $DEC_RC): $(cat ack_err.txt)"
  exit 1
fi

if [ -f ackreceiver_1_ack.received.txt ]; then
  echo "     - ${GREEN}PASS${NC} - decrypt wrote ackreceiver_1_ack.received.txt"
else
  echo "     ! ${RED}FAIL${NC} - no received reference file: $(cat ack_err.txt)"
  exit 1
fi

if cmp -s ackreceiver_1_ack.received.txt acksender_1_ack_ref.sent.txt; then
  echo "     - ${GREEN}PASS${NC} - both sides derived the identical reference"
else
  echo "     ! ${RED}FAIL${NC} - references differ: sent $(cat acksender_1_ack_ref.sent.txt), received $(cat ackreceiver_1_ack.received.txt)"
  exit 1
fi

# The name in the guidance is the contact entry the operation ran
# against - on a real receiving side that entry is the sender, here it is
# this loopback keychain's "ackreceiver".
if grep -q "Send its contents to ackreceiver" ack_err.txt; then
  echo "     - ${GREEN}PASS${NC} - stderr tells the recipient to send the value back"
else
  echo "     ! ${RED}FAIL${NC} - stderr did not explain the reference: $(cat ack_err.txt)"
  exit 1
fi

# -----------------------------------------------------------------------------
#  the next message gets its own sequence-numbered file and a different
#  value: each message's source_id is its own key chunk
# -----------------------------------------------------------------------------
echo "     Testing a second message..."

printf 'second' | ./bin/otp -c acksender --encrypt --with-ack-file > ack_cipher.bin 2> ack_err.txt

if [ -f acksender_2_ack_ref.sent.txt ]; then
  echo "     - ${GREEN}PASS${NC} - the second message wrote acksender_2_ack_ref.sent.txt"
else
  echo "     ! ${RED}FAIL${NC} - no reference file for message #2: $(cat ack_err.txt)"
  exit 1
fi

if cmp -s acksender_2_ack_ref.sent.txt acksender_1_ack_ref.sent.txt; then
  echo "     ! ${RED}FAIL${NC} - message #2 reused message #1's reference"
  exit 1
else
  echo "     - ${GREEN}PASS${NC} - message #2's reference differs from message #1's"
fi

# -----------------------------------------------------------------------------
#  without the flag nothing is written: the file is opt-in
# -----------------------------------------------------------------------------
echo "     Testing that the file is opt-in..."

./bin/otp -c ackreceiver --decrypt < ack_cipher.bin > ack_out.txt 2> ack_err.txt

if [ ! -f ackreceiver_2_ack.received.txt ]; then
  echo "     - ${GREEN}PASS${NC} - a decrypt without the flag writes no reference file"
else
  echo "     ! ${RED}FAIL${NC} - a reference file appeared without --with-ack-file"
  exit 1
fi

if ! grep -q "Ack reference" ack_err.txt; then
  echo "     - ${GREEN}PASS${NC} - and says nothing about references on stderr"
else
  echo "     ! ${RED}FAIL${NC} - stderr mentioned the reference without the flag"
  exit 1
fi

# -----------------------------------------------------------------------------
#  a reference that cannot be written aborts the operation with nothing
#  spent: once the key range is destroyed the source_id is unrecoverable,
#  so a message must never cost key bytes whose reference was lost. The
#  write is made to fail by occupying its exact name with a directory.
# -----------------------------------------------------------------------------
echo "     Testing that an unwritable reference spends no key..."

KEY_BEFORE=$(wc -c < .keychain/acksender_enc.key | tr -d ' ')
META_BEFORE=$(cat .keychain/acksender.meta)
mkdir -p acksender_3_ack_ref.sent.txt

printf 'third' | ./bin/otp -c acksender --encrypt --with-ack-file > ack_out.txt 2> ack_err.txt
FAIL_RC=$?
KEY_AFTER=$(wc -c < .keychain/acksender_enc.key | tr -d ' ')

rmdir acksender_3_ack_ref.sent.txt

if [ $FAIL_RC -ne 0 ] && grep -q "could not write the ack reference" ack_err.txt; then
  echo "     - ${GREEN}PASS${NC} - the operation failed with an explanatory error"
else
  echo "     ! ${RED}FAIL${NC} - expected a failure (exit $FAIL_RC): $(cat ack_err.txt)"
  exit 1
fi

if [ "$KEY_AFTER" = "$KEY_BEFORE" ] && [ "$META_BEFORE" = "$(cat .keychain/acksender.meta)" ]; then
  echo "     - ${GREEN}PASS${NC} - no key material was consumed ($KEY_BEFORE bytes before and after)"
else
  echo "     ! ${RED}FAIL${NC} - key or metadata changed: $KEY_BEFORE -> $KEY_AFTER bytes"
  exit 1
fi

if [ ! -s ack_out.txt ]; then
  echo "     - ${GREEN}PASS${NC} - no ciphertext was emitted"
else
  echo "     ! ${RED}FAIL${NC} - $(wc -c < ack_out.txt) bytes of ciphertext were emitted anyway"
  exit 1
fi

# -----------------------------------------------------------------------------
#  mid-crash: a run killed immediately after the reference is published
#  has spent nothing, and the retry recomputes the identical value - the
#  source_id depends on the key file and offset, never on the message
# -----------------------------------------------------------------------------
echo "     Testing a crash right after the reference is published..."

KEY_BEFORE=$(wc -c < .keychain/acksender_enc.key | tr -d ' ')

printf 'third' | OTP_TEST_CRASH_POINT=after_ack_publish \
  ./bin/otp -c acksender --encrypt --with-ack-file > ack_out.txt 2> ack_err.txt
CRASH_RC=$?
KEY_AFTER=$(wc -c < .keychain/acksender_enc.key | tr -d ' ')

if [ $CRASH_RC -eq 77 ] && [ -f acksender_3_ack_ref.sent.txt ]; then
  echo "     - ${GREEN}PASS${NC} - the crashed run left the reference file behind"
else
  echo "     ! ${RED}FAIL${NC} - expected exit 77 with a reference file (exit $CRASH_RC)"
  exit 1
fi

if [ "$KEY_AFTER" = "$KEY_BEFORE" ]; then
  echo "     - ${GREEN}PASS${NC} - the crashed run spent no key material"
else
  echo "     ! ${RED}FAIL${NC} - key changed across the crash: $KEY_BEFORE -> $KEY_AFTER bytes"
  exit 1
fi

cp acksender_3_ack_ref.sent.txt ack_crashref.txt

printf 'third' | ./bin/otp -c acksender --encrypt --with-ack-file > ack_cipher.bin 2> ack_err.txt
RETRY_RC=$?

if [ $RETRY_RC -eq 0 ] && cmp -s acksender_3_ack_ref.sent.txt ack_crashref.txt; then
  echo "     - ${GREEN}PASS${NC} - the retry republished a byte-identical reference"
else
  echo "     ! ${RED}FAIL${NC} - the retry produced a different reference (exit $RETRY_RC)"
  exit 1
fi

if ./bin/otp -c ackreceiver --decrypt --with-ack-file < ack_cipher.bin > ack_out.txt 2>/dev/null &&
   cmp -s ackreceiver_3_ack.received.txt ack_crashref.txt; then
  echo "     - ${GREEN}PASS${NC} - the receiver's reference matches the one the crash left"
else
  echo "     ! ${RED}FAIL${NC} - the receiver derived a different reference"
  exit 1
fi

if [ ! -f acksender_3_ack_ref.sent.txt.tmp ] && [ ! -f ackreceiver_3_ack.received.txt.tmp ]; then
  echo "     - ${GREEN}PASS${NC} - no staging file was left behind"
else
  echo "     ! ${RED}FAIL${NC} - a .tmp staging file survived"
  exit 1
fi

# -----------------------------------------------------------------------------
#  cleanup
# -----------------------------------------------------------------------------

echo "     Cleaning up test files..."
rm -f ack_enc.txt ack_dec.txt ack_keycopy.txt ack_plain.txt ack_cipher.bin \
      ack_out.txt ack_err.txt ack_expected.txt \
      ack_crashref.txt \
      acksender_1_ack_ref.sent.txt acksender_2_ack_ref.sent.txt \
      acksender_3_ack_ref.sent.txt \
      ackreceiver_1_ack.received.txt ackreceiver_3_ack.received.txt
rm -rf .keychain
exit 0
