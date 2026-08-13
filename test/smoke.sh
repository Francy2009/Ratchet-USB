#!/usr/bin/env bash
#
# End-to-end smoke test: drives the real CLI binary the way a user would.
#
# The unit tests call into the library; this one runs the shipped executable
# through a whole conversation -- two vaults, a card exchange, a first message
# that carries the X3DH handshake, and a reply that forces a DH ratchet step --
# and checks the plaintext comes out the far end. It is the only test that
# would catch a break in the layers the library tests never touch: argument
# parsing, vault file I/O, the copy-paste block encoding, and the prompts.
#
# Usage: smoke.sh <path-to-ratchet-usb-binary>

set -euo pipefail

BIN="${1:?usage: smoke.sh <path-to-ratchet-usb-binary>}"
if [[ ! -x "$BIN" ]]; then
  echo "smoke: '$BIN' is not an executable" >&2
  exit 1
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ALICE="$WORK/alice"
BOB="$WORK/bob"
mkdir -p "$ALICE" "$BOB"

ALICE_PASS="alice-smoke-passphrase"
BOB_PASS="bob-smoke-passphrase"

# Argon2id is deliberately expensive in real use. The smoke test is checking
# plumbing, not key stretching, so wind it down to keep CI quick.
CHEAP=(--argon2-time 1 --argon2-mem-kb 8192)

fail() {
  echo "smoke: FAIL: $*" >&2
  exit 1
}

step() {
  echo "smoke: $*"
}

# ---------------------------------------------------------------------------

step "creating Alice's vault"
printf '%s\n%s\n' "$ALICE_PASS" "$ALICE_PASS" |
  "$BIN" init --usb-path "$ALICE" --otpk-count 3 "${CHEAP[@]}" >"$WORK/alice-init.txt" 2>&1 ||
  fail "alice init exited non-zero"
[[ -f "$ALICE/vault.bin" ]] || fail "alice init left no vault.bin"

step "creating Bob's vault"
printf '%s\n%s\n' "$BOB_PASS" "$BOB_PASS" |
  "$BIN" init --usb-path "$BOB" --otpk-count 3 "${CHEAP[@]}" >"$WORK/bob-init.txt" 2>&1 ||
  fail "bob init exited non-zero"
[[ -f "$BOB/vault.bin" ]] || fail "bob init left no vault.bin"

# The recovery phrase must be twelve BIP-39 words, and the two vaults must not
# somehow have landed on the same identity.
# The words are laid out in numbered columns, several to a line, so count the
# "<n>. <word>" pairs rather than whitespace-separated tokens.
words="$(sed -n '/Recovery phrase/,/Write these words/p' "$WORK/alice-init.txt" |
         grep -oE '[0-9]+\.[[:space:]]+[a-z]+' | wc -l)"
[[ "$words" -eq 12 ]] || fail "expected a 12-word recovery phrase, counted $words"

step "exporting contact cards"
printf '%s\n' "$ALICE_PASS" |
  "$BIN" card --usb-path "$ALICE" >"$WORK/alice.card" 2>/dev/null ||
  fail "alice card exited non-zero"
printf '%s\n' "$BOB_PASS" |
  "$BIN" card --usb-path "$BOB" >"$WORK/bob.card" 2>/dev/null ||
  fail "bob card exited non-zero"

grep -q "BEGIN RATCHET CARD" "$WORK/alice.card" ||
  fail "alice's card is not a wire block: $(head -c 200 "$WORK/alice.card")"
grep -q "BEGIN RATCHET CARD" "$WORK/bob.card" ||
  fail "bob's card is not a wire block"

if cmp -s "$WORK/alice.card" "$WORK/bob.card"; then
  fail "both vaults produced an identical card -- key generation is not random"
fi

step "importing cards"
printf '%s\n' "$ALICE_PASS" |
  "$BIN" add --usb-path "$ALICE" bob --card "$WORK/bob.card" >/dev/null 2>&1 ||
  fail "alice failed to import bob's card"
printf '%s\n' "$BOB_PASS" |
  "$BIN" add --usb-path "$BOB" alice --card "$WORK/alice.card" >/dev/null 2>&1 ||
  fail "bob failed to import alice's card"

printf '%s\n' "$ALICE_PASS" |
  "$BIN" contacts --usb-path "$ALICE" 2>/dev/null | grep -q bob ||
  fail "bob is missing from alice's contact list"

# ---------------------------------------------------------------------------
# The conversation itself.

SECRET_A="the crow flies at midnight -- $$"

step "Alice sends the first message (carries the X3DH handshake)"
printf '%s\n' "$ALICE_PASS" |
  "$BIN" send --usb-path "$ALICE" bob "$SECRET_A" >"$WORK/msg1.txt" 2>/dev/null ||
  fail "alice send exited non-zero"

grep -q "BEGIN RATCHET MESSAGE" "$WORK/msg1.txt" ||
  fail "the message is not a wire block"

# The whole point of the tool: the plaintext must not survive into the block.
if grep -qF "the crow flies" "$WORK/msg1.txt"; then
  fail "the plaintext is readable in the encrypted block"
fi

step "Bob receives it"
printf '%s\n' "$BOB_PASS" |
  "$BIN" recv --usb-path "$BOB" "$(cat "$WORK/msg1.txt")" >"$WORK/recv1.txt" 2>/dev/null ||
  fail "bob recv exited non-zero"

grep -qF "$SECRET_A" "$WORK/recv1.txt" ||
  fail "Bob did not recover the plaintext. Got: $(cat "$WORK/recv1.txt")"

# ---------------------------------------------------------------------------
# The reply travels the other way, which forces a DH ratchet step.

SECRET_B="acknowledged, moving to the safe house -- $$"

step "Bob replies (forces a DH ratchet step)"
printf '%s\n' "$BOB_PASS" |
  "$BIN" send --usb-path "$BOB" alice "$SECRET_B" >"$WORK/msg2.txt" 2>/dev/null ||
  fail "bob send exited non-zero"

step "Alice receives the reply"
printf '%s\n' "$ALICE_PASS" |
  "$BIN" recv --usb-path "$ALICE" "$(cat "$WORK/msg2.txt")" >"$WORK/recv2.txt" 2>/dev/null ||
  fail "alice recv exited non-zero"

grep -qF "$SECRET_B" "$WORK/recv2.txt" ||
  fail "Alice did not recover the reply. Got: $(cat "$WORK/recv2.txt")"

# ---------------------------------------------------------------------------
# Out-of-order delivery: send three, deliver the third before the second.

step "Alice sends three more messages"
for i in 1 2 3; do
  printf '%s\n' "$ALICE_PASS" |
    "$BIN" send --usb-path "$ALICE" bob "ordered message $i" >"$WORK/ooo$i.txt" 2>/dev/null ||
    fail "alice send #$i exited non-zero"
done

step "Bob receives them out of order (3, 1, 2)"
for i in 3 1 2; do
  printf '%s\n' "$BOB_PASS" |
    "$BIN" recv --usb-path "$BOB" "$(cat "$WORK/ooo$i.txt")" >"$WORK/ooo-recv$i.txt" 2>/dev/null ||
    fail "bob failed to receive out-of-order message $i"
  grep -qF "ordered message $i" "$WORK/ooo-recv$i.txt" ||
    fail "out-of-order message $i did not decrypt correctly"
done

# ---------------------------------------------------------------------------
# Things that must fail.

step "a tampered message must be rejected"
# Flip a character in the middle of the base64 payload.
python3 - "$WORK/ooo1.txt" "$WORK/tampered.txt" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().splitlines()
body = [i for i, l in enumerate(lines) if l and "-----" not in l and ":" not in l]
i = body[len(body) // 2]
line = lines[i]
j = len(line) // 2
lines[i] = line[:j] + ("A" if line[j] != "A" else "B") + line[j + 1:]
open(dst, "w").write("\n".join(lines) + "\n")
PY

if printf '%s\n' "$BOB_PASS" |
     "$BIN" recv --usb-path "$BOB" "$(cat "$WORK/tampered.txt")" >"$WORK/tampered-out.txt" 2>&1; then
  fail "a tampered message was accepted"
fi

step "a wrong passphrase must be rejected"
if printf 'definitely-not-the-passphrase\n' |
     "$BIN" contacts --usb-path "$ALICE" >/dev/null 2>&1; then
  fail "the vault opened with the wrong passphrase"
fi

step "the vault must not have been written outside the given directory"
[[ ! -e "$HOME/vault.bin" ]] || fail "a vault appeared in the home directory"

echo
echo "smoke: all end-to-end checks passed"
