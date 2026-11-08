#!/usr/bin/env bash
# End-to-end group text and file delivery through the GUI's structured CLI.
set -euo pipefail
BIN="${1:?usage: smoke_group_gui.sh <path-to-ratchet-usb>}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export XDG_RUNTIME_DIR="$WORK/runtime"
mkdir -m 700 "$XDG_RUNTIME_DIR"
phrase() {
  sed -n '/Vault passphrase (write/,/These words unlock/p' "$1" |
    grep -oE '[0-9]+\.[[:space:]]+[a-z]+' | sed -E 's/[0-9]+\.[[:space:]]+//' |
    paste -sd' ' - | sed -E 's/ +$//'
}
for name in alice bob carol; do
  mkdir "$WORK/$name"
  "$BIN" init --usb-path "$WORK/$name" --otpk-count 3 --argon2-time 3 \
    --argon2-mem-kb 65536 </dev/null >"$WORK/$name.init" 2>&1
  phrase "$WORK/$name.init" >"$WORK/$name.pass"
  test "$(wc -w <"$WORK/$name.pass")" -eq 12
  "$BIN" card --usb-path "$WORK/$name" <"$WORK/$name.pass" >"$WORK/$name.card" 2>/dev/null
done
for name in bob carol; do
  "$BIN" add --usb-path "$WORK/alice" "$name" --card "$WORK/$name.card" <"$WORK/alice.pass" >/dev/null 2>&1
  "$BIN" add --usb-path "$WORK/$name" alice --card "$WORK/alice.card" <"$WORK/$name.pass" >/dev/null 2>&1
  "$BIN" trust --usb-path "$WORK/alice" "$name" --confirmed <"$WORK/alice.pass" >/dev/null 2>&1
  "$BIN" trust --usb-path "$WORK/$name" alice --confirmed <"$WORK/$name.pass" >/dev/null 2>&1
done
"$BIN" group-send --usb-path "$WORK/alice" --to bob --to carol --ttl 1h --burn 'group secret' <"$WORK/alice.pass" >"$WORK/group" 2>/dev/null
for name in bob carol; do
  "$BIN" recv --usb-path "$WORK/$name" --structured-output "$(cat "$WORK/group")" <"$WORK/$name.pass" >"$WORK/$name.text" 2>/dev/null
  grep -q 'group secret' "$WORK/$name.text"
  grep -q '^kind=text$' "$WORK/$name.text"
  grep -q '^ttl=1h$' "$WORK/$name.text"
  grep -q '^burn=yes$' "$WORK/$name.text"
done
printf 'file for both recipients\n' >"$WORK/document.txt"
"$BIN" group-send --usb-path "$WORK/alice" --to bob --to carol --file "$WORK/document.txt" --ttl 24h --burn <"$WORK/alice.pass" >"$WORK/group-file" 2>/dev/null
for name in bob carol; do
  "$BIN" recv --usb-path "$WORK/$name" --stage-file --structured-output "$(cat "$WORK/group-file")" <"$WORK/$name.pass" >"$WORK/$name.file" 2>/dev/null
  grep -q '^kind=file$' "$WORK/$name.file"
  grep -q '^ttl=24h$' "$WORK/$name.file"
  grep -q '^burn=yes$' "$WORK/$name.file"
  grep -q '^staged=yes$' "$WORK/$name.file"
  staged="$(sed -n 's/^path=//p' "$WORK/$name.file")"
  cmp "$WORK/document.txt" "$staged"
done
# Exercise the actual GUI stdin framing with a near-limit binary file, rather
# than putting the multi-megabyte ciphertext in argv.
dd if=/dev/zero of="$WORK/large.bin" bs=4194240 count=1 status=none
"$BIN" group-send --usb-path "$WORK/alice" --to bob --to carol --file "$WORK/large.bin" --ttl 1h <"$WORK/alice.pass" >"$WORK/large-group" 2>/dev/null
bytes="$(wc -c <"$WORK/large-group")"
cat "$WORK/large-group" "$WORK/bob.pass" |
  "$BIN" recv --usb-path "$WORK/bob" --stage-file --structured-output --stdin-payload "$bytes" >"$WORK/large-result" 2>/dev/null
grep -q '^kind=file$' "$WORK/large-result"
grep -q '^ttl=1h$' "$WORK/large-result"
staged="$(sed -n 's/^path=//p' "$WORK/large-result")"
cmp "$WORK/large.bin" "$staged"
if "$BIN" group-send --usb-path "$WORK/alice" --to bob --to carol --file "$WORK/document.txt" 'ambiguous text' <"$WORK/alice.pass" >/dev/null 2>"$WORK/error"; then
  echo 'group-send accepted a file and message together' >&2
  exit 1
fi
grep -q -- '--file cannot be combined' "$WORK/error"
if "$BIN" group-send --usb-path "$WORK/alice" --to bob --to carol --file "$WORK/document.txt" --stdin-payload 1 </dev/null >/dev/null 2>"$WORK/error"; then
  echo 'group-send accepted a file and stdin payload together' >&2
  exit 1
fi
grep -q -- '--file cannot be combined' "$WORK/error"
echo 'group GUI smoke: passed'
