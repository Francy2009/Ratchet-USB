#!/usr/bin/env bash
#
# Checks that a built binary carries the executable-hardening properties the
# project relies on. Takes one or more binaries, so the CLI and the desktop GUI
# are covered by the same gate instead of only the CLI.
#
# LC_ALL=C is not cosmetic: readelf translates its own headers, so on an it_IT
# system it prints "Tipo:" where this script looks for "Type:". Without the
# forced locale the PIE check reported a correctly-built PIE binary as
# unhardened, which is a false failure now and a silently-passing gate later.
set -euo pipefail

export LC_ALL=C

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <binary> [binary...]" >&2
  exit 2
fi

status=0

fail() {
  local binary=$1
  shift
  echo "${binary}: $*" >&2
  status=1
}

for binary in "$@"; do
  if [[ ! -f "${binary}" ]]; then
    echo "${binary}: not a file" >&2
    status=1
    continue
  fi

  readelf -h "${binary}" | grep -Eq 'Type:[[:space:]]+DYN' \
    || fail "${binary}" "PIE check failed (expected ET_DYN)"

  readelf -lW "${binary}" | grep -q 'GNU_RELRO' \
    || fail "${binary}" "RELRO segment missing"

  readelf -dW "${binary}" | grep -Eq 'BIND_NOW|FLAGS.*NOW' \
    || fail "${binary}" "full RELRO/BIND_NOW missing"

  stack_flags=$(readelf -lW "${binary}" | awk '$1 == "GNU_STACK" {print $7}')
  [[ "${stack_flags}" != *E* ]] \
    || fail "${binary}" "executable stack detected"
done

if [[ ${status} -ne 0 ]]; then
  exit 1
fi

echo "hardening OK: $*"
