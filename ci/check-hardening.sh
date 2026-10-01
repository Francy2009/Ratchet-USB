#!/usr/bin/env bash
set -euo pipefail

readonly binary=${1:?binary path required}
readelf -h "${binary}" | grep -Eq 'Type:[[:space:]]+DYN' \
  || { echo "PIE check failed" >&2; exit 1; }
readelf -lW "${binary}" | grep -q 'GNU_RELRO' \
  || { echo "RELRO segment missing" >&2; exit 1; }
readelf -dW "${binary}" | grep -Eq 'BIND_NOW|FLAGS.*NOW' \
  || { echo "full RELRO/BIND_NOW missing" >&2; exit 1; }
readonly stack_flags=$(readelf -lW "${binary}" | awk '$1 == "GNU_STACK" {print $7}')
[[ "${stack_flags}" != *E* ]] \
  || { echo "executable stack detected" >&2; exit 1; }
