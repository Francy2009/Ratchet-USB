#!/usr/bin/env bash
# Post-packaging self-containment check.
#
# Extracts the AppImage and proves two things that decide whether it runs on a
# machine that has none of this project's dependencies:
#
#   1. ldd over every bundled ELF finds no "not found" -- nothing is expected to
#      be present on the target that is not either bundled or part of the base
#      system (glibc and the X/GL stack AppImages intentionally rely on);
#   2. the libraries that are this project's own dependencies are actually in
#      the bundle: libsodium and Qt. The core's OpenSSL is built no-shared and
#      linked in statically; any libcrypto that shows up as a runtime dependency
#      (Qt's networking/image stack pulls one in) must therefore be bundled.
#
# Usage: ci/verify-appimage.sh <path-to-AppImage>
set -euo pipefail

appimage="${1:?usage: $0 <path-to-AppImage>}"
if [[ ! -f "${appimage}" ]]; then
  echo "no such AppImage: ${appimage}" >&2
  exit 2
fi
appimage="$(cd "$(dirname "${appimage}")" && pwd)/$(basename "${appimage}")"

readonly work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

echo "extracting ${appimage}" >&2
cd "${work_dir}"
# --appimage-extract is handled by the runtime and needs no FUSE.
"${appimage}" --appimage-extract >/dev/null

readonly root="${work_dir}/squashfs-root"
if [[ ! -d "${root}" ]]; then
  echo "extraction produced no squashfs-root" >&2
  exit 1
fi

lib_dirs=()
for candidate in "${root}/usr/lib" "${root}/usr/lib/x86_64-linux-gnu"; do
  [[ -d "${candidate}" ]] && lib_dirs+=("${candidate}")
done
if [[ ${#lib_dirs[@]} -eq 0 ]]; then
  echo "the AppImage bundles no libraries at all" >&2
  exit 1
fi
# The bundled libraries are resolved through the RUNPATH linuxdeploy sets
# ($ORIGIN/../lib for binaries, $ORIGIN for libraries), so this is only for the
# explicit liveness run below. It is deliberately not exported: pointing
# LD_LIBRARY_PATH at the bundle would make the system tools this script runs
# (find, grep, ldd) load bundled copies of libraries they use.
readonly bundle_lib_path="$(IFS=:; echo "${lib_dirs[*]}")"

status=0

echo "checking ldd for unresolved shared libraries" >&2
while IFS= read -r -d '' elf; do
  output="$(ldd "${elf}" 2>/dev/null || true)"
  if grep -q 'not found' <<<"${output}"; then
    echo "missing shared library for ${elf}" >&2
    grep 'not found' <<<"${output}" | sed 's/^/    /' >&2
    status=1
  fi
done < <(find "${root}/usr/bin" "${root}/usr/lib" "${root}/usr/plugins" \
  -type f -print0 2>/dev/null)

require_glob() {
  local pattern="$1"
  if ! find "${lib_dirs[@]}" -maxdepth 1 -name "${pattern}" | grep -q .; then
    echo "expected bundled library matching '${pattern}' is missing" >&2
    status=1
  fi
}

require_glob 'libsodium.so.*'
require_glob 'libQt6Core.so.*'
require_glob 'libQt6Gui.so.*'
require_glob 'libQt6Widgets.so.*'

if ldd "${root}/usr/bin/ratchet-usb" | grep -qi 'libcrypto'; then
  require_glob 'libcrypto.so.*'
  echo "OpenSSL: shared, and bundled" >&2
else
  echo "OpenSSL: statically linked (no runtime libcrypto dependency)" >&2
fi

if ! find "${root}" -name 'libqxcb.so' | grep -q .; then
  echo "the Qt xcb platform plugin (libqxcb.so) is not bundled; the GUI would not start on another machine" >&2
  status=1
fi

# A cheap liveness check: the bundled CLI must run from the extracted tree.
if version="$(LD_LIBRARY_PATH="${bundle_lib_path}" "${root}/usr/bin/ratchet-usb" --version 2>/dev/null)"; then
  echo "bundled CLI runs: ${version}" >&2
else
  echo "the bundled CLI failed to run" >&2
  status=1
fi

echo
echo "Bundled shared libraries (${#lib_dirs[@]} dir(s)):"
find "${lib_dirs[@]}" -maxdepth 1 -name '*.so*' -printf '%f\n' | sort -u | sed 's/^/  /'

if [[ ${status} -ne 0 ]]; then
  echo >&2
  echo "AppImage self-containment check FAILED" >&2
  exit 1
fi
echo >&2
echo "AppImage self-containment check passed" >&2
