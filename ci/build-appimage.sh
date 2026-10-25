#!/usr/bin/env bash
# Package an already-built ratchet-usb tree (CLI + GUI) into a single AppImage.
#
# The AppImage is meant to run on machines that have none of this project's
# dependencies installed, so the point of this script is that linuxdeploy pulls
# every shared library the binaries need into the bundle. ci/verify-appimage.sh
# then proves it by extracting the result and running ldd over it.
#
# Usage: ci/build-appimage.sh [build-dir] [output-appimage]
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly build_dir="${1:-${repo_root}/build}"
readonly output="${2:-${build_dir}/Ratchet-USB-x86_64.AppImage}"
readonly arch="x86_64"

# Pinned packaging tools. Their URLs are checked against a SHA-256 before use,
# for the same reason every other downloaded artifact in this tree is: a
# mutable "latest" download is a supply-chain hole, not a convenience.
readonly linuxdeploy_url="https://github.com/linuxdeploy/linuxdeploy/releases/download/1-alpha-20251107-1/linuxdeploy-x86_64.AppImage"
readonly linuxdeploy_sha256="c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d"
readonly qt_plugin_url="https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/1-alpha-20250213-1/linuxdeploy-plugin-qt-x86_64.AppImage"
readonly qt_plugin_sha256="15106be885c1c48a021198e7e1e9a48ce9d02a86dd0a1848f00bdbf3c1c92724"
readonly appimagetool_url="https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"
readonly appimagetool_sha256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"

readonly tools_dir="${build_dir}/appimage-tools"
readonly appdir="${build_dir}/AppDir"

fetch_verified() {
  local name="$1" url="$2" expected="$3"
  local dest="${tools_dir}/${name}"
  if [[ -x "${dest}" ]]; then
    return 0
  fi
  mkdir -p "${tools_dir}"
  echo "downloading ${name}" >&2
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    "${url}" --output "${dest}.part"
  local actual
  actual="$(sha256sum "${dest}.part")"
  actual="${actual%%[[:space:]]*}"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${name}: checksum mismatch" >&2
    echo "  expected ${expected}" >&2
    echo "  actual   ${actual}" >&2
    rm -f "${dest}.part"
    exit 1
  fi
  mv "${dest}.part" "${dest}"
  chmod +x "${dest}"
}

fetch_verified linuxdeploy "${linuxdeploy_url}" "${linuxdeploy_sha256}"
fetch_verified linuxdeploy-plugin-qt "${qt_plugin_url}" "${qt_plugin_sha256}"
fetch_verified appimagetool "${appimagetool_url}" "${appimagetool_sha256}"

echo "staging AppDir at ${appdir}" >&2
rm -rf "${appdir}"
DESTDIR="${appdir}" cmake --install "${build_dir}" --prefix /usr

for binary in ratchet-usb ratchet-gui; do
  if [[ ! -x "${appdir}/usr/bin/${binary}" ]]; then
    echo "expected ${appdir}/usr/bin/${binary} after install" >&2
    exit 1
  fi
done

install -Dm644 "${repo_root}/ci/ratchet-usb.desktop" \
  "${appdir}/usr/share/applications/ratchet-usb.desktop"
install -Dm644 "${repo_root}/ci/ratchet-usb.png" \
  "${appdir}/usr/share/icons/hicolor/256x256/apps/ratchet-usb.png"

# linuxdeploy runs as an AppImage; extracting-and-running avoids needing FUSE.
export APPIMAGE_EXTRACT_AND_RUN=1
export ARCH="${arch}"
export OUTPUT="${output}"
export PATH="${tools_dir}:${PATH}"
# linuxdeploy-plugin-qt needs qmake to locate the Qt installation and its
# plugins; on Ubuntu it is qmake6.
if [[ -z "${QMAKE:-}" ]]; then
  QMAKE="$(command -v qmake6 || command -v qmake || true)"
  export QMAKE
fi

echo "running linuxdeploy" >&2
"${tools_dir}/linuxdeploy" \
  --appdir "${appdir}" \
  --desktop-file "${appdir}/usr/share/applications/ratchet-usb.desktop" \
  --icon-file "${appdir}/usr/share/icons/hicolor/256x256/apps/ratchet-usb.png" \
  --custom-apprun "${repo_root}/ci/AppRun" \
  --plugin qt \
  --output appimage

if [[ ! -f "${output}" ]]; then
  echo "linuxdeploy did not produce ${output}" >&2
  exit 1
fi
echo "${output}"
