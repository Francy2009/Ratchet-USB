#!/usr/bin/env bash
#
# One-shot setup: dependencies, build, tests, and an install into ~/.local/bin
# so `ratchet-usb` becomes an ordinary command. No sudo is needed for the
# install itself -- only for the system packages, and you are asked first.
#
#   ./setup.sh              install for the current user (~/.local/bin)
#   ./setup.sh --prefix /usr/local   install system-wide (needs sudo)
#   ./setup.sh --no-deps    skip the package step entirely

set -euo pipefail

PREFIX="$HOME/.local"
SKIP_DEPS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
    --no-deps) SKIP_DEPS=1; shift ;;
    -h|--help) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

cd "$(dirname "$0")"

say()  { printf '\n== %s\n' "$1"; }
fail() { printf 'error: %s\n' "$1" >&2; exit 1; }

# --- dependencies ------------------------------------------------------------
# Only the package names differ between distributions; the build itself needs
# libsodium's headers, CMake and a C++20 compiler, nothing else.
install_deps() {
  local mgr="" cmd=""
  if   command -v dnf     >/dev/null 2>&1; then mgr=dnf
  elif command -v apt-get >/dev/null 2>&1; then mgr=apt
  elif command -v pacman  >/dev/null 2>&1; then mgr=pacman
  elif command -v zypper  >/dev/null 2>&1; then mgr=zypper
  fi

  case "$mgr" in
    dnf)    cmd="sudo dnf install -y libsodium-devel cmake gcc-c++" ;;
    apt)    cmd="sudo apt-get install -y libsodium-dev cmake g++" ;;
    pacman) cmd="sudo pacman -S --needed --noconfirm libsodium cmake gcc" ;;
    zypper) cmd="sudo zypper install -y libsodium-devel cmake gcc-c++" ;;
    *)
      echo "Could not tell which package manager this system uses."
      echo "Install libsodium's development package, CMake and a C++20"
      echo "compiler by hand, then re-run with --no-deps."
      return 1 ;;
  esac

  echo "This needs to run:"
  echo "  $cmd"
  printf 'Run it now? [Y/n] '
  local answer=""
  read -r answer || answer=""
  case "$answer" in
    ""|y|Y|yes) $cmd ;;
    *) echo "Skipped. Re-run with --no-deps once the packages are in place."
       return 1 ;;
  esac
}

if [ "$SKIP_DEPS" -eq 0 ]; then
  say "Dependencies"
  install_deps || fail "dependencies are not in place"
else
  say "Dependencies (skipped)"
fi

# --- build -------------------------------------------------------------------
say "Building"
command -v cmake >/dev/null 2>&1 || fail "cmake not found"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build build -j"$(nproc 2>/dev/null || echo 2)"

# --- tests -------------------------------------------------------------------
# A failure here stops the install: a crypto tool that does not pass its own
# tests has no business being put on your PATH.
say "Tests"
ctest --test-dir build --output-on-failure

# --- install -----------------------------------------------------------------
say "Installing into $PREFIX/bin"
cmake --install build

BIN="$PREFIX/bin/ratchet-usb"
[ -x "$BIN" ] || fail "install did not produce $BIN"

say "Done"
if command -v ratchet-usb >/dev/null 2>&1; then
  echo "ratchet-usb is on your PATH:"
  echo "  $(command -v ratchet-usb)"
  echo
  echo "Plug in a USB drive and run:"
  echo "  ratchet-usb init"
else
  # ~/.local/bin is on PATH by default on most current distributions, but not
  # all, and a login shell may not have picked it up in this session yet.
  echo "Installed to $BIN, but $PREFIX/bin is not on your PATH yet."
  echo
  echo "For this session:"
  echo "  export PATH=\"$PREFIX/bin:\$PATH\""
  echo
  echo "To make it permanent:"
  echo "  echo 'export PATH=\"$PREFIX/bin:\$PATH\"' >> ~/.bashrc"
  echo
  echo "Then plug in a USB drive and run: ratchet-usb init"
fi
