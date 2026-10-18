# AGENTS.md

Ratchet-USB: a Linux-only C++20 terminal program for serverless encrypted
messaging. Test-only branch `0.5.0-dev`; no production guarantees.

## Build and test

CMake drives everything, and it **always invokes Cargo** to build the Rust SPQR
bridge (`build/cargo/release/libratchet_spqr_bridge.a`), even when you only
touched C++. The first build is slow; Rust 1.88+ (pinned in
`rust-toolchain.toml`), Cargo, OpenSSL 3.5+, libsodium, and CMake 3.16+ are
required. libsecret is optional (disables host rollback anchors).

```sh
./setup.sh --no-deps                                  # deps -> build -> ctest -> install to ~/.local/bin
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Unit tests are one binary (`build/test/ratchet_tests`) using a hand-rolled
harness (`test/test_support.hpp`: `TEST`, `CHECK`, `CHECK_EQ`, `CHECK_THROWS`).
There is **no per-test filter**; run the binary directly and read its output.
Add a new file to the `add_executable(ratchet_tests ...)` list in
`test/CMakeLists.txt`. New `src/*.cpp` must be added to the `ratchet_core`
source list in the root `CMakeLists.txt`.

Two end-to-end tests are **not** registered with ctest; run them by hand:
`./test/smoke.sh build/ratchet-usb` (real CLI conversation) and
`python3 test/smoke_ui.py build/ratchet-usb` (TUI over a real pty).

## Other verification commands

```sh
python3 test/vectors/reference.py --check             # key-schedule ref impl
python3 test/vectors/reference.py --emit > test/vectors/vectors.hpp   # after changing derivation
cargo test --manifest-path third_party/spqr/Cargo.toml --locked
cargo test --manifest-path rust/spqr_bridge/Cargo.toml --locked
python3 ci/check-rust-licenses.py --write             # then --check; update docs/RUST-DEPENDENCIES.md
./ci/check-hardening.sh build/ratchet-usb             # Release binary only
```

CI is the source of truth (`.github/workflows/ci.yml`): gcc + clang, Debug +
Release, `-Wall -Wextra -Wpedantic -Werror`, ASan/UBSan, Valgrind, clang-tidy,
and libFuzzer. The single required check is the `ci` gate job.

- **lint**: configure with `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, then
  `find src -name '*.cpp' -print0 | xargs -0 clang-tidy -p build --quiet`.
  Checks and warnings-as-errors live in `.clang-tidy`. There is no
  clang-format config (`FormatStyle: none`) — do not reformat files.
- **fuzz** (clang only): `-DRATCHET_BUILD_FUZZERS=ON -DRATCHET_BUILD_TESTS=OFF
  -DCMAKE_CXX_COMPILER=clang++`. Replay corpora with `.../fuzz_parsers
  test/fuzz/corpus -runs=0`. libFuzzer writes new inputs to its *first*
  directory argument; keep it outside `test/fuzz/corpus` (use `.fuzz-out/`) so
  the tree stays clean.

## Layout

- `src/` + `include/ratchet/` — `ratchet_core` static lib; `src/main.cpp` is
  the `ratchet-usb` executable. Both CLI (`src/cli.cpp`) and TUI
  (`src/ui.cpp`, `src/ui_model.cpp`, `src/app.cpp`) share the same core.
- `rust/spqr_bridge/` — C ABI bridge to SPQR. `third_party/spqr/` — vendored
  Signal SPQR 1.6.0 at a pinned commit. **Do not update the vendored crate**
  without a license/protocol/interop review (see `third_party/spqr/UPSTREAM.md`).
- `model/*.pv` — ProVerif formal models; not part of the build.
- `test/vectors/` — generated `vectors.hpp`, checked in and diffed by CI.
- `build/`, `rust/spqr_bridge/target/`, `third_party/spqr/target/` — artifacts;
  never commit. `vault.bin`, `*.seed` are gitignored: never let real secrets in.

## Conventions and gotchas

- Combined distribution is **AGPL-3.0-only** (`LICENSE`); original MIT text is
  preserved in `LICENSE-MIT`. Rust dependency licenses are inventoried and CI
  fails if `docs/RUST-DEPENDENCIES.md` drifts from the lockfiles.
- Naming: types CamelCase, functions/variables `lower_case`, constants
  `k`-prefixed. Comments in this tree explain *why* (rationale, security
  constraints), often at length — match that style rather than a bare-code
  default.
- Scripted/non-tty use matters: a bare `ratchet-usb` with redirected stdin must
  error with `no command given`, and `ratchet-usb ui` must refuse without a
  terminal. `test/smoke.sh` asserts both; keep CLI output stable for scripts.
- Commands share `--usb-path` / `RATCHET_USB_PATH`; `--lang it|en` forces
  locale; `NO_COLOR` disables TUI colour.
- `milestone/*` and `v0.5.0-dev` tags are published pre-releases. `v0.5.0-dev`
  stays pinned to its commit; do not move or re-point published tags.
