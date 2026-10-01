# Locked Rust dependencies

This inventory is generated from both Cargo lockfiles by
`python3 ci/check-rust-licenses.py --write`. It includes packages used
for building and testing and packages for other supported targets; it
does not claim that every entry is linked into the executable.

The expressions below are the packages' own license metadata. Their
source packages carry the complete notices. A binary release must also
provide the exact corresponding source and preserve applicable notices;
this inventory alone is not a binary redistribution package.

Packages: 174.

| Package | Version | Declared license |
| --- | --- | --- |
| `aho-corasick` | `1.1.3` | `Unlicense OR MIT` |
| `anstream` | `0.6.21` | `MIT OR Apache-2.0` |
| `anstyle` | `1.0.13` | `MIT OR Apache-2.0` |
| `anstyle-parse` | `0.2.7` | `MIT OR Apache-2.0` |
| `anstyle-query` | `1.1.5` | `MIT OR Apache-2.0` |
| `anstyle-wincon` | `3.0.11` | `MIT OR Apache-2.0` |
| `anyhow` | `1.0.104` | `MIT OR Apache-2.0` |
| `autocfg` | `1.4.0` | `Apache-2.0 OR MIT` |
| `bindgen` | `0.72.1` | `BSD-3-Clause` |
| `bit-set` | `0.8.0` | `Apache-2.0 OR MIT` |
| `bit-vec` | `0.8.0` | `Apache-2.0 OR MIT` |
| `bitflags` | `2.9.0` | `MIT OR Apache-2.0` |
| `block-buffer` | `0.12.1` | `MIT OR Apache-2.0` |
| `bytes` | `1.12.1` | `MIT` |
| `cc` | `1.3.0` | `MIT OR Apache-2.0` |
| `cexpr` | `0.6.0` | `Apache-2.0/MIT` |
| `cfg-if` | `1.0.0` | `MIT/Apache-2.0` |
| `chacha20` | `0.10.2` | `MIT OR Apache-2.0` |
| `clang-sys` | `1.8.1` | `Apache-2.0` |
| `cmov` | `0.5.4` | `Apache-2.0 OR MIT` |
| `colorchoice` | `1.0.4` | `MIT OR Apache-2.0` |
| `const-oid` | `0.10.2` | `Apache-2.0 OR MIT` |
| `core-models` | `0.0.7` | `Apache-2.0` |
| `cpufeatures` | `0.3.1` | `MIT OR Apache-2.0` |
| `crabgrind` | `0.2.6` | `MIT` |
| `crypto-common` | `0.2.2` | `MIT OR Apache-2.0` |
| `ctutils` | `0.4.2` | `Apache-2.0 OR MIT` |
| `curve25519-dalek` | `5.0.0` | `BSD-3-Clause` |
| `curve25519-dalek-derive` | `0.1.1` | `MIT/Apache-2.0` |
| `digest` | `0.11.3` | `MIT OR Apache-2.0` |
| `either` | `1.15.0` | `MIT OR Apache-2.0` |
| `env_filter` | `0.1.4` | `MIT OR Apache-2.0` |
| `env_logger` | `0.11.8` | `MIT OR Apache-2.0` |
| `equivalent` | `1.0.2` | `Apache-2.0 OR MIT` |
| `errno` | `0.3.11` | `MIT OR Apache-2.0` |
| `fastrand` | `2.3.0` | `Apache-2.0 OR MIT` |
| `fiat-crypto` | `0.3.0` | `MIT OR Apache-2.0 OR BSD-1-Clause` |
| `find-msvc-tools` | `0.1.9` | `MIT OR Apache-2.0` |
| `fixedbitset` | `0.5.7` | `MIT OR Apache-2.0` |
| `fnv` | `1.0.7` | `Apache-2.0 / MIT` |
| `galois_field_2pm` | `0.1.0` | `MIT OR Apache-2.0` |
| `getrandom` | `0.3.2` | `MIT OR Apache-2.0` |
| `getrandom` | `0.4.3` | `MIT OR Apache-2.0` |
| `glob` | `0.3.3` | `MIT OR Apache-2.0` |
| `hashbrown` | `0.15.2` | `MIT OR Apache-2.0` |
| `hax-lib` | `0.3.7` | `Apache-2.0` |
| `hax-lib-macros` | `0.3.7` | `Apache-2.0` |
| `hax-lib-macros-types` | `0.3.7` | `Apache-2.0` |
| `heck` | `0.5.0` | `MIT OR Apache-2.0` |
| `hex` | `0.4.3` | `MIT OR Apache-2.0` |
| `hkdf` | `0.13.0` | `MIT OR Apache-2.0` |
| `hmac` | `0.13.0` | `MIT OR Apache-2.0` |
| `hybrid-array` | `0.4.13` | `MIT OR Apache-2.0` |
| `indexmap` | `2.9.0` | `Apache-2.0 OR MIT` |
| `is_terminal_polyfill` | `1.70.2` | `MIT OR Apache-2.0` |
| `itertools` | `0.13.0` | `MIT OR Apache-2.0` |
| `itertools` | `0.14.0` | `MIT OR Apache-2.0` |
| `itoa` | `1.0.15` | `MIT OR Apache-2.0` |
| `jiff` | `0.2.18` | `Unlicense OR MIT` |
| `jiff-static` | `0.2.18` | `Unlicense OR MIT` |
| `libc` | `0.2.172` | `MIT OR Apache-2.0` |
| `libcrux-hacl-rs` | `0.0.5` | `Apache-2.0` |
| `libcrux-hmac` | `0.0.8` | `Apache-2.0` |
| `libcrux-intrinsics` | `0.0.8` | `Apache-2.0` |
| `libcrux-macros` | `0.0.3` | `Apache-2.0` |
| `libcrux-ml-kem` | `0.0.10` | `Apache-2.0` |
| `libcrux-platform` | `0.0.3` | `Apache-2.0` |
| `libcrux-secrets` | `0.0.6` | `Apache-2.0` |
| `libcrux-sha2` | `0.0.8` | `Apache-2.0` |
| `libcrux-sha3` | `0.0.10` | `Apache-2.0` |
| `libcrux-traits` | `0.0.8` | `Apache-2.0` |
| `libloading` | `0.8.9` | `ISC` |
| `libm` | `0.2.13` | `MIT` |
| `linux-raw-sys` | `0.9.4` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` |
| `log` | `0.4.27` | `MIT OR Apache-2.0` |
| `matches` | `0.1.10` | `MIT` |
| `memchr` | `2.7.4` | `Unlicense OR MIT` |
| `minimal-lexical` | `0.2.1` | `MIT/Apache-2.0` |
| `multimap` | `0.10.0` | `MIT OR Apache-2.0` |
| `nom` | `7.1.3` | `MIT` |
| `num-bigint` | `0.4.6` | `MIT OR Apache-2.0` |
| `num-integer` | `0.1.46` | `MIT OR Apache-2.0` |
| `num-traits` | `0.2.19` | `MIT OR Apache-2.0` |
| `num_enum` | `0.7.3` | `BSD-3-Clause OR MIT OR Apache-2.0` |
| `num_enum_derive` | `0.7.3` | `BSD-3-Clause OR MIT OR Apache-2.0` |
| `once_cell` | `1.21.3` | `MIT OR Apache-2.0` |
| `once_cell_polyfill` | `1.70.2` | `MIT OR Apache-2.0` |
| `paste` | `1.0.15` | `MIT OR Apache-2.0` |
| `pastey` | `0.2.1` | `MIT OR Apache-2.0` |
| `petgraph` | `0.7.1` | `MIT OR Apache-2.0` |
| `pkg-config` | `0.3.33` | `MIT OR Apache-2.0` |
| `portable-atomic` | `1.13.0` | `Apache-2.0 OR MIT` |
| `portable-atomic-util` | `0.2.4` | `Apache-2.0 OR MIT` |
| `ppv-lite86` | `0.2.21` | `MIT OR Apache-2.0` |
| `prettyplease` | `0.2.32` | `MIT OR Apache-2.0` |
| `proc-macro-crate` | `3.3.0` | `MIT OR Apache-2.0` |
| `proc-macro-error-attr2` | `2.0.0` | `MIT OR Apache-2.0` |
| `proc-macro-error2` | `2.0.1` | `MIT OR Apache-2.0` |
| `proc-macro2` | `1.0.95` | `MIT OR Apache-2.0` |
| `proptest` | `1.9.0` | `MIT OR Apache-2.0` |
| `prost` | `0.14.1` | `Apache-2.0` |
| `prost-build` | `0.14.1` | `Apache-2.0` |
| `prost-derive` | `0.14.1` | `Apache-2.0` |
| `prost-types` | `0.14.1` | `Apache-2.0` |
| `protoc-bin-vendored` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-linux-aarch_64` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-linux-ppcle_64` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-linux-s390_64` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-linux-x86_32` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-linux-x86_64` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-macos-aarch_64` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-macos-x86_64` | `3.2.0` | `MIT` |
| `protoc-bin-vendored-win32` | `3.2.0` | `MIT` |
| `quick-error` | `1.2.3` | `MIT/Apache-2.0` |
| `quote` | `1.0.40` | `MIT OR Apache-2.0` |
| `r-efi` | `5.2.0` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` |
| `r-efi` | `6.0.0` | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` |
| `rand` | `0.10.2` | `MIT OR Apache-2.0` |
| `rand` | `0.9.5` | `MIT OR Apache-2.0` |
| `rand_chacha` | `0.9.0` | `MIT OR Apache-2.0` |
| `rand_core` | `0.10.1` | `MIT OR Apache-2.0` |
| `rand_core` | `0.9.3` | `MIT OR Apache-2.0` |
| `rand_distr` | `0.5.1` | `MIT OR Apache-2.0` |
| `rand_xorshift` | `0.4.0` | `MIT OR Apache-2.0` |
| `ratchet-spqr-bridge` | `0.1.0` | `AGPL-3.0-only` |
| `regex` | `1.11.1` | `MIT OR Apache-2.0` |
| `regex-automata` | `0.4.9` | `MIT OR Apache-2.0` |
| `regex-syntax` | `0.8.5` | `MIT OR Apache-2.0` |
| `rustc-hash` | `2.1.3` | `Apache-2.0 OR MIT` |
| `rustc_version` | `0.4.1` | `MIT OR Apache-2.0` |
| `rustix` | `1.0.5` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` |
| `rusty-fork` | `0.3.1` | `MIT/Apache-2.0` |
| `ryu` | `1.0.20` | `Apache-2.0 OR BSL-1.0` |
| `semver` | `1.0.26` | `MIT OR Apache-2.0` |
| `serde` | `1.0.228` | `MIT OR Apache-2.0` |
| `serde_core` | `1.0.228` | `MIT OR Apache-2.0` |
| `serde_derive` | `1.0.228` | `MIT OR Apache-2.0` |
| `serde_json` | `1.0.140` | `MIT OR Apache-2.0` |
| `sha2` | `0.11.0` | `MIT OR Apache-2.0` |
| `shlex` | `1.3.0` | `MIT OR Apache-2.0` |
| `shlex` | `2.0.1` | `MIT OR Apache-2.0` |
| `sorted-vec` | `0.8.6` | `Apache-2.0` |
| `spqr` | `1.6.0` | `AGPL-3.0-only` |
| `subtle` | `2.6.1` | `BSD-3-Clause` |
| `syn` | `2.0.100` | `MIT OR Apache-2.0` |
| `tempfile` | `3.19.1` | `MIT OR Apache-2.0` |
| `thiserror` | `2.0.12` | `MIT OR Apache-2.0` |
| `thiserror-impl` | `2.0.12` | `MIT OR Apache-2.0` |
| `toml_datetime` | `0.6.8` | `MIT OR Apache-2.0` |
| `toml_edit` | `0.22.24` | `MIT OR Apache-2.0` |
| `typenum` | `1.20.1` | `MIT OR Apache-2.0` |
| `unarray` | `0.1.4` | `MIT OR Apache-2.0` |
| `unicode-ident` | `1.0.18` | `(MIT OR Apache-2.0) AND Unicode-3.0` |
| `utf8parse` | `0.2.2` | `Apache-2.0 OR MIT` |
| `uuid` | `1.16.0` | `Apache-2.0 OR MIT` |
| `wait-timeout` | `0.2.1` | `MIT/Apache-2.0` |
| `wasi` | `0.14.2+wasi-0.2.4` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` |
| `windows-link` | `0.2.1` | `MIT OR Apache-2.0` |
| `windows-sys` | `0.59.0` | `MIT OR Apache-2.0` |
| `windows-sys` | `0.61.2` | `MIT OR Apache-2.0` |
| `windows-targets` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_aarch64_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_aarch64_msvc` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_i686_gnu` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_i686_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_i686_msvc` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_x86_64_gnu` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_x86_64_gnullvm` | `0.52.6` | `MIT OR Apache-2.0` |
| `windows_x86_64_msvc` | `0.52.6` | `MIT OR Apache-2.0` |
| `winnow` | `0.7.6` | `MIT` |
| `wit-bindgen-rt` | `0.39.0` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` |
| `zerocopy` | `0.8.24` | `BSD-2-Clause OR Apache-2.0 OR MIT` |
| `zerocopy-derive` | `0.8.24` | `BSD-2-Clause OR Apache-2.0 OR MIT` |
| `zeroize` | `1.8.1` | `Apache-2.0 OR MIT` |
