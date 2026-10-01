# Third-party notices

The combined Ratchet-USB distribution that includes Signal SPQR is licensed
under AGPL-3.0-only (see `LICENSE`). The original Ratchet-USB code was
published under MIT; its earlier license text is retained in `LICENSE-MIT`.
Third-party components and their separate notices follow.

## Signal Sparse Post-Quantum Ratchet (SPQR)

`third_party/spqr` contains Signal Messenger's SPQR version 1.6.0 from commit
`06959b4708f9b7b1e94d0f8cc835f3958c077e94`. It is licensed under
AGPL-3.0-only; its complete license and source notices are retained in that
directory. The local build patch is documented in `third_party/spqr/UPSTREAM.md`.
The Rust bridge links SPQR into the Ratchet-USB executable. The combined
distribution is therefore distributed under AGPL-3.0-only terms.

The Rust dependencies resolved by the two committed Cargo lockfiles are listed
with their declared licenses in
[`docs/RUST-DEPENDENCIES.md`](docs/RUST-DEPENDENCIES.md). This list also includes
build, test and other-target dependencies. The exact source packages retain
their own notices. A future binary distribution must provide the corresponding
source and applicable notices for the dependencies it actually links; the
inventory alone does not satisfy those distribution obligations.

## BIP-39 English wordlist

`src/bip39_wordlist.cpp` contains the official English wordlist from the
BIP-39 standard (`bips/bip-0039/english.txt`). BIP-39 is published under the
MIT License. Its preamble carries `License: MIT` and its Copyright section
states "This BIP falls under the MIT License". That notice remains applicable
to the wordlist inside this AGPL distribution.

Copyright (c) the BIP-39 authors: Marek Palatinus, Pavol Rusnak, Aaron
Voisine, Sean Bowe. Specification:
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

It is copied here verbatim, unedited, because the mnemonic scheme is
normative: changing a single word would break every recovery phrase this
tool has ever produced. The copy is checked against the upstream file, whose
SHA-256 is `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.

## libsodium

Ratchet-USB links against [libsodium](https://libsodium.org) for its classical
primitives (X25519, Ed25519, ChaCha20-Poly1305, Argon2id and HKDF/HMAC-SHA256).
Post-quantum operations use OpenSSL and the vendored SPQR dependencies.
libsodium is not bundled with this repository,
it's a build dependency you install separately (`libsodium-dev` on
Debian/Ubuntu). It's released under the ISC license. See
https://github.com/jedisct1/libsodium/blob/master/LICENSE for the full text.

## OpenSSL

Ratchet-USB requires OpenSSL Crypto 3.5 or newer for the standardized
ML-KEM-768 and ML-DSA-65 EVP implementations. No post-quantum primitive is
implemented locally. OpenSSL is used under the Apache License 2.0; CI builds
the 3.5.9 LTS source archive pinned by SHA-256.

## Secret Service and macOS Keychain

Rollback anchors use libsecret/Secret Service when available on Linux and the
Security framework on macOS. They are optional build/platform integrations;
without one, the program visibly reports rollback-unprotected USB-only mode.
