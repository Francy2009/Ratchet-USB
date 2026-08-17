# Third-party notices

This project is MIT licensed (see `LICENSE`), but it uses a couple of things
made by other people. Here they are, for the record.

## BIP-39 English wordlist

`src/bip39_wordlist.cpp` contains the official English wordlist from the
BIP-39 standard (`bips/bip-0039/english.txt`). BIP-39 is published under the
MIT License — its preamble carries `License: MIT` and its Copyright section
states "This BIP falls under the MIT License" — so the wordlist comes with
the same terms this project uses, attribution included.

Copyright (c) the BIP-39 authors: Marek Palatinus, Pavol Rusnak, Aaron
Voisine, Sean Bowe. Specification:
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

It is copied here verbatim, unedited, because the mnemonic scheme is
normative: changing a single word would break every recovery phrase this
tool has ever produced. The copy is checked against the upstream file, whose
SHA-256 is `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.

## libsodium

Ratchet-USB links against [libsodium](https://libsodium.org) for every
cryptographic primitive it uses (X25519, Ed25519, ChaCha20-Poly1305,
Argon2id, HKDF/HMAC-SHA256). libsodium is not bundled with this repository,
it's a build dependency you install separately (`libsodium-dev` on
Debian/Ubuntu). It's released under the ISC license. See
https://github.com/jedisct1/libsodium/blob/master/LICENSE for the full text.
