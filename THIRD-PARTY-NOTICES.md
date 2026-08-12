# Third-party notices

This project is MIT licensed (see `LICENSE`), but it uses a couple of things
made by other people. Here they are, for the record.

## BIP-39 English wordlist

`src/bip39_wordlist.cpp` contains the official English wordlist from the
BIP-39 standard (`bips/bip-0039/english.txt`). The wordlist itself has no
license attached in the BIP repository and is treated as public domain /
freely reusable, same as the rest of the Bitcoin Improvement Proposals. It is
copied here verbatim, unedited, because the mnemonic scheme is normative:
changing a single word would break every recovery phrase this tool has ever
produced.

## libsodium

Ratchet-USB links against [libsodium](https://libsodium.org) for every
cryptographic primitive it uses (X25519, Ed25519, ChaCha20-Poly1305,
Argon2id, HKDF/HMAC-SHA256). libsodium is not bundled with this repository,
it's a build dependency you install separately (`libsodium-dev` on
Debian/Ubuntu). It's released under the ISC license. See
https://github.com/jedisct1/libsodium/blob/master/LICENSE for the full text.
