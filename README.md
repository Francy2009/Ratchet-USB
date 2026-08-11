# Ratchet-USB

CLI tool for over-the-top encrypted messaging: the ciphertext is produced
locally and pasted by hand into whatever channel is at hand (WhatsApp, e-mail,
a forum post). The channel only ever carries opaque text.

Everything sensitive lives on a removable drive. The tool never writes to the
host's filesystem: the vault path is always taken from `--usb-path`.

**Status: phase 1 only** — seed generation and the encrypted vault. There is no
ratchet and no X3DH key agreement yet; those come next and will build on the
identity key derived here.

## Build

Requires a C++20 compiler, CMake ≥ 3.16 and libsodium (1.0.19 or newer
preferred, see *HKDF* below). libsodium is the only dependency, for the tests
too.

```sh
sudo apt install libsodium-dev cmake g++      # Debian/Ubuntu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Usage

```sh
# create the vault on the USB drive
ratchet-usb init --usb-path /media/usb

# check the vault opens and show the identity
ratchet-usb unlock --usb-path /media/usb
```

`init` generates 128 bits from `randombytes_buf`, shows them as a 12-word
BIP-39 phrase, asks for a passphrase (twice, without echo), and writes
`<usb-path>/vault.bin` with mode `0600`. The 12 words are shown once and never
stored: they are the only backup, and anyone who reads them owns the identity.

`unlock` asks for the passphrase, decrypts the vault, and prints the identity
**public** key. The private key and the seed never leave memory and are wiped as
soon as the command returns.

Argon2id cost can be tuned with `--argon2-time` and `--argon2-mem-kb`; the
values used are stored in the vault header, so a vault written on a fast machine
still opens on a slow one.

## Cryptography

| Step | Primitive |
| --- | --- |
| Entropy | `randombytes_buf`, 128 bits |
| Backup encoding | BIP-39, English wordlist, 12 words |
| Master seed | HKDF-SHA256-Extract(salt = `Ratchet-USB/v1/master-seed`, ikm = entropy) |
| Identity key | HKDF-SHA256-Expand(seed, `Ratchet-USB/v1/identity-x25519`), clamped, X25519 |
| Passphrase → key | Argon2id, 16-byte salt, defaults 256 MiB / 3 passes |
| Vault | ChaCha20-Poly1305 (IETF), header authenticated as AAD |

The mnemonic encodes the *entropy*, and the master seed is derived from it with
HKDF rather than with BIP-39's own PBKDF2 construction. Two consequences worth
knowing:

- the 12 words alone are a complete backup — the vault passphrase protects the
  file on the drive, it is not mixed into the seed;
- these words will **not** reproduce the same keys in a Bitcoin wallet, and a
  wallet's words will not reproduce a Ratchet-USB identity. The wordlist is the
  standard one, the derivation is not.

Every buffer holding key material is a `SecureBytes`/`SecureString`: locked in
RAM with `sodium_mlock` where the OS permits it, and wiped with
`sodium_memzero` on destruction. They cannot be copied, so a secret cannot
silently acquire a second lifetime.

### HKDF

The build uses `crypto_kdf_hkdf_sha256_*` when libsodium provides it (1.0.19
and later). Against older releases CMake falls back to an in-tree RFC 5869
implementation on top of `crypto_auth_hmacsha256`; both paths are checked
against the RFC's own test vectors, so the derived keys are identical either
way and a vault stays portable between the two.

## Vault format

`vault.bin` is exactly 121 bytes:

```
offset  size  field
0       4     magic "RCHT"
4       1     version (1)
5       16    Argon2id salt
21      4     Argon2id time cost      (uint32, little-endian)
25      4     Argon2id memory in KiB  (uint32, little-endian)
29      12    ChaCha20-Poly1305 nonce
41      64    ciphertext: seed (32) || identity private key (32)
105     16    Poly1305 tag
```

The 41-byte header is serialised field by field, not dumped as a struct, so the
file does not depend on the compiler's padding. The whole header is passed to
the AEAD as additional data: altering the salt, the nonce or the cost
parameters makes decryption fail rather than quietly deriving a different key.
A wrong passphrase and a tampered file report the same error on purpose.

The cost fields are read back from a file an attacker may have written, so they
are range-checked (time 1–64, memory 8 KiB–4 GiB) before reaching Argon2.

## Layout

```
include/ratchet/   public headers
src/               implementation + the BIP-39 wordlist
test/              unit tests (no external framework)
```

## Threat model, briefly

Protects against: someone who obtains the USB drive without the passphrase, and
anyone reading the transport channel.

Does not protect against: a compromised host (a keylogger sees the passphrase),
someone who reads the 12 words, or the fact that a person keeps writing to you
on a channel that records the ciphertext.
