# Ratchet-USB

CLI tool for over-the-top encrypted messaging: the ciphertext is produced
locally and pasted by hand into whatever channel is at hand (WhatsApp, e-mail,
a forum post). The channel only ever carries opaque text.

Everything sensitive lives on a removable drive. The tool never writes to the
host's filesystem: the vault path is always taken from `--usb-path`.

**Status: phase 2** — seed generation, the encrypted vault, X3DH key agreement
and Double Ratchet messaging. Sending and receiving works end to end. Not yet
done: group conversations, multi-device, and anything resembling key
transparency (see *Out of scope*).

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
# on Alice's drive: create the vault
ratchet-usb init --usb-path /media/usb

# print Alice's contact card and send it to Bob out of band
ratchet-usb card --usb-path /media/usb

# on Bob's drive, after doing the same init/card dance and getting Alice's card
ratchet-usb add-contact --usb-path /media/usb --name alice --card alice_card.txt
ratchet-usb trust --usb-path /media/usb --name alice   # after checking the fingerprint

# Bob writes to Alice; the first send runs the X3DH handshake automatically
ratchet-usb send --usb-path /media/usb --to alice --message "hi" > msg.txt
# msg.txt gets pasted into WhatsApp/email/whatever; Alice pastes it back out

# on Alice's drive
ratchet-usb recv --usb-path /media/usb --message "$(cat msg.txt)"
```

### Commands

| Command | Does |
| --- | --- |
| `init` | Generates the seed, shows the 12-word backup, creates the vault (identity, one signed prekey, a batch of one-time prekeys). |
| `unlock` | Decrypts the vault and prints the identity fingerprint, without touching anything. |
| `card` | Prints this identity's contact card (base64 block) to share. `--rotate-spk` and `--replenish-otpk <n>` refresh what gets published. |
| `add-contact` | Imports a contact's card (from `--card <file>` or stdin) under an alias, verifying its signature. |
| `contacts` | Lists contacts, their fingerprint, trust state and whether a session exists yet. |
| `trust` | Marks a contact's fingerprint as checked out of band. |
| `send` | Encrypts a message for a contact, running X3DH first if there is no session yet, and prints the block to paste. |
| `recv` | Decrypts a pasted block, establishing the session automatically if it is someone's first message. |

`init` shows the 12 words once and never stores them: they are the seed
backup, and anyone who reads them owns the identity. Note what they do
**not** back up — see *What the mnemonic covers* below.

Argon2id cost can be tuned with `--argon2-time` and `--argon2-mem-kb` at
`init`; the values are stored in the vault header and reused on every
subsequent save, so a vault written on a fast machine still opens on a slow
one and its cost does not drift.

## Cryptography

| Step | Primitive |
| --- | --- |
| Entropy | `randombytes_buf`, 128 bits |
| Backup encoding | BIP-39, English wordlist, 12 words |
| Master seed | HKDF-SHA256-Extract(salt = `Ratchet-USB/v1/master-seed`, ikm = entropy) |
| Identity key | Ed25519, seed-derived via HKDF-Expand; converted to X25519 for DH (see *Identity key*) |
| Signed prekey / one-time prekeys | Random X25519 keypairs; the signed prekey is Ed25519-signed by the identity |
| Key agreement | X3DH (three or four Diffie-Hellman values combined with HKDF) |
| Session ratchet | Double Ratchet (symmetric-key ratchet + DH ratchet), message keys used directly as ChaCha20-Poly1305 keys |
| Passphrase → vault key | Argon2id, 16-byte salt, defaults 256 MiB / 3 passes |
| Vault container | ChaCha20-Poly1305 (IETF), header authenticated as AAD |

The mnemonic encodes the *entropy*, and the master seed is derived from it
with HKDF rather than with BIP-39's own PBKDF2 construction. Two
consequences worth knowing:

- the 12 words alone reproduce the seed and the long-term identity — the
  vault passphrase protects the file on the drive, it is not mixed into the
  seed;
- these words will **not** reproduce the same keys in a Bitcoin wallet, and a
  wallet's words will not reproduce a Ratchet-USB identity. The wordlist is
  the standard one, the derivation is not.

Every buffer holding key material is a `SecureBytes`/`SecureString`/
`SecureBuffer`: locked in RAM with `sodium_mlock` where the OS permits it,
and wiped with `sodium_memzero` on destruction. They cannot be copied — only
moved — so a secret cannot silently acquire a second, untracked lifetime.

### Identity key: one Ed25519 pair, not two

X3DH needs the identity key to both sign (the signed prekey) and perform
Diffie-Hellman (the handshake itself), and X25519 cannot sign. Rather than
carry two independent identity keys — doubling what a user has to verify —
the identity is a single Ed25519 keypair, derived from the seed, converted to
its birationally equivalent X25519 form (`crypto_sign_ed25519_*_to_curve25519`)
whenever a Diffie-Hellman is needed. One key, one fingerprint to read aloud.

### Prekeys are not backed up by the mnemonic

The signed prekey and one-time prekeys are random, not derived from the
seed. If a one-time prekey could be regenerated from the seed alone,
restoring the vault from the 12 words would resurrect an already-spent
prekey and quietly break the "used once" guarantee that gives X3DH its
forward secrecy for the first message. The trade-off: **prekeys, contacts
and sessions live only in `vault.bin`**, not in the mnemonic. Losing the
drive without a backup of the file loses those, even with the words in
hand — a fresh `init` from the same words gets back the same long-term
identity, but starts with an empty contact list and no sessions.

### X3DH, adapted to no server

Signal's X3DH assumes a server holding prekey bundles that a sender fetches
on demand. There is no server here: a contact's bundle is a card, exchanged
once, out of band, exactly like the rest of this tool's ciphertext. `send`
performs the handshake automatically the first time there is something to
say to a contact, consuming one of their published one-time prekeys if the
stored card still has any (falling back to a 3-DH handshake, per the X3DH
spec's own fallback, once the pool runs out — `card --replenish-otpk`
refills it).

One deliberate deviation from the reference protocol: X3DH's associated data
(both parties' identity keys) is not attached only to the first message's
AEAD tag — it is folded into the derivation of the initial root key itself,
so every key the Double Ratchet ever produces is transitively bound to both
identities, not only the opening message.

### Double Ratchet

Standard symmetric-key ratchet (`HMAC-SHA256`-based `KDF_CK`) plus a
Diffie-Hellman ratchet on every change of direction (`HKDF`-based `KDF_RK`),
following the Signal Double Ratchet specification's pseudocode field for
field (`RK`, `DHs`, `DHr`, `CKs`, `CKr`, `Ns`, `Nr`, `PN`). Two
simplifications relative to the reference:

- a message key is used directly as the ChaCha20-Poly1305 key, instead of
  being expanded into separate AES-CBC/HMAC/IV material — unnecessary once
  the cipher is already an AEAD;
- each message's AEAD nonce is drawn fresh with `randombytes_buf` and
  carried in the envelope, rather than derived from a counter — twelve extra
  bytes per message in exchange for one less place a counter could be
  mishandled.

Messages that arrive out of order are handled the same way as the spec: a
capped cache (`kMaxSkip = 1000`) of message keys for a chain that has moved
on, so a gap in delivery does not lose anything as long as it is not
absurdly large. A gap bigger than that is refused outright, since a header
is otherwise a free way to make `recv` hash without bound.

### Trust model

Importing a card verifies that the signed prekey really was signed by the
claimed identity key, and every message ties back to the sender's identity
through the handshake — but nothing here confirms that the identity key
belongs to the person a user thinks they are talking to. That link only
exists once a human checks it: `add-contact` prints the fingerprint, and
`trust` records that it was checked over a different channel (in person, a
phone call — not the same chat the card arrived over). `send` and `recv`
warn, but do not block, on an unverified contact.

### HKDF

The build uses `crypto_kdf_hkdf_sha256_*` when libsodium provides it (1.0.19
and later). Against older releases CMake falls back to an in-tree RFC 5869
implementation on top of `crypto_auth_hmacsha256`; both paths are checked
against the RFC's own test vectors, so the derived keys are identical either
way and a vault stays portable between the two.

## Vault format

`vault.bin`:

```
offset  size  field
0       4     magic "RCHT"
4       1     version (2)
5       16    Argon2id salt
21      4     Argon2id time cost      (uint32, little-endian)
25      4     Argon2id memory in KiB  (uint32, little-endian)
29      12    ChaCha20-Poly1305 nonce
41      N     ciphertext: the serialised vault store (seed, prekeys, contacts, sessions)
41+N    16    Poly1305 tag
```

The 41-byte header is serialised field by field, not dumped as a struct, so
the file does not depend on the compiler's padding. The whole header is
passed to the AEAD as additional data: altering the salt, the nonce or the
cost parameters makes decryption fail rather than quietly deriving a
different key. A wrong passphrase and a tampered file report the same error
on purpose.

The cost fields are read back from a file an attacker may have written, so
they are range-checked (time 1–64, memory 8 KiB–4 GiB) before reaching
Argon2.

Version 1 (phase 1) held a fixed 64-byte seed-plus-identity-key plaintext.
Version 2 holds the full store and is not backward compatible; there was no
released vault to migrate.

### Message and card wire format

Both a contact card and a message are a `-----BEGIN RATCHET <LABEL>-----`
block of base64, wrapped at 64 columns, ignoring whitespace on decode so a
chat app reflowing the text does not break it. A message carries a truncated
hash of the sender's identity key (so `recv` knows which session it belongs
to without being told), the Double Ratchet header, and — only on the message
that opens a session — the X3DH fields.

## Layout

```
include/ratchet/   public headers
src/               implementation + the BIP-39 wordlist
test/              unit tests (no external framework)
```

## Threat model, briefly

Protects against: someone who obtains the USB drive without the passphrase,
anyone reading the transport channel, and a compromise of one session's
message keys not exposing past or future ones (forward secrecy and post-
compromise security, both inherited from the Double Ratchet).

Does not protect against: a compromised host (a keylogger sees the
passphrase and every plaintext typed), someone who reads the 12 words or
steals `vault.bin`, trusting a contact's identity key without checking the
fingerprint out of band, or the fact that the channel in between still
records the ciphertext and its timing.

## Out of scope (for now)

Groups, multi-device, prekey rotation policy beyond a manual command, and
anything like key transparency. Each would meaningfully grow this phase's
surface; left for later.
