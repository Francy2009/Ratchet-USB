# Ratchet-USB

A small command-line tool for sending encrypted messages without needing a
server. You encrypt the message on your machine, copy the resulting text, and
paste it wherever you want (WhatsApp, email, a forum, whatever). The other
person copies it back into the tool to read it. The app in the middle only
ever sees random-looking text, never your actual message.

Everything that matters (your keys, your contacts, your chat history) lives
on a USB stick or any removable drive. The tool never writes anything to the
computer it's running on. You always point it at your drive with
`--usb-path`.

**Where it's at right now:** phase 2. You can generate an identity, create
contacts, and send/receive messages with proper forward-secret encryption.
What's still missing: group chats, using the same identity from more than one
device, and any kind of public key directory (more on that in "What this
doesn't do" below).

> **Before you rely on this for anything real:** this project has not gone
> through an independent security audit yet. It's built carefully and tested,
> but "carefully built by one person" and "checked by outside cryptographers"
> are not the same guarantee. If you're a journalist, activist, or anyone
> else who could face real consequences if a message got read, please don't
> make this your only line of defense — treat it as one extra layer, keep
> using other reviewed and audited tools alongside it, and get in touch if
> you want to talk through your specific situation before trusting it.

## Building it

You need a C++20 compiler, CMake 3.16 or newer, and libsodium (1.0.19+ is
best, see the HKDF note further down). That's the only library it depends
on.

```sh
sudo apt install libsodium-dev cmake g++      # on Debian/Ubuntu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

If everything builds and the tests pass, you're good to go — the binary is
`build/ratchet-usb`.

## How to use it

```sh
# Alice sets up her vault
ratchet-usb init --usb-path /media/usb

# Alice prints her "contact card" and sends it to Bob some other way
ratchet-usb card --usb-path /media/usb

# Bob does the same setup, then imports Alice's card
ratchet-usb add-contact --usb-path /media/usb --name alice --card alice_card.txt
ratchet-usb trust --usb-path /media/usb --name alice   # after checking the fingerprint

# Bob writes to Alice — the very first message also sets up the encryption keys
ratchet-usb send --usb-path /media/usb --to alice --message "hi" > msg.txt
# msg.txt gets copy-pasted into WhatsApp/email/whatever, Alice copies it out again

# Alice reads it
ratchet-usb recv --usb-path /media/usb --message "$(cat msg.txt)"
```

### Commands

| Command | What it does |
| --- | --- |
| `init` | Creates a new identity, shows you the 12-word backup phrase once, and sets up the vault. |
| `unlock` | Opens the vault and shows your fingerprint. Along the way it checks your prekeys: if the signed prekey is more than 30 days old it's rotated, and if fewer than 5 one-time prekeys are left, 10 fresh ones are generated — both automatically, no flags needed. |
| `card` | Prints your contact card so you can share it. `--rotate-spk` and `--replenish-otpk <n>` refresh the keys it publishes on demand, on top of the automatic upkeep `unlock` already does. |
| `add-contact` | Imports someone's card (from a file with `--card` or from stdin), checking that the signature is valid. |
| `contacts` | Lists your contacts, their fingerprint, whether you've marked them trusted, and if you already have a session going. |
| `trust` | Marks a contact as verified, meaning you checked their fingerprint through some other channel. |
| `send` | Encrypts a message for someone. If this is the first message to them, it sets up the session automatically. |
| `recv` | Decrypts a message someone sent you, setting up the session automatically if it's their first message to you. |

`init` shows you the 12 recovery words exactly once and doesn't save them
anywhere — they're your backup, and whoever has them can restore your
identity. Note that they don't back up everything (see "What the recovery
words actually cover" below).

You can tune how expensive the passphrase check is with `--argon2-time` and
`--argon2-mem-kb` when running `init`. Whatever values you pick get saved
inside the vault and reused every time after that, so a vault created on a
fast laptop still opens fine on a slower machine, and the cost doesn't
silently change.

## The crypto, in plain terms

| Step | What's used |
| --- | --- |
| Random seed | `randombytes_buf`, 128 bits |
| Backup phrase | BIP-39, English wordlist, 12 words |
| Master seed | HKDF-SHA256 over the random entropy |
| Identity key | One Ed25519 key pair, derived from the seed, converted to X25519 when needed for key exchange |
| Signed / one-time prekeys | Random X25519 key pairs, the signed one gets an Ed25519 signature from your identity key |
| Key exchange | X3DH (the same handshake Signal uses) |
| Ongoing chat encryption | Double Ratchet — a rotating key per message, ChaCha20-Poly1305 for the actual encryption |
| Passphrase to vault key | Argon2id, 256 MiB / 3 passes by default |
| Vault file | ChaCha20-Poly1305, header included as authenticated data |

The recovery phrase encodes the raw entropy, and the master seed comes from
running that entropy through HKDF — not through BIP-39's usual PBKDF2 step.
Two things follow from that:

- the 12 words alone are enough to rebuild your seed and your long-term
  identity. The vault passphrase only protects the file sitting on the
  drive, it doesn't feed into the seed itself;
- these words will **not** work in a Bitcoin wallet, and a wallet's words
  won't work here either. Same wordlist, different math underneath.

Anything holding a secret key uses a wrapper (`SecureBytes`, `SecureString`,
`SecureBuffer`) that locks the memory when the OS allows it and zeroes it out
once it's no longer needed. You can't accidentally copy one, only move it —
so a secret can't end up living in two places without you noticing.

### Why one identity key, not two

X3DH needs the identity key to do two different jobs: sign the prekey, and
do a Diffie-Hellman exchange during the handshake. X25519 can't sign
anything, so a lot of designs just use two separate identity keys. Here we
use a single Ed25519 key instead, and convert it to its X25519 equivalent on
the fly whenever a Diffie-Hellman is needed. That means one identity, one
fingerprint to read out loud and check with someone — not two.

### Prekeys don't come back with the recovery phrase

The signed prekey and the one-time prekeys are random, they're not derived
from your seed. That's on purpose: if a one-time prekey could be regenerated
from the seed, restoring your vault from the 12 words would bring back a key
you already used once, which defeats the whole point of a "use once" key.
The trade-off is that **prekeys, contacts and ongoing chats only exist inside
`vault.bin`**, not in the recovery phrase. If you lose the drive without a
copy of that file, you lose your contacts and chat history even with the
words in hand. Running `init` again with the same words gets your identity
back, but you start from zero contacts.

### X3DH without a server

Signal's version of X3DH expects a server that hands out prekey bundles on
request. There's no server here, so a contact's bundle is just their card,
shared once, by hand, the same way as everything else in this tool. `send`
runs the handshake automatically the first time you message someone, using
up one of their one-time prekeys if they published any (and falling back to
a slightly weaker 3-way handshake once those run out — `unlock` tops them
back up on its own once the pool runs low, or `card --replenish-otpk` does
it on demand).

One small difference from the spec: instead of only authenticating the very
first message with the identity keys, this implementation mixes both
parties' identities into the very first encryption key, so every key the
ratchet ever produces afterwards is tied back to both identities, not just
the opening message.

### Double Ratchet

This follows the standard Signal Double Ratchet design pretty closely: a
symmetric ratchet for keys within one direction of the conversation, plus a
Diffie-Hellman ratchet whenever the conversation changes direction. Two
small simplifications compared to the original spec:

- a message key is used straight as the ChaCha20-Poly1305 key, instead of
  being split into separate encryption/authentication/IV pieces — not
  needed once you're already using an authenticated cipher;
- each message gets a random nonce instead of one derived from a counter,
  which costs a few extra bytes per message but removes a whole category of
  counter-handling bugs.

Messages that arrive out of order are handled the same way Signal does it: a
capped list (max 1000) of skipped message keys, so a short gap in delivery
doesn't lose anything. A gap bigger than that gets rejected outright, since
otherwise someone could send a bogus header and make `recv` do unbounded
work.

### About trust

Importing someone's card checks that their signed prekey really was signed
by the identity key on the card, and every message you get is cryptographically
tied to the sender's identity through the handshake. But none of that proves
the identity key actually belongs to the person you think it does — that's
something only a human can confirm. `add-contact` prints a fingerprint, and
`trust` records that you checked it some other way (in person, a phone call —
not the same chat where the card showed up). `send` and `recv` will warn you
about an unverified contact, but they won't stop you.

### A note on HKDF

The build uses libsodium's own `crypto_kdf_hkdf_sha256_*` functions when
they're available (libsodium 1.0.19+). On older versions, it falls back to a
small in-house RFC 5869 implementation built on `crypto_auth_hmacsha256`.
Both are tested against the RFC's official test vectors and produce
identical output, so a vault stays portable regardless of which path your
libsodium version takes.

## Vault file layout

`vault.bin` looks like this:

```
offset  size  field
0       4     magic "RCHT"
4       1     version (2)
5       16    Argon2id salt
21      4     Argon2id time cost      (uint32, little-endian)
25      4     Argon2id memory in KiB  (uint32, little-endian)
29      12    ChaCha20-Poly1305 nonce
41      N     encrypted data: seed, prekeys, contacts, sessions
41+N    16    Poly1305 authentication tag
```

The header is written out field by field rather than dumped as a raw struct,
so the file format doesn't depend on how your compiler happens to pad
things. The whole header also gets fed into the encryption as authenticated
data, so tampering with the salt, nonce or cost values makes decryption fail
instead of silently deriving the wrong key. On purpose, a wrong passphrase
and a tampered file produce the exact same error message.

The cost values get read back from a file that could, in theory, have been
tampered with, so they're range-checked (time 1–64, memory between 8 KiB and
4 GiB) before they're ever handed to Argon2.

Version 1 (phase 1) just stored a fixed 64-byte seed-plus-key blob. Version 2
stores the whole vault and isn't compatible with version 1 — there was no
released vault to worry about migrating anyway.

### Message and card format

Both a contact card and a message are wrapped in a
`-----BEGIN RATCHET <LABEL>-----` block of base64 text, 64 characters per
line, and any extra whitespace is ignored when reading it back — that way a
chat app reflowing the text doesn't break it. A message includes a short
hash of the sender's identity (so `recv` knows which conversation it belongs
to without being told explicitly), the Double Ratchet header, and — only on
the message that starts a new conversation — the X3DH handshake data.

## Project layout

```
include/ratchet/   public headers
src/               the actual implementation, plus the BIP-39 wordlist
test/              unit tests (no external test framework, just plain checks)
```

## What this protects you from

Someone who gets hold of your USB drive but doesn't know the passphrase.
Anyone watching or logging the channel you paste messages through. And if
one session's keys ever leak, that doesn't expose past or future messages —
that's forward secrecy and post-compromise security, both inherited from the
Double Ratchet design.

## What it doesn't protect you from

A compromised computer — if there's a keylogger running, it sees your
passphrase and everything you type, encryption or not. Someone reading your
12 recovery words, or stealing `vault.bin` directly. Trusting a contact's
identity without actually checking their fingerprint. And the channel you're
pasting messages through still sees the ciphertext go by, along with when
you sent it, even if it can't read what's inside.

## What this doesn't do (yet)

Group chats, using one identity across multiple devices, and anything like
key transparency. Each of these is a real chunk of work on its own, so
they're left for later rather than half-done now.

## License

MIT — see [LICENSE](LICENSE). Third-party code and data used by this project
(the BIP-39 wordlist, libsodium) are credited in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
