# Ratchet-USB

[![CI](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml/badge.svg)](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml)

A small command-line tool for sending encrypted messages without a server.
You encrypt on your machine, copy the text it prints, and paste it wherever:
WhatsApp, email, a forum. The other person pastes it back into the tool to
read it. Whatever carries the text in between just sees gibberish.

Keys, contacts, chat history — all of it lives on a USB stick or some other
removable drive, never on the computer itself. The tool finds the drive on
its own most of the time; `--usb-path` is there for when you'd rather not
leave it to guessing.

Phase 2 right now: you can make an identity, add contacts, send and receive
with forward-secret encryption. No group chats yet, no using one identity
from two machines, no public key directory. More on all of that at the
bottom.

One thing worth saying plainly before you rely on this for anything real: it
hasn't been through an independent security audit. I've built it carefully
and tested it hard, but that's not the same thing as someone else checking
it who isn't me. If you're the kind of person who'd face real trouble over a
read message — a journalist, an activist, whoever — don't make this your
only layer. Use it next to tools that have actually been audited, and get in
touch if you want to talk through your situation first.

## Platforms

Only actually run on **Linux**. `setup.sh` knows dnf, apt, pacman and
zypper; anywhere else, install libsodium's dev package, CMake and a C++20
compiler yourself and pass `--no-deps`.

**macOS** probably builds — nothing here is Linux-specific at the API level
— but I haven't tried it, so I can't promise it. Two things would bite:
drive detection reads `/proc/mounts`, which doesn't exist there, so you'll
need `--usb-path` every time; and `fsync` on macOS doesn't force a real
flush to disk without `F_FULLFSYNC`, which matters if you yank the drive
mid-write.

**Windows** doesn't build, and it's not the crypto's fault — that part is
portable. It's `termios` for turning off terminal echo, and `fsync` on both
the file and its directory for a durable write, neither of which Windows
has. Porting `src/terminal.cpp` and `src/vault.cpp` is maybe a few hundred
lines, but both are the kind of code where a subtle mistake fails quietly:
get the echo wrong and your passphrase ends up on screen, get the durable
write wrong and vaults corrupt. WSL works fine today, it's just Linux as far
as this is concerned.

## Getting started

```sh
git clone https://github.com/Francy2009/Ratchet-USB.git && cd Ratchet-USB
./setup.sh
```

That installs whatever it needs (asks first), builds, runs the tests, drops
the binary in `~/.local/bin`. No sudo, nothing to add to your PATH — it's
already there on most distros. Tests failing stops it before it installs
anything.

Plug in a drive, then:

```sh
ratchet-usb init
```

```
Found a removable drive to set up:
  /run/media/you/KINGSTON
Use it? [Y/n]
```

That's it. Every command after this finds the same drive on its own:

```sh
ratchet-usb contacts
```

`--prefix /usr/local` installs system-wide (needs sudo for that one),
`--no-deps` skips the package install. Building by hand: C++20 compiler,
CMake 3.16+, libsodium (1.0.19+ preferred — see the HKDF note further
down).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Binary ends up at `build/ratchet-usb`.

## Using it

```sh
# Alice sets up her vault
ratchet-usb init

# Alice prints her "contact card" and sends it to Bob some other way
ratchet-usb card

# Bob does the same setup, then imports Alice's card
ratchet-usb add alice --card alice_card.txt
ratchet-usb trust alice        # after checking the fingerprint

# Bob writes to Alice -- the very first message also sets up the encryption keys
ratchet-usb send alice "hi" > msg.txt
# msg.txt gets copy-pasted into WhatsApp/email/whatever, Alice copies it out again

# Alice reads it
ratchet-usb recv "$(cat msg.txt)"
```

## Which drive it uses

Usually you don't have to think about this. The order is:

1. `--usb-path <dir>`, if given
2. `RATCHET_USB_PATH`
3. a mounted removable drive that already has a vault on it
4. it just asks

`RATCHET_USB_PATH` is handy for a whole terminal session:

```sh
export RATCHET_USB_PATH=/media/usb
ratchet-usb card
```

Detection stays narrow on purpose — only drives the kernel flags as
removable or that hang off USB, never `/`, and it always asks before
writing anywhere. `init` will make a directory for you, but only inside a
drive that's already mounted, so a typo in a path can't quietly land a
vault on your actual disk. Run it non-interactively (a script, a pipe) and
all of that gets skipped — you need `--usb-path`, because there's nobody
around to answer the prompt.

This is Linux-only and best-effort, since it means poking at `/proc/mounts`
and `/sys`. Finds nothing, falls back to option 1 or 2, no harm done.

Same idea applies to a contact alias or a message you leave off the command
line — `send` with no message just asks for one, or reads it from a pipe.

## Commands

`init` makes a new identity, shows the 12-word phrase once, sets up the
vault. `unlock` opens it and prints your fingerprint — and while it's at
it, rotates a signed prekey if it's past 30 days old and tops up one-time
prekeys if fewer than 5 are left, no flags needed for either. `card` prints
the card to share, or just the fingerprint with `--fingerprint`;
`--rotate-spk` and `--replenish-otpk <n>` do the same maintenance on
demand. `add` imports someone's card (a file with `--card`, or stdin) under
whatever alias you give it, checking the signature along the way.
`contacts` lists who you know: fingerprint, trusted or not, session or not.
`trust <alias>` marks someone verified — meaning you checked their
fingerprint some other way. `send <alias> [message]` encrypts for someone,
setting up the session first if there isn't one yet. `recv [message]` does
the same on the receiving end.

Those 12 words from `init` are shown once and saved nowhere — they're the
backup, and whoever has them can rebuild your identity. Not everything,
though: contacts and chat history aren't in there, see below for why.
Already have a phrase from somewhere — an old vault, one someone generated
for you? `init --from-mnemonic` takes the 12 words instead of making new
ones. You still start with an empty vault either way.

`--argon2-time` and `--argon2-mem-kb` on `init` let you tune how expensive
the passphrase check is. Whatever you pick gets saved in the vault itself,
so it opens the same way later even on a slower machine.

## The crypto

128 random bits out of `randombytes_buf`, turned into 12 BIP-39 words. The
master seed comes from running that entropy through HKDF-SHA256 rather than
BIP-39's usual PBKDF2 — so the 12 words rebuild your identity on their own
(the vault passphrase only guards the file, it's not part of the seed at
all), but they're also useless in a Bitcoin wallet, and a wallet's words are
useless here. Same list of words, different math underneath.

One Ed25519 keypair is the identity, converted to X25519 on the fly for
Diffie-Hellman. X3DH needs the identity key to both sign and do DH, and
X25519 alone can't sign, which is usually why people end up carrying two
identity keys instead of one. Here it's just the one — one fingerprint to
read out and check, not two.

Prekeys, signed and one-time both, are random X25519 pairs rather than
anything derived from the seed — if a one-time prekey could be regenerated
from the seed, restoring from the 12 words would resurrect a key you'd
already burned, which defeats the point of "one time" entirely. Cost of
that: prekeys, contacts, ongoing chats live only in `vault.bin`. Lose the
drive without a copy and the words get your identity back but not your
contacts.

X3DH does the key exchange, same handshake as Signal, minus Signal's server
handing out bundles — here the bundle is just the card someone gave you by
hand. `send` runs it automatically on the first message, spending one of
the recipient's one-time prekeys if they published any (falling back to a
slightly weaker 3-way handshake once those run dry — `unlock` and `card
--replenish-otpk` both top the pool back up). The prekey it picks is
random, not the next one in line: the same card usually ends up in several
inboxes, and picking a fixed one means whoever writes first consumes it and
everyone else hits a key that's already gone. Random doesn't remove the
collision, since a hand-shared pool is finite either way, but it stops it
from being guaranteed. One departure from the spec worth flagging: instead
of authenticating just the opening message with the identity keys, both
identities get folded into the very first encryption key, so everything the
ratchet produces afterward stays tied to both of them, not only to how the
conversation opened.

After that it's a Double Ratchet for every message, close to how Signal
does it — a symmetric chain within each direction of the conversation, a
Diffie-Hellman step whenever the conversation switches direction,
ChaCha20-Poly1305 doing the actual encrypting. Two things simplified from
the original: the message key goes straight into ChaCha20-Poly1305 instead
of being split into encryption/auth/IV pieces (not needed with an
authenticated cipher already), and the nonce is random per message rather
than counter-derived, a few extra bytes for not having to think about
counter bugs. Out-of-order delivery is handled with a capped cache of up to
1000 skipped keys — a real gap in delivery doesn't lose the message, a gap
past the cap gets refused outright rather than letting a forged header make
`recv` chew through unbounded work. Those cached keys expire after a week
now. It's the one part of the ratchet that doesn't move forward on its own:
the chains on either side keep advancing, the skipped key just sits there
waiting. Without an expiry, a stolen vault would still open month-old
messages, and stale keys from long-abandoned chains would keep eating into
that 1000-key budget until no new gap could be tolerated at all. `recv`
sweeps expired ones before doing anything else, `unlock` sweeps every
session, so even a vault you only open and never receive into stays clean.
The cost: a message more than a week late doesn't decrypt anymore.

None of this proves an identity key belongs to who you think it does —
that part's on you. Importing a card checks the signed prekey's signature,
and every message you get afterward is tied to the sender's identity
through the handshake, but `add` still just hands you a fingerprint to go
verify. `trust` is you recording that you did — over the phone, in person,
somewhere that isn't the same chat the card arrived on. `send` and `recv`
will nag about an unverified contact but won't stop you.

Secret key material lives in `SecureBytes` / `SecureString` / `SecureBuffer`
— locked in memory where the OS allows it, zeroed once it's done, and
move-only so a copy can't quietly exist somewhere you forgot about. The
passphrase becomes the vault key via Argon2id (256 MiB, 3 passes by
default), and the file itself is sealed with ChaCha20-Poly1305.

Worth knowing: the build reaches for libsodium's native
`crypto_kdf_hkdf_sha256_*` when it's there (1.0.19+), and falls back to a
small RFC 5869 implementation of its own otherwise. Both get checked
against the RFC's vectors and produce the same bytes, so vaults move
between the two without trouble.

## Vault file layout

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

Written field by field rather than dumped as a struct, so padding decisions
your compiler makes don't leak into the file format. The header is
authenticated data on the encryption, not just cleartext sitting next to
it, so touching the salt, nonce or cost values breaks decryption instead of
quietly deriving a different key — and a wrong passphrase gives you the
exact same error as a tampered file, deliberately. The cost values get
range-checked before they ever reach Argon2 (time 1–64, memory 8 KiB–4 GiB),
since they're read back from a file that could in principle have been
messed with. There was an older format, just a fixed 64-byte seed-and-key
blob — nothing published ever used it, so there's no migration to worry
about.

Cards and messages both come wrapped in
`-----BEGIN RATCHET <LABEL>-----`, base64, 64 characters a line, extra
whitespace ignored on the way back in — so a chat app reflowing your
paragraph doesn't break the block. A message carries a short hash of the
sender's identity (so `recv` knows which conversation without being told),
the ratchet header, and, only on the message that opens a conversation, the
X3DH handshake data.

## Layout

`include/ratchet/` for public headers, `src/` for the implementation and
the BIP-39 wordlist, `test/` for the unit tests — no framework, just plain
checks.

## How the crypto is checked

A round-trip test doesn't prove much here. Encrypting and decrypting with
the same code just proves the code agrees with itself, and code that's
wrong in a consistent way agrees with itself perfectly. Swap the two HMAC
constants in the chain-key step, or feed HKDF the DH output as salt instead
of input, and messages still round-trip fine. What you'd get is a ratchet
that works and isn't the one the spec describes.

So the key schedule also gets checked against vectors from somewhere else
entirely. `test/vectors/reference.py` is the same derivations written a
second time, in Python, from the specs rather than from `src/ratchet.cpp`,
using nothing but the standard library. Its own primitives are pinned to
published vectors first (RFC 7748 for X25519, RFC 5869 for HKDF-SHA256),
and its output is frozen into `test/vectors/vectors.hpp`, which the C++
side has to match byte for byte. CI regenerates that header on every push
and fails on any difference, so the two can't drift into quiet agreement —
a bug would have to show up twice, independently, in the same direction.

That's conformance, not interoperability — this doesn't speak libsignal's
wire format and there's no way to test it against the real thing (the
departures noted above make sure of that: direct message key as the AEAD
key, a random nonce in the envelope, a root-key info string that's this
project's own).

`test/smoke.sh` separately drives the actual binary through a full
conversation — two vaults, a card exchange, handshake, reply, messages
arriving out of order, a tampered one, a wrong passphrase — since none of
the unit tests touch argument parsing, file I/O, or the copy-paste
encoding.

CI runs the lot on every push: GCC and Clang, Debug and Release, warnings
as errors, ASan, UBSan, Valgrind, clang-tidy. One job builds a newer
libsodium from source, since Ubuntu ships 1.0.18 and the fallback HKDF
would otherwise never actually compile, let alone run, in CI. It also
double-checks that the newer libsodium's HKDF got picked, because a
detection bug would otherwise fall back silently and the badge would stay
green regardless.

## What it protects against, and what it doesn't

Someone who gets your drive but not your passphrase. Anyone watching the
channel you paste messages through. A leaked session key doesn't expose
past or future messages either, courtesy of forward secrecy and
post-compromise security in the ratchet.

What it can't help with: a compromised computer — a keylogger sees your
passphrase and everything else regardless of encryption. Someone reading
your 12 words or grabbing `vault.bin` outright. Trusting a contact without
actually checking their fingerprint. And whatever channel you're pasting
through still sees ciphertext go by, plus timing — it just can't read the
contents.

## Not there yet

Group chats, one identity across multiple devices, key transparency. All
real work, none of it worth doing halfway, so it waits.

## Disclaimer

There is no server here, and that is not a slogan — nothing this tool does
ever leaves your machine and the drive in your pocket. No account, no
telemetry, no update check, no key directory phoning home. Which also means
I have nothing: I cannot see your messages, cannot recover your vault, and
cannot hand anything over to anyone, because none of it ever reaches me.
The flip side is that the whole thing is on you. Lose the drive or forget
the passphrase and the messages are gone, and I have no way to help.

I publish this because I think people should be able to talk privately. I
have no control over what anybody does with it once it is downloaded, and I
take no responsibility for it. Use it lawfully. It is a privacy tool, not
cover for hurting somebody.

Encryption is regulated differently from one country to the next, and in a
few places using or importing it is restricted outright. Checking what
applies where you are is your job, not mine.

This is 0.1.0, and pre-1.0 in the way that matters: the vault and message
formats are not frozen, so a later release may not read what this one wrote.
Keep your recovery words, and do not treat a vault as a long-term archive.

And once more, because it is the thing most likely to matter to you: this
has not been independently audited. It is tested hard — CI on two compilers,
sanitizers, fuzzing, key-schedule vectors from an independent implementation
— but tested by me is not the same as reviewed by someone who is not me. If
being read would put you in real danger, do not let this be your only layer.

## License

MIT, see [LICENSE](LICENSE) — which, in the two paragraphs in capitals at
the bottom, is also the legal version of everything above: the software
comes with no warranty of any kind, and I am not liable for what it does or
fails to do. The BIP-39 wordlist and libsodium are third-party and credited
in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
