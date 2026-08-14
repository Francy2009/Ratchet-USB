# Ratchet-USB

**English** · [Italiano](README.it.md)

[![CI](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml/badge.svg)](https://github.com/Francy2009/Ratchet-USB/actions/workflows/ci.yml)

A small command-line tool for sending encrypted messages without needing a
server. You encrypt the message on your machine, copy the resulting text, and
paste it wherever you want: WhatsApp, email, a forum, whatever. The other
person copies it back into the tool to read it. Whatever app carries the text
in between only ever sees random-looking gibberish, never your actual
message.

Everything that matters, your keys, your contacts, your chat history, lives
on a USB stick or any removable drive. The tool never writes anything to the
computer it's running on. It finds the drive by itself when it can, and you
can always name it explicitly with `--usb-path`.

Where it's at right now: phase 2. You can generate an identity, add contacts,
and send and receive messages with proper forward-secret encryption. Still
missing are group chats, using the same identity from more than one device,
and any kind of public key directory (more on that near the bottom, under
"What this doesn't do").

Before you rely on this for anything real: this project hasn't gone through
an independent security audit yet. It's built carefully and tested, but
"carefully built by one person" and "checked by outside cryptographers" are
not the same guarantee. If you're a journalist, activist, or anyone else who
could face real consequences if a message got read, please don't make this
your only line of defense. Treat it as one extra layer, keep using other
reviewed and audited tools alongside it, and get in touch if you want to talk
through your specific situation before trusting it.

## Which systems this runs on

**Linux**, and that is the only one it has actually been run on. `setup.sh`
knows dnf, apt, pacman and zypper; on any other distribution install
libsodium's development package, CMake and a C++20 compiler yourself and pass
`--no-deps`.

**macOS** should build — every system call used here exists there, and
libsodium supports it — but nobody has tried, so treat it as unverified. Two
things would be worse if you do: drive detection reads `/proc/mounts` and so
finds nothing, leaving you to pass `--usb-path`; and macOS's `fsync` does not
force a physical flush without `F_FULLFSYNC`, which weakens the guarantee that
a vault survives the drive being pulled out mid-write.

**Windows** does not build. Not the crypto, which is portable, but the parts
around it: turning terminal echo off for the passphrase goes through
`termios`, and the vault is written durably using `fsync` on both the file and
its directory, neither of which Windows has an equivalent for. Porting it is a
few hundred lines in `src/terminal.cpp` and `src/vault.cpp`, and both are
places where a subtle mistake fails quietly rather than loudly -- an echo that
is not really off puts your passphrase on screen, and a mis-ported durable
write corrupts vaults. **WSL works today** and is Linux as far as this is
concerned.

## Getting started

Two commands, once:

```sh
git clone https://github.com/Francy2009/Ratchet-USB.git && cd Ratchet-USB
./setup.sh
```

`setup.sh` installs the packages it needs (asking first), builds, runs the
tests, and puts the binary in `~/.local/bin`, which is on your PATH on most
current distributions. No `sudo` for the install itself, and no `export PATH`
afterwards: `ratchet-usb` becomes an ordinary command. If the tests fail it
stops before installing anything.

Then plug in a USB drive and:

```sh
ratchet-usb init
```

That's the whole setup. `init` looks for a mounted removable drive and asks
before using it:

```
Found a removable drive to set up:
  /run/media/you/KINGSTON
Use it? [Y/n]
```

From then on, every other command finds that drive on its own, so there is
nothing to type and nothing to remember:

```sh
ratchet-usb contacts
```

`./setup.sh --prefix /usr/local` installs system-wide instead (that one does
need sudo), and `--no-deps` skips the package step. To build by hand rather
than through the script, you need a C++20 compiler, CMake 3.16 or newer, and
libsodium (1.0.19 or later is best; see the HKDF note further down), which is
the only library this depends on:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The binary then sits at `build/ratchet-usb`.

## How to use it

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

## Telling it which drive to use

Most of the time you don't have to. Every command works out where the vault
is, in this order:

1. `--usb-path <dir>`, if you pass it
2. the `RATCHET_USB_PATH` environment variable
3. a mounted removable drive that already holds a vault, which it offers you
4. failing all that, it simply asks

So `--usb-path` is always there when you want to be explicit, and setting
`RATCHET_USB_PATH` once per session still works:

```sh
export RATCHET_USB_PATH=/media/usb
ratchet-usb card
```

The auto-detection is deliberately narrow. It only ever considers drives the
kernel reports as removable, or that hang off a USB bus; it never offers `/`;
and it always asks before writing. `init` will create a directory for you, but
only inside a removable drive that is already mounted, so a mistyped path can
never quietly put a vault on the computer's own disk. Anything non-interactive
(a script, a pipe) skips detection and the prompts entirely and requires
`--usb-path`, because there is nobody there to confirm.

Detecting drives means reading `/proc/mounts` and `/sys`, so it is Linux-only
and best-effort by nature. When it finds nothing, you are back to case 1 or 2
and nothing is lost.

The same goes for a contact alias or a message left off the command line:
`send` without a message, for instance, prompts for one (or reads it from a
pipe).

## What each command does

`init` creates a new identity, shows you the 12-word backup phrase once, and
sets up the vault. `unlock` just opens the vault and shows your fingerprint,
though along the way it also checks your prekeys: a signed prekey older than
30 days gets rotated, and if fewer than 5 one-time prekeys are left, 10 fresh
ones are generated, both automatically, no flags needed. `card` prints your
contact card so you can share it, or just your fingerprint with
`--fingerprint`; `--rotate-spk` and `--replenish-otpk <n>` refresh those keys
on demand, on top of the automatic upkeep `unlock` already does. `add`
imports someone's card, from a file with `--card` or from stdin, under the
alias you give it, and checks that the signature is valid. `contacts` lists
who you know, their fingerprint, whether you've marked them trusted, and
whether you already have a session going with them. `trust <alias>` marks a
contact as verified, meaning you checked their fingerprint through some other
channel. `send <alias> [message]` encrypts a message for someone, setting up
the session automatically if it's the first one. `recv [message]` decrypts a
message someone sent you, again setting up the session automatically if it's
the first one to arrive.

`init` shows you the 12 recovery words exactly once and doesn't save them
anywhere; they're your backup, and whoever has them can restore your
identity. They don't back up everything though, more on that below. If you
already have a backup phrase, from a previous vault or a fresh one someone
generated for you, `init --from-mnemonic` asks for the 12 words instead of
generating new ones and rebuilds the identity from them; it still starts you
off with a brand new, empty vault, since contacts and chat history never
lived in the words to begin with.

You can also tune how expensive the passphrase check is with `--argon2-time`
and `--argon2-mem-kb` when running `init`. Whatever values you pick get saved
inside the vault and reused every time after, so a vault created on a fast
laptop still opens fine on a slower machine, and the cost doesn't silently
change.

## The crypto, in plain terms

The seed starts as 128 random bits from `randombytes_buf`, encoded into a
12-word BIP-39 backup phrase. The master seed itself comes from running that
raw entropy through HKDF-SHA256, not through BIP-39's usual PBKDF2 step. Two
things follow from that: the 12 words alone are enough to rebuild your seed
and your long-term identity (the vault passphrase only protects the file
sitting on the drive, it doesn't feed into the seed itself), and these words
will not work in a Bitcoin wallet, nor will a wallet's words work here. Same
wordlist, different math underneath.

Your identity is a single Ed25519 key pair derived from that seed, converted
to X25519 on the fly whenever a Diffie-Hellman exchange needs it. X3DH needs
the identity key for two different jobs, signing the prekey and doing a
Diffie-Hellman exchange, and X25519 can't sign anything on its own, so a lot
of designs end up using two separate identity keys. Using one Ed25519 key
here instead means one identity and one fingerprint to read out loud and
check with someone, not two.

Signed and one-time prekeys are random X25519 key pairs, not derived from
your seed. That's on purpose: if a one-time prekey could be regenerated from
the seed, restoring your vault from the 12 words would bring back a key
you'd already used once, defeating the whole point of a "use once" key. The
trade-off is that prekeys, contacts and ongoing chats only exist inside
`vault.bin`, not in the recovery phrase. Lose the drive without a copy of
that file and you lose your contacts and chat history even with the words in
hand; running `init --from-mnemonic` with the same words gets your identity
back, but you start from zero contacts.

Key exchange is X3DH, the same handshake Signal uses, though without
Signal's server handing out prekey bundles on request. Here a contact's
bundle is just their card, shared once, by hand, the same way as everything
else in this tool. `send` runs the handshake automatically the first time you
message someone, using up one of their one-time prekeys if they published
any, and falling back to a slightly weaker 3-way handshake once those run
out (`unlock` tops the pool back up on its own once it runs low, or `card
--replenish-otpk` does it on demand). Which prekey gets used is picked at
random, because the same card usually ends up in several people's hands and
they'd otherwise all reach for the same one; the first to write would consume
it and everyone else would be left pointing at a key you no longer have.
Sharing a fixed set of one-time prekeys by hand means a clash is always
possible, but this keeps it from being the normal case. One small difference
from the spec:
instead of only authenticating the very first message with the identity
keys, this implementation mixes both parties' identities into the very first
encryption key, so every key the ratchet ever produces afterwards is tied
back to both identities, not just the opening message.

Ongoing messages are encrypted with a Double Ratchet, following Signal's
design fairly closely: a symmetric ratchet for keys within one direction of
the conversation, plus a Diffie-Hellman ratchet whenever the conversation
changes direction, with ChaCha20-Poly1305 doing the actual encryption. Two
small simplifications compared to the original spec: a message key is used
straight as the ChaCha20-Poly1305 key instead of being split into separate
encryption, authentication and IV pieces (not needed once you're already
using an authenticated cipher), and each message gets a random nonce instead
of one derived from a counter, which costs a few extra bytes per message but
removes a whole category of counter-handling bugs. Messages that arrive out
of order are handled the way Signal does it too: a capped list of up to 1000
skipped message keys, so a short gap in delivery doesn't lose anything, while
a bigger gap gets rejected outright, since otherwise someone could send a
bogus header and make `recv` do unbounded work. Those cached keys also expire
after a week. A skipped key is the only part of the ratchet that doesn't move
on by itself -- the chains either side of it have already ratcheted forward,
but the key sits there waiting for a message that may never arrive -- so
without an expiry a vault stolen months later would still open those old
messages, and keys left behind by a chain the conversation has long since
moved past would keep eating the 1000-key budget. `recv` sweeps the expired
ones before it does anything else, and `unlock` sweeps every session, so a
vault you only ever open expires them too. The trade-off is that a message
that turns up more than a week late no longer decrypts.

None of this proves that an identity key actually belongs to the person you
think it does; that's something only a human can confirm. Importing someone's
card checks that their signed prekey really was signed by the identity key on
the card, and every message you get is cryptographically tied to the
sender's identity through the handshake, but `add` still just prints
a fingerprint for you to check. `trust` records that you verified it some
other way, in person or over a phone call, not the same chat where the card
showed up. `send` and `recv` will warn you about an unverified contact, but
they won't stop you.

Anything holding a secret key uses a wrapper (`SecureBytes`, `SecureString`,
`SecureBuffer`) that locks the memory when the OS allows it and zeroes it out
once it's no longer needed. You can't accidentally copy one of these, only
move it, so a secret can't end up living in two places without you noticing.
The passphrase itself is turned into the vault key with Argon2id, 256 MiB and
3 passes by default, and the vault file is sealed with ChaCha20-Poly1305.

One last detail: the build uses libsodium's own `crypto_kdf_hkdf_sha256_*`
functions when they're available (libsodium 1.0.19+), and falls back to a
small in-house RFC 5869 implementation on older versions. Both are tested
against the RFC's official test vectors and produce identical output, so a
vault stays portable no matter which path your libsodium takes.

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
instead of silently deriving the wrong key; on purpose, a wrong passphrase
and a tampered file produce the exact same error message. The cost values
get read back from a file that could, in theory, have been tampered with, so
they're range-checked (time 1 to 64, memory between 8 KiB and 4 GiB) before
they're ever handed to Argon2. An early version of the format just stored a
fixed 64-byte seed-plus-key blob; the current one stores the whole vault and
isn't compatible with that, though there was no released vault to worry
about migrating anyway.

A contact card and a message are both wrapped in a
`-----BEGIN RATCHET <LABEL>-----` block of base64 text, 64 characters per
line, with any extra whitespace ignored when reading it back, so a chat app
reflowing the text doesn't break it. A message includes a short hash of the
sender's identity, so `recv` knows which conversation it belongs to without
being told explicitly, the Double Ratchet header, and, only on the message
that starts a new conversation, the X3DH handshake data.

## Project layout

`include/ratchet/` holds the public headers, `src/` has the actual
implementation plus the BIP-39 wordlist, and `test/` has the unit tests
(no external test framework, just plain checks).

## How the crypto is checked

A round-trip test is worth less here than it looks. Encrypting and decrypting
with the same code proves the implementation agrees with itself, and an
implementation that is wrong in a self-consistent way agrees with itself
perfectly. Swap the two HMAC constants in the chain-key derivation, or hand
HKDF the Diffie-Hellman output as its salt and the root key as its input
material, and every message still round-trips. The result is a ratchet that
works beautifully and is not the one the specification describes.

So the key schedule is also checked against known-answer vectors that came
from somewhere else. `test/vectors/reference.py` implements the same
derivations a second time, in Python, from the specifications rather than from
`src/ratchet.cpp`, using only the standard library. Its own primitives are
pinned to published test vectors first -- RFC 7748 for X25519, RFC 5869 for
HKDF-SHA256 -- and its output is frozen into `test/vectors/vectors.hpp`, which
the C++ suite has to reproduce byte for byte. CI regenerates that header on
every push and fails if it differs from the committed copy, so the two
implementations cannot quietly drift into agreement. For a bug to survive, it
would have to be made twice, independently, in the same direction.

That is a conformance check, not an interoperability claim: this tool does not
speak libsignal's wire format and cannot be tested against it (see the
deliberate departures noted above -- the message key is used directly as a
ChaCha20-Poly1305 key, the nonce is random and carried in the envelope, and
the root-key info string is this project's own).

Alongside that, `test/smoke.sh` drives the actual built binary through a whole
conversation -- two vaults, a card exchange, a handshake, a reply, out-of-order
delivery, a tampered message, a wrong passphrase -- because none of the unit
tests touch argument parsing, file I/O, or the copy-paste block encoding.

CI runs all of it on every push: GCC and Clang, Debug and Release, warnings as
errors, AddressSanitizer, UndefinedBehaviorSanitizer, Valgrind and clang-tidy.
One job builds a newer libsodium from source, because Ubuntu ships 1.0.18 and
this project carries its own RFC 5869 HKDF for releases older than 1.0.19 --
without that job, half the HKDF code in the tree would never be compiled, let
alone run. It also asserts that the newer libsodium's HKDF really was selected,
since a detection failure otherwise falls back silently and leaves the badge
green.

## What this does and doesn't protect you from

It protects you from someone who gets hold of your USB drive but doesn't
know the passphrase, and from anyone watching or logging the channel you
paste messages through. If one session's keys ever leak, that doesn't expose
past or future messages either, thanks to the forward secrecy and
post-compromise security built into the Double Ratchet design.

It doesn't protect you from a compromised computer: a keylogger sees your
passphrase and everything you type, encryption or not. It doesn't protect
you if someone reads your 12 recovery words or steals `vault.bin` directly,
or if you trust a contact's identity without actually checking their
fingerprint. And the channel you're pasting messages through still sees the
ciphertext go by, along with when you sent it, even if it can't read what's
inside.

## What this doesn't do yet

Group chats, using one identity across multiple devices, and anything like
key transparency. Each of these is a real chunk of work on its own, so
they're left for later rather than half-done now.

## License

MIT, see [LICENSE](LICENSE). Third-party code and data used by this project,
the BIP-39 wordlist and libsodium, are credited in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
