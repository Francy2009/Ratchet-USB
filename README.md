# Ratchet-USB

A small command-line tool for sending encrypted messages without needing a
server. You encrypt the message on your machine, copy the resulting text, and
paste it wherever you want: WhatsApp, email, a forum, whatever. The other
person copies it back into the tool to read it. Whatever app carries the text
in between only ever sees random-looking gibberish, never your actual
message.

Everything that matters, your keys, your contacts, your chat history, lives
on a USB stick or any removable drive. The tool never writes anything to the
computer it's running on. You always point it at your drive with
`--usb-path`.

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

## Building it

You need a C++20 compiler, CMake 3.16 or newer, and libsodium (1.0.19 or
later is best; see the HKDF note further down). That's the only library it
depends on.

```sh
sudo apt install libsodium-dev cmake g++      # on Debian/Ubuntu
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

If everything builds and the tests pass, you're good to go. The binary ends
up at `build/ratchet-usb`.

## How to use it

```sh
# Alice sets up her vault
ratchet-usb init --usb-path /media/usb

# Alice prints her "contact card" and sends it to Bob some other way
ratchet-usb card --usb-path /media/usb

# Bob does the same setup, then imports Alice's card
ratchet-usb add-contact --usb-path /media/usb --name alice --card alice_card.txt
ratchet-usb trust --usb-path /media/usb --name alice   # after checking the fingerprint

# Bob writes to Alice -- the very first message also sets up the encryption keys
ratchet-usb send --usb-path /media/usb --to alice --message "hi" > msg.txt
# msg.txt gets copy-pasted into WhatsApp/email/whatever, Alice copies it out again

# Alice reads it
ratchet-usb recv --usb-path /media/usb --message "$(cat msg.txt)"
```

`init` creates a new identity, shows you the 12-word backup phrase once, and
sets up the vault. `unlock` just opens the vault and shows your fingerprint,
though along the way it also checks your prekeys: a signed prekey older than
30 days gets rotated, and if fewer than 5 one-time prekeys are left, 10 fresh
ones are generated, both automatically, no flags needed. `card` prints your
contact card so you can share it; `--rotate-spk` and `--replenish-otpk <n>`
refresh those keys on demand, on top of the automatic upkeep `unlock` already
does. `add-contact` imports someone's card, from a file with `--card` or from
stdin, and checks that the signature is valid. `contacts` lists who you know,
their fingerprint, whether you've marked them trusted, and whether you
already have a session going with them. `trust` marks a contact as verified,
meaning you checked their fingerprint through some other channel. `send`
encrypts a message for someone, setting up the session automatically if it's
the first one. `recv` decrypts a message someone sent you, again setting up
the session automatically if it's the first one to arrive.

`init` shows you the 12 recovery words exactly once and doesn't save them
anywhere; they're your backup, and whoever has them can restore your
identity. They don't back up everything though, more on that below.

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
hand; running `init` again with the same words gets your identity back, but
you start from zero contacts.

Key exchange is X3DH, the same handshake Signal uses, though without
Signal's server handing out prekey bundles on request. Here a contact's
bundle is just their card, shared once, by hand, the same way as everything
else in this tool. `send` runs the handshake automatically the first time you
message someone, using up one of their one-time prekeys if they published
any, and falling back to a slightly weaker 3-way handshake once those run
out (`unlock` tops the pool back up on its own once it runs low, or `card
--replenish-otpk` does it on demand). One small difference from the spec:
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
bogus header and make `recv` do unbounded work.

None of this proves that an identity key actually belongs to the person you
think it does; that's something only a human can confirm. Importing someone's
card checks that their signed prekey really was signed by the identity key on
the card, and every message you get is cryptographically tied to the
sender's identity through the handshake, but `add-contact` still just prints
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
