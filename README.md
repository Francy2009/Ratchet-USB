# Ratchet-USB

Languages: [Italiano](README.it.md) · **English**

Ratchet-USB is a terminal program for exchanging encrypted messages without a
dedicated server. Write a message on your computer, copy the encrypted block it
prints, and send that block through a channel of your choice. The recipient
pastes the block into the program to read it. The transport channel can see the
block and the time of the exchange, but not the message text.

Your identity, contacts, and sessions live in an encrypted vault on a USB drive
or in a directory you choose. The drive itself is not a cryptographic key. The
vault file is protected by its passphrase, a random word phrase the program
generates and shows once when the vault is created. Someone who copies the file
can try to guess that passphrase without having the drive, so keep the words
safe and separate from the drive.

This is still a development version (`0.5.0-dev`). The post-quantum migration is
implemented, but it has not had an independent security review. See the
[migration status](docs/PQ-MIGRATION-STATUS.md) for completed and outstanding
checks, and the [threat model](docs/THREAT-MODEL.md) for its limits.

## Using it

Run `ratchet-usb` without arguments to open the terminal interface. You can
create a vault, add a contact, verify their fingerprint, and exchange messages
using the keys shown on screen. The interface follows your system locale; use
`--lang it` or `--lang en` to choose explicitly. It locks after three minutes
of inactivity by default. Change that interval with `--idle-lock <seconds>`.

The same steps are available as commands. A typical exchange looks like this:

```sh
ratchet-usb init
ratchet-usb card > my-card.txt
ratchet-usb add alice --card alice-card.txt
ratchet-usb trust alice
ratchet-usb send alice
ratchet-usb recv
```

After `init`, the program shows two different things, once each. The first is a
12-word recovery phrase; keep it separate from the drive. The phrase can
reconstruct your identity, but not your contacts, prekeys, or conversations.
The second is the vault passphrase, a random six-word phrase (66 bits of
entropy) that keys Argon2id. Write it down and type it back one word per line
when the vault asks; it is not the recovery phrase and cannot restore anything.
`passphrase` generates a new one and re-encrypts the same vault, keeping the
identity, contacts and sessions; the old passphrase stops working immediately.
A vault written by an earlier version is marked as password-protected and keeps
its original one-line prompt until you run `passphrase`, which moves it to the
word format. `add` imports a contact card. Before running `trust`, compare
Alice's fingerprint by phone, in person, or through another independent channel.
The program requires verification before sending or receiving messages.

With no text argument, `send` asks for a message or reads standard input. This
keeps the message out of your shell history. `recv` accepts a pasted encrypted
block. `contacts` shows your contacts and their session status. `card` produces
your shareable card. `unlock` opens the vault and refreshes prekeys when needed.
`anchor` can enroll a reference on the computer to detect restoration of an
older vault copy; you must enable it explicitly. `migrate` prepares a format
migration, and `migrate --commit` confirms it after checks.

Besides text, `send` can carry a file. `ratchet-usb send alice --file
documento.odt` encrypts the file through the same ratchet and prints the same
kind of block; in the terminal interface, press Ctrl-P while writing to type the
path. Any format works — a photo, a document, a spreadsheet — and the file is
never modified or copied elsewhere. On the other side, `recv` recognises the
block and offers to show the file in a temporary folder; the folder is opened in
your file manager and removed when ratchet-usb closes. A file whose extension
names something a desktop might run, such as `.desktop` or `.sh`, is refused.
The whole file travels inside the block, so the block grows with the file (about
a third larger once armoured), and one file may not exceed 4 MiB.

The interface also works with the system clipboard: press `y` on a card or a
message block to copy it, and `Ctrl-V` to paste the clipboard into a text field.
Neither has to pass through a terminal selection.

The program tries to find a removable drive. If detection is unsuitable for
your setup, pass `--usb-path <directory>` to commands or set `RATCHET_USB_PATH`.

## Installing

Linux is the supported system. You need a C++20 compiler, CMake 3.16 or newer,
libsodium, OpenSSL 3.5 or newer, Rust 1.88 or newer, and Cargo. `setup.sh`
proposes packages for dnf, apt, pacman, or zypper before installing them.

Keep the system cryptography libraries updated. CI checks OpenSSL 3.5.9 and
libsodium 1.0.22; a local build may link other installed versions.

```sh
./setup.sh
```

The script builds the program, runs its tests, and installs the executable in
`~/.local/bin`. To build without installing:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Use `./setup.sh --no-deps` to skip system package installation when dependencies
are already present. macOS and Windows are not supported. The program uses
terminal and filesystem functions specific to Linux.

## What happens to a message

Each identity has an Ed25519 key and an ML-DSA-65 key. A contact card contains
the public keys, X25519 and ML-KEM-768 prekeys, and signatures covering the
card. The first message uses a hybrid X25519 and ML-KEM-768 handshake. Both
participants derive state for a classical Double Ratchet and for Signal's
Sparse Post Quantum Ratchet, called SPQR.

For every subsequent message, each ratchet produces a key. The program
combines the two keys to encrypt the text. The SPQR message, classical header,
and handshake fields are authenticated together with the ciphertext. Session
state advances only after authentication succeeds. The session and SPQR state
are saved in the encrypted vault.

Earlier hybrid cards that advertise only suite 2 keep their original message
format. An established session does not change protocol while it is active.
New cards advertise suite 4: Triple Ratchet with the X-Wing handshake
combiner. Suite 3 cards keep the previous combiner. Ratchet-USB does not use
Signal's message format and cannot exchange messages with the Signal app.
The formats are described in [docs/WIRE-V3.md](docs/WIRE-V3.md).

## Security limits

You must verify a contact's fingerprint. A signed card proves that its fields
belong to one identity; it does not prove that the identity belongs to the
person you intend to reach. A compromised computer can read passphrases and
messages while the program is open. The transport channel can observe timing
and the parties communicating. The Rust SPQR bridge wipes and best-effort locks
the secret buffers it hands back to C++, but the vendored crate still works in
ordinary heap allocations while it runs, so immediate erasure of every copy is
not guaranteed. Older copies of the vault may also remain on the physical
storage of a USB drive after a save.

Local tests cover complete conversations, out-of-order messages, replays,
altered data, and compatibility with the earlier suite. An independent
cryptographic review and longer fuzzing are still needed. Do not use this
development version as the sole protection for high-risk communications.

Opening a received file writes its decrypted bytes to a private folder on the
host and removes that folder when the program closes, but the file is plaintext
on the host until then.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and detailed limits.

## Project history

These tags are published as GitHub pre-releases. They mark development steps.
They are not production-approved releases.

| Tag | Step |
| --- | --- |
| `milestone/pq-hybrid` | Hybrid handshake and cards before SPQR integration. |
| `milestone/spqr-license` | SPQR sources and combined AGPL license. |
| `milestone/spqr-bridge` | Tested connection between C++ and the Rust library. |
| `milestone/triple-ratchet` | Triple Ratchet messages, sessions, and persistence. |
| `milestone/pq-migration-docs` | Pinned Rust build and migration documentation. |
| `milestone/local-verification` | Parser fix and local migration checks. |
| `v0.5.0-dev` | Development snapshot from the first pre-release publication. It stays on that commit. |
| `milestone/linux-only` | macOS removed from the program, CI, and documentation. |
| `milestone/suite-4-xwing` | Suite 4 X-Wing handshakes for new cards, HMAC on new rollback anchors, and a ProVerif session model. |
| `milestone/file-sharing` | Encrypted file sharing, the system clipboard, and received files opened in a temporary folder that is removed on exit. |

Inspect a step with `git show milestone/triple-ratchet`, or compare two steps
with `git diff milestone/pq-hybrid milestone/triple-ratchet`. The same commits
are listed at <https://github.com/Francy2009/Ratchet-USB/releases>.

## License and dependencies

The combined distribution that includes Signal SPQR is under
[AGPL-3.0-only](LICENSE). The original Ratchet-USB code was published under
MIT; its text remains in [LICENSE-MIT](LICENSE-MIT). Component provenance and
licenses are documented in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The software comes without a
warranty.
