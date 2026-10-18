# Security

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[private vulnerability reporting](https://github.com/Francy2009/Ratchet-USB/security/advisories/new)
on this repository. Do not open a public issue for anything that affects the
confidentiality of messages, keys, or the vault.

Expect a first reply within a week. This is a personal project, not a funded
one, so there is no bounty and no guaranteed patch window — but a real finding
will get a real answer, and credit in the fix unless you would rather not have
it.

If you are reporting something that affects users right now rather than a
theoretical weakness, say so in the first line; it changes how fast this gets
looked at.

## What this project claims, and what it does not

**It has not been independently audited.** That is the single most important
thing on this page. The code is carefully written and heavily tested, and it
has been reviewed — but reviewed by the people who wrote it, which is not the
same thing. If being read would put you in real danger, do not make this your
only layer.

What the design does aim at:

- New suite-3 sessions use an X25519 + ML-KEM-768 hybrid opening, then
  combine keys from the classical Double Ratchet and Signal SPQR on every
  message. Existing suite-2 sessions continue with their original hybrid
  opening and classical Double Ratchet. The transport cannot read plaintext.
- Ratchet forward secrecy limits what a newly compromised session state can
  reveal about past messages. Copies of older vault files can retain older
  keys, especially on flash storage.
- Message length fingerprinting protection: Plaintext payloads are padded
  according to ISO/IEC 7816-4 into discrete buckets (128, 256, 512, 1024, 2048
  bytes, and 1024-byte increments beyond) before AEAD encryption. This hides
  exact plaintext length but still reveals an approximate size bucket.
- Persistent secret state lives in the encrypted vault on the removable
  drive. An explicitly enrolled host keyring record stores only vault id,
  generation and ciphertext digest.
- The vault uses Argon2id and ChaCha20-Poly1305. A stolen copy permits an
  offline passphrase-guessing attack, so passphrase strength matters.

## The terminal interface

Running `ratchet-usb` with no arguments opens a full-screen interface in the
terminal. It is worth being precise about what that did and did not change,
since the whole design here is about not having much surface to attack.

What it does not add:

- **No terminal UI dependency.** Cryptography uses libsodium and OpenSSL 3.5+.
  The terminal handling
  — raw mode, the frame, the colours, the ASCII banner — is a few hundred lines
  in this tree rather than ncurses, which would also have meant this process
  reading and interpreting terminfo files. The colours are the sixteen every
  terminal has had for forty years, written as a fixed set of SGR sequences,
  and they are off whenever the output is not a terminal or `NO_COLOR` is set.
- **No graphical toolkit** or X11/Wayland window. The interface does not
  publish message text to a desktop accessibility bus. On Linux, the optional
  rollback anchor uses libsecret and may communicate with Secret Service over
  D-Bus; its record contains no message or key material.
- **No config, history, cache, theme or layout files.** The interface keeps
  nothing of its own on the host. The optional rollback anchor is a non-secret
  generation/digest record in Secret Service and is created only by the
  `anchor` command. The operating system may still write process memory to swap
  or a crash dump.
- **A received file is staged, in the clear, on a private tmpfs.** When the
  user chooses to open an arriving file, its decrypted bytes are written to a
  `0600` file inside a private `0700` directory under `$XDG_RUNTIME_DIR` (or
  under `$TMPDIR`, falling back to `/tmp`, when that is unset), and that folder
  is opened in the file manager rather than the file being handed straight to
  an application. The interface removes the folder synchronously as it exits;
  a detached helper is the fallback if the process dies before reaching that
  point, and holds a one-shot `recv` folder for a short minimum so the desktop
  can draw it. If no helper can be forked, the folder is removed on the
  ordinary exit paths. The staging file is never on the USB drive, but it is
  plaintext on the host until the folder is removed.
- **Clipboard and default-application handoff are explicit and opt-in.**
  Copying a block shells out to the session's clipboard helper (`wl-copy`,
  `xclip` or `xsel`), and opening a received file runs `xdg-open`. Both happen
  only when the user asks; nothing is copied or opened automatically. A file
  whose type a desktop might *execute* rather than display (`.desktop`, `.sh`,
  `.py`, executables and the like) is refused outright, and the file's
  extension is shown before any open is offered.
- **No window title**, ever. A title naming the tool would appear in the
  taskbar, the window switcher, and any screenshot or screen share.
- **No mouse reporting**, which keeps the escape sequences it has to decode
  down to a handful and leaves the terminal's own selection working.
- **Nothing on the existing code paths.** With stdin or stdout redirected, none
  of this code runs: a bare `ratchet-usb` produces the same error it always
  did, and every command behaves exactly as before. `test/smoke.sh` checks it.

What it genuinely improves: `ratchet-usb send alice "the message"` puts that
message into the shell's history file, in the clear, on the host disk. Typed
into the interface it never reaches `argv` or the shell.

What it costs, stated plainly: **the vault stays open longer.** The command
line opens and closes it once per command; the interface opens it once and
keeps the seed, the session keys and the passphrase in memory across a whole
session. Against the threat model this changes little — a compromised host is
already out of scope, and C++ secret buffers are locked against swap — but
the window is wider, so it is narrowed deliberately:

The integrated Rust SPQR code temporarily holds its working state in ordinary
heap allocations. Those allocations are not guaranteed to be locked or wiped
on release. This is a remaining memory-hardening limitation of this build.

- The vault closes on its own after three minutes with no key pressed
  (`--idle-lock <seconds>`, `0` to switch it off), and immediately if the
  process is suspended and resumed.
- Locking, quitting and Ctrl-C all run the same path, which wipes the seed, the
  keys and the passphrase and clears what they produced off the screen.
- Ctrl-C is read as a keystroke rather than a signal precisely so that it takes
  that path: a signal handler cannot safely wipe memory.
- The interface draws on the alternate screen, so nothing from the session is
  left in the scrollback when it exits.

And one thing it does not change: everything a contact sends is still treated
as hostile text. An alias or a message body is escaped before it is drawn, and
lines are truncated rather than wrapped, so neither an escape sequence nor a
five-thousand-character alias can repaint the screen or push a "not verified"
warning out of sight. Colour did not weaken that: the style of a run is chosen
by the interface and never comes from the text, so a message cannot paint
itself green, and every run is closed again so a truncated line cannot leave
the terminal — or the shell prompt after it — painted. There are tests for all
of it, and a fuzzer that drives arbitrary bytes through the key decoder and the
state machine and checks the drawn frame each time.

What is explicitly **out of scope**, in the sense that the design does not try
to defend against it:

- **A compromised host.** Malware on the machine you plug the drive into can
  read the passphrase as you type it and the plaintext as it is printed.
  Nothing in this tool can fix that.
- **Another process running as you.** The tool clears its dumpable flag
  (`PR_SET_DUMPABLE = 0`), stopping a process running as the same user from
  attaching with ptrace and reading an open vault out of memory. It also
  refuses to write a core dump (`RLIMIT_CORE = 0`).
- **Traffic analysis.** The transport sees a base64 block at a certain time,
  addressed to somebody. While payload lengths are masked into discrete buckets
  via ISO/IEC 7816-4 padding, transmission timing and metadata are not hidden.
- **A forgotten passphrase.** There is no recovery path, by design. The BIP-39
  phrase restores the identity, not the vault's contacts or history.
- **Physical coercion.** There is no duress passphrase and no deniable volume.
- **Multiple devices sharing one identity**, group chats, and a key directory.
  These are not implemented in this version.

## No warranty, and using it lawfully

This is version 0.5.0-dev and it is pre-1.0 in the way that matters: the vault
and message formats are not frozen yet, so a future release may not read what
this one wrote. Keep your BIP-39 words, and do not treat a vault as a durable
archive.

The combined distribution with Signal SPQR is under AGPL-3.0-only; earlier
Ratchet-USB code was published under MIT (see `LICENSE-MIT`). The software
is provided without warranty, and I mean that literally rather than as boilerplate: it
comes as is, and I am not responsible for what it does or fails to do.
Combined with the fact that nothing leaves your machine, it also means I have
nothing to give you if something goes wrong — no copy of your vault, no way
to reset a passphrase, no view of your messages.

Encryption is regulated differently from one country to the next, and in a
few places using or importing it is restricted outright. Checking what
applies where you are is your job. Use it lawfully: it is a privacy tool, not
cover for hurting somebody.

## Verifying the build yourself

Every push runs, and you can run locally:

```sh
# The interface, driven through a real pty: a whole conversation, plus the
# assertion that no window title, no mouse reporting and no escape byte from
# somebody else's text ever reaches the terminal.
python3 test/smoke_ui.py build/ratchet-usb

# Warnings are fatal; both compilers, both build types.
cmake -S . -B build -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic -Werror"
cmake --build build && ctest --test-dir build --output-on-failure
./test/smoke.sh build/ratchet-usb

# The key schedule against vectors from an independent Python implementation.
python3 test/vectors/reference.py --check

# Signal SPQR, the bridge, and locked dependency license metadata.
cargo test --manifest-path third_party/spqr/Cargo.toml --locked
cargo test --manifest-path rust/spqr_bridge/Cargo.toml --locked
python3 ci/check-rust-licenses.py --check

# Sanitizers, and Valgrind for uninitialised key material.
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g"
cmake --build build-asan && ctest --test-dir build-asan --output-on-failure

# The parsers that run on input nobody vouched for.
cmake -S . -B build-fuzz -DRATCHET_BUILD_FUZZERS=ON -DRATCHET_BUILD_TESTS=OFF \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
cmake --build build-fuzz
mkdir -p .fuzz-out   # libFuzzer writes what it finds into the first directory
./build-fuzz/test/fuzz/fuzz_parsers .fuzz-out test/fuzz/corpus -max_total_time=60

# What a terminal hands over, which includes whatever was pasted into it.
./build-fuzz/test/fuzz/fuzz_ui_keys .fuzz-out test/fuzz/corpus_ui -max_total_time=60
```

If you find an input that makes `fuzz_parsers` do anything other than return or
throw `ratchet::Error`, that is a finding — please report it, and include the
crashing input, which libFuzzer writes to `crash-*` in the working directory.
