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

- Messages are end-to-end encrypted with X3DH plus a Double Ratchet, so the
  channel carrying the ciphertext (WhatsApp, email, a forum) learns nothing.
- Forward secrecy: a key compromised today does not decrypt yesterday's
  messages.
- Everything secret lives on the removable drive, never on the host disk.
- The vault is sealed with Argon2id and ChaCha20-Poly1305, so a stolen drive is
  worth nothing without the passphrase.

What is explicitly **out of scope**, in the sense that the design does not try
to defend against it:

- **A compromised host.** Malware on the machine you plug the drive into can
  read the passphrase as you type it and the plaintext as it is printed.
  Nothing in this tool can fix that.
- **Another process running as you, on macOS.** On Linux the tool clears its
  dumpable flag at startup, which stops a process running as the same user from
  attaching with ptrace and reading an open vault out of memory. There is no
  portable equivalent in this codebase for macOS, so a macOS build does not have
  that protection — one more reason the platform is listed as unverified.
  Refusing to write a core dump works on both.
- **Traffic analysis.** The transport sees a base64 block of a certain size at
  a certain time, addressed to somebody. That metadata is not hidden.
- **A forgotten passphrase.** There is no recovery path, by design. The BIP-39
  phrase restores the identity, not the vault's contacts or history.
- **Physical coercion.** There is no duress passphrase and no deniable volume.
- **Multiple devices sharing one identity**, group chats, and a key directory.
  These are not implemented; see the roadmap in the README.

## No warranty, and using it lawfully

This is version 0.2.0 and it is pre-1.0 in the way that matters: the vault
and message formats are not frozen yet, so a future release may not read what
this one wrote. Keep your BIP-39 words, and do not treat a vault as a durable
archive.

It is released under the MIT License, which disclaims warranty and liability
in full, and I mean that literally rather than as boilerplate: the software
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
# Warnings are fatal; both compilers, both build types.
cmake -S . -B build -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic -Werror"
cmake --build build && ctest --test-dir build --output-on-failure
./test/smoke.sh build/ratchet-usb

# The key schedule against vectors from an independent Python implementation.
python3 test/vectors/reference.py --check

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
```

If you find an input that makes `fuzz_parsers` do anything other than return or
throw `ratchet::Error`, that is a finding — please report it, and include the
crashing input, which libFuzzer writes to `crash-*` in the working directory.
