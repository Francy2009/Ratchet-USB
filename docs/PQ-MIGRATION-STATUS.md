# Post-quantum migration status

This branch remains `0.5.0-dev`. Its Triple Ratchet implementation passes the
local unit and end-to-end tests; it has not received an independent security
audit or a sustained fuzzing campaign. Do not describe it as a production
release.

Implemented:

- Ed25519 and ML-DSA-65 signed contact cards, with a stated maximum suite;
- X25519 and ML-KEM-768 hybrid PQXDH opening, followed by separate EC and
  sparse post-quantum ratchet (SPQR) state;
- Signal SPQR's ML-KEM Braid state machine through a Rust C ABI, with its
  message mixed into each Triple Ratchet message key;
- v3 envelopes binding the SPQR message, EC header and PQXDH opening into the
  authenticated data; v2 hybrid conversations remain readable;
- encrypted store v9 persistence for the SPQR state and contact maximum suite;
- replay, one-time-prekey, simultaneous-opening and downgrade checks;
- local unit, command-line and terminal-interface conversation tests.

Signal SPQR is vendored at the commit recorded in `THIRD-PARTY-NOTICES.md`.
The combined distribution is AGPL-3.0-only; the original Ratchet-USB MIT
notice is preserved in `LICENSE-MIT`. Rust 1.88 or newer and Cargo are now
build dependencies. `Cargo.lock` is committed for repeatable dependency
resolution.

Remaining release gates: independent cryptographic and implementation review,
extended fuzzing, CI on Linux and macOS for this branch, and a fresh assessment
of process-memory exposure in the Rust SPQR implementation. Rust's internal
SPQR state is deserialized into ordinary heap memory while processing a
message; the persisted serialized state resides in a locked C++ buffer.
