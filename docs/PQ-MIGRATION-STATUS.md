# Post-quantum migration status

This branch is an implementation-in-progress and is deliberately labelled
`0.5.0-dev`. It must not be presented as the planned 0.6 or 1.0 release.

Implemented and enforced:

- vault v3 generation chain, exclusive lifecycle lock, bounded descriptor-relative I/O;
- optional Secret Service/macOS Keychain rollback anchor with explicit enrollment;
- transactional legacy migration with a verified prepared state and explicit commit;
- versioned protocol suites with authenticated headers and no classic send fallback;
- ML-KEM-768 PQXDH contribution and Ed25519 + ML-DSA-65 contact-card signatures;
- hybrid safety numbers, mandatory out-of-band verification and verification reset on upgrade;
- replay, one-time-prekey, simultaneous-opening and downgrade checks;
- Triple Ratchet initial-secret split and hybrid message-key KDF.

Not implemented:

- the ML-KEM Braid state machine, incremental ML-KEM operations and erasure coding;
- Sparse Post-Quantum Ratchet epoch chains and their skipped-key maps;
- envelope v3 carrying a composite EC/SCKA header;
- a complete independent cryptographic audit and 24-hour-per-target fuzz campaign.

The blocker is architectural, not merely unfinished glue. OpenSSL 3.5 exposes
standard ML-KEM key generation, encapsulation and decapsulation, but not the
incremental `Encaps1`/`Encaps2` operations required by ML-KEM Braid. Signal's
reference SPQR implementation supplies that machinery in Rust under AGPL-3.0.
Using it would add a Rust/FFI dependency and create a licensing decision for
this MIT project. Reimplementing the ML-KEM internals locally would violate the
project rule against custom post-quantum cryptography.

Until that dependency/licensing decision is made, `TRIPLE_RATCHET_V1` is a
reserved suite value and is never negotiated or emitted.
Development builds that advertised this suite in v4 contact cards issued
incompatible cards. Re-export and re-import those cards with a corrected build;
the current parser rejects the unsupported suite rather than treating it as
an implemented Triple Ratchet.
