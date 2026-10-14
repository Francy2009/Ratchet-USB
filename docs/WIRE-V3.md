# Versioned wire and store formats

Integers are little-endian; variable fields are length-prefixed. Parsers reject
truncation, trailing fields, excessive counts and size limits.

- Vault v3: `RCHT`, version, Argon2id salt/costs, random AEAD nonce, encrypted
  store and ChaCha20-Poly1305 tag. The header is AAD.
- Store v9: `RSTR`, version, vault id, generation, previous-vault digest,
  master seed, prekeys, contacts with maximum suites, sessions including SPQR
  state, and replay records. Older stores remain parseable.
- Card v4: dual identity public keys, maximum suite, classic and ML-KEM
  bundles, IDs and epochs; Ed25519 and ML-DSA-65 signatures cover the canonical
  body. Existing suite-2 cards remain importable.
- Envelope v2: hybrid PQXDH opening, authenticated suite and sender, EC
  ratchet header and ciphertext. Used for existing hybrid-only conversations.
- Envelope v3: suites `TRIPLE_RATCHET_V1` and `XWING_TRIPLE_RATCHET_V1`,
  authenticated SPQR message in addition to the v2 fields. The canonical
  prefix containing both ratchet inputs is AEAD AAD; the EC and SPQR message
  keys are combined before encrypting or decrypting the payload. Suite 4
  changes the handshake combiner only. The message body stays version 3.

`CLASSIC_V2` is limited to legacy reading and migration. New cards advertise
`XWING_TRIPLE_RATCHET_V1`. Cards that advertise `TRIPLE_RATCHET_V1` keep that
suite and the previous handshake combiner. Cards that advertise
`HYBRID_PQXDH_V1` keep using v2. An established session never changes suite
in place.
