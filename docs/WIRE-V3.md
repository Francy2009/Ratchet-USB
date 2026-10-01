# Versioned wire and store formats

All integers are little-endian and all variable fields are length-prefixed.
Parsers reject truncation, trailing fields, excessive counts and size limits.

- Vault v3: `RCHT`, version, Argon2id salt/costs, random AEAD nonce, encrypted
  store and ChaCha20-Poly1305 tag. The header is AAD.
- Store v8: `RSTR`, version, 128-bit vault id, 64-bit generation, previous-vault
  SHA-256 digest, master seed, classic/PQ prekeys, contacts, sessions and replay records.
- Card v4: dual identity public keys, suite, classic and ML-KEM bundles, IDs and
  epochs; the canonical body carries mandatory Ed25519 and ML-DSA-65 signatures.
- Envelope v2: `RMSG`, version, authenticated suite/sender/initial PQXDH fields,
  EC ratchet header and ciphertext. The complete canonical header is AEAD AAD.

`CLASSIC_V2` is reserved for legacy reading/migration and cannot open or send a
new session. `HYBRID_PQXDH_V1` is the current emitted suite.
`TRIPLE_RATCHET_V1` is reserved but rejected until composite envelope v3 and a
conformant ML-KEM Braid implementation exist.
