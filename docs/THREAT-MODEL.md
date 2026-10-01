# Threat model

Protected against by design and tests:

- malicious USB files, malformed cards/envelopes, symlinks, hardlinks and oversized input;
- modification, replay, duplication and reordering of authenticated messages;
- passive recording followed by later compromise, within Double Ratchet forward-secrecy limits;
- classic-only downgrade after a contact has acquired a hybrid minimum suite;
- message length fingerprinting via ISO/IEC 7816-4 discrete bucket padding;
- concurrent cooperating processes and host-detectable USB state rollback/fork;
- theft of a locked vault, subject to passphrase strength and configured Argon2id cost.

Partially protected:

- rollback is detectable only on hosts where the user explicitly enrolled an
  anchor; USB-only mode cannot distinguish a copied older vault;
- temporary key compromise gets classical Double Ratchet healing, but
  post-quantum PCS awaits the ML-KEM Braid phase;
- MITM and key substitution are prevented only after users compare the hybrid
  safety number through an independent channel.

Out of scope:

- malware controlling the live Ratchet-USB process, keyboard, terminal or RNG;
- physical coercion and denial of service by destroying or withholding the USB;
- secure physical deletion from flash wear-leveling media;
- transport-level traffic analysis (transmission timing, frequency, and carrier-level metadata remain observable, though message payload lengths are obscured by bucket padding).
