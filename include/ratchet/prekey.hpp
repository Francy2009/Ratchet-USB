#ifndef RATCHET_PREKEY_HPP
#define RATCHET_PREKEY_HPP

#include <cstdint>
#include <vector>

#include "ratchet/identity.hpp"
#include "ratchet/x25519.hpp"

namespace ratchet::prekey {

// A signed prekey: a medium-lived X25519 keypair, published with a signature
// from the identity key so a contact can trust it belongs to that identity
// without a server vouching for it.
struct SignedPrekey {
  uint32_t id = 0;
  x25519::PublicKey pub{};
  x25519::SecretKey sk;
  Signature signature{};
  // Unix timestamp (seconds), used to decide when the prekey is old enough
  // to rotate automatically. Never published on the card itself.
  uint64_t created_at = 0;
};

// A one-time prekey: an X25519 keypair meant to be consumed by exactly one
// X3DH handshake and then deleted.
struct OneTimePrekey {
  uint32_t id = 0;
  x25519::PublicKey pub{};
  x25519::SecretKey sk;
};

// Generates a fresh signed prekey and signs its public half with the identity
// key. Prekeys are random, not derived from the seed: if a one-time prekey
// could be regenerated from the seed alone, restoring the vault from the 12
// words would resurrect an already-spent prekey, defeating the "one time"
// guarantee. The trade-off, spelled out in the README, is that prekeys are
// backed up by the vault file, not by the mnemonic.
SignedPrekey generate_signed_prekey(const IdentitySigningSecretKey& identity_sk,
                                    uint32_t id);

// Verifies a signed prekey's signature against the identity that supposedly
// signed it. Used both when importing a contact's card and, defensively,
// before using our own stored prekey.
bool verify_signed_prekey_signature(const IdentitySigningPublicKey& identity_pk,
                                    const x25519::PublicKey& spk_pub,
                                    const Signature& signature);

std::vector<OneTimePrekey> generate_one_time_prekeys(uint32_t start_id,
                                                      std::size_t count);

}  // namespace ratchet::prekey

#endif  // RATCHET_PREKEY_HPP
