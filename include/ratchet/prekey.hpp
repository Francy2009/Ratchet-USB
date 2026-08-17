#ifndef RATCHET_PREKEY_HPP
#define RATCHET_PREKEY_HPP

#include <cstdint>
#include <string_view>
#include <vector>

#include "ratchet/identity.hpp"
#include "ratchet/x25519.hpp"

namespace ratchet::prekey {

// Domain separation for the identity key's signature over a signed prekey.
// Part of the wire contract: it is length-prefixed into the signed message, so
// a signature made under a different context can never verify under this one.
inline constexpr std::string_view kSignedPrekeyContext =
    "Ratchet-USB/v2/signed-prekey";

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

// Re-signs an existing prekey in place, keeping its key pair and its id.
//
// This is the migration path for a vault written before the signature covered
// a context string and the id: the key pair itself is still perfectly good, so
// throwing it away would invalidate every card already in circulation for no
// reason. `unlock` and `card` call this for any stored prekey whose signature
// no longer verifies under the current scheme.
void resign_signed_prekey(const IdentitySigningSecretKey& identity_sk,
                          SignedPrekey& record);

// Verifies a signed prekey's signature against the identity that supposedly
// signed it. Used both when importing a contact's card and, defensively,
// before using our own stored prekey. `spk_id` is covered by the signature, so
// it has to be the id the prekey was published under -- passing a different
// one is exactly the tampering this is here to catch.
bool verify_signed_prekey_signature(const IdentitySigningPublicKey& identity_pk,
                                    uint32_t spk_id,
                                    const x25519::PublicKey& spk_pub,
                                    const Signature& signature);

std::vector<OneTimePrekey> generate_one_time_prekeys(uint32_t start_id,
                                                      std::size_t count);

}  // namespace ratchet::prekey

#endif  // RATCHET_PREKEY_HPP
