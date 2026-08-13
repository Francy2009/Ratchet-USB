#ifndef RATCHET_X3DH_HPP
#define RATCHET_X3DH_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "ratchet/identity.hpp"
#include "ratchet/prekey.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/store.hpp"
#include "ratchet/x25519.hpp"

// X3DH key agreement (Signal's "Extended Triple Diffie-Hellman"), adapted to
// a setting with no server: a contact's prekey bundle is not fetched on
// demand, it is exchanged once, up front, as a card the user pastes over the
// same channel as everything else.
//
// One deliberate deviation from the reference protocol: X3DH's associated
// data (the two parties' identity keys) is not attached to the AEAD tag of
// the first message -- instead it is folded into the derivation of the
// initial root key itself (see derive_shared_secret in x3dh.cpp), which
// pins every key the Double Ratchet will ever derive to both identities
// rather than only the very first message's tag.
namespace ratchet::x3dh {

// Builds the base64 card an identity publishes: its own identity key, its
// current signed prekey (already signed), and however many one-time prekeys
// are offered alongside it.
std::string export_card(const IdentitySigningPublicKey& identity_pk,
                        const prekey::SignedPrekey& spk,
                        const std::vector<prekey::OneTimePrekey>& otpks);

struct ImportedCard {
  IdentitySigningPublicKey identity_pub{};
  store::PeerCard card;
};

// Parses and verifies a card produced by export_card: the signed prekey's
// signature must check out against the claimed identity key. Throws Error on
// a malformed blob or a bad signature.
ImportedCard import_card(std::string_view base64_card);

struct InitiatorResult {
  SecureBytes<32> shared_secret;
  x25519::SecretKey ephemeral_sk;
  x25519::PublicKey ephemeral_pk{};
  uint32_t spk_id = 0;
  // The signed prekey this handshake actually ran against, returned so the
  // caller can seed the ratchet with it directly. Reading it back out of the
  // contact's card instead would be re-deriving a fact the handshake already
  // established, against a card that is mutated during the call.
  x25519::PublicKey spk_pub{};
  std::optional<uint32_t> otpk_id;
};

// Alice's side: consumes one of Bob's one-time prekeys from `contact.card`
// (removing it so it is not offered again) if one is available, and returns
// the shared secret plus the fields Bob needs to complete his side. Falls
// back to a 3-DH handshake (no one-time prekey) if the stored card's pool is
// empty, per the X3DH spec's fallback for exhausted bundles.
InitiatorResult initiate(const IdentitySigningSecretKey& my_identity_sk,
                         const IdentitySigningPublicKey& my_identity_pk,
                         store::Contact& contact);

// Bob's side, given Alice's identity key and ephemeral key from her initial
// message, plus which of Bob's own prekeys she used. `my_otpk` is null when
// the initial message did not reference one.
SecureBytes<32> respond(const IdentitySigningSecretKey& my_identity_sk,
                        const IdentitySigningPublicKey& my_identity_pk,
                        const IdentitySigningPublicKey& their_identity_pk,
                        const x25519::PublicKey& their_ephemeral_pub,
                        const prekey::SignedPrekey& my_spk,
                        const prekey::OneTimePrekey* my_otpk);

}  // namespace ratchet::x3dh

#endif  // RATCHET_X3DH_HPP
