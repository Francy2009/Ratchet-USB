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
// initial root key itself (see detail::derive_shared_secret below), which
// pins every key the Double Ratchet will ever derive to both identities
// rather than only the very first message's tag.
namespace ratchet::x3dh {

namespace detail {

// The info string bound into the X3DH combine step. Part of the wire
// contract: v2 is where the identity keys entered the derivation, so a v1
// peer and a v2 peer cannot accidentally agree on a secret.
inline constexpr std::string_view kCombineInfo = "Ratchet-USB/v2/x3dh";

// SK = HKDF(salt = AD, ikm = 0xFF*32 || DH1 || DH2 || DH3 || [DH4], info)
// where AD = count || Encode(IK_initiator) || Encode(IK_responder).
//
// The 0xFF prefix is the X3DH spec's guard against a specific class of
// implementation mix-ups (it makes the input distinguishable from a bare
// Curve25519 point); the low-order-point rejection that DH1..DH4 already went
// through is the actual security-relevant check on the DH values.
//
// The salt is what makes this the deviation the file comment describes. Two
// things ride on passing the *Ed25519* encodings rather than their X25519
// conversions:
//
//   - The birational map to Montgomery form computes u = (1+y)/(1-y), which
//     depends on y alone. A point and its negation differ only in the sign of
//     x -- one bit of the encoding -- so they convert to the same X25519 key
//     and produce identical DH output. Without the identity keys in the
//     transcript, two distinct identity keys, with two distinct fingerprints,
//     yield the same shared secret. Feeding the full 32-byte Ed25519 encoding
//     is what commits the handshake to the key a human actually verified.
//
//   - The order is always initiator-then-responder, on both sides, so the two
//     parties build the same salt without needing to agree on who is "first"
//     by any other means.
//
// The DH count leads the salt so a 3-DH transcript and a 4-DH transcript stay
// distinguishable even if their lengths ever coincide.
//
// Exposed here, rather than kept private to the .cpp, so the test suite can
// check it against known-answer vectors from an independent implementation --
// a round-trip test cannot tell a correct combine step from one that is wrong
// in a self-consistent way.
void derive_shared_secret(const IdentitySigningPublicKey& ik_initiator,
                          const IdentitySigningPublicKey& ik_responder,
                          const std::vector<const SecureBytes<32>*>& dhs,
                          SecureBytes<32>& out);

}  // namespace detail

// Builds the base64 card an identity publishes: its own identity key, its
// current signed prekey (already signed), and however many one-time prekeys
// are offered alongside it.
//
// The whole body is signed with `identity_sk`, not just the signed prekey.
// With no server in the picture the card travels over the same untrusted
// channel as everything else, and the only anchor is the fingerprint the user
// checked out of band -- so everything the card claims has to hang off that
// one key. Signing only the prekey (which is all the X3DH spec asks for,
// because there the bundle comes from a server over an authenticated channel)
// leaves the prekey id and every one-time prekey rewritable in transit.
std::string export_card(const IdentitySigningSecretKey& identity_sk,
                        const IdentitySigningPublicKey& identity_pk,
                        const prekey::SignedPrekey& spk,
                        const std::vector<prekey::OneTimePrekey>& otpks);

struct ImportedCard {
  IdentitySigningPublicKey identity_pub{};
  store::PeerCard card;
};

// Parses and verifies a card produced by export_card.
//
// Two signatures are checked, in this order: the card-wide signature over the
// entire body, verified *before* the body is parsed, and then the signed
// prekey's own signature. Verifying first means the parser only ever walks
// bytes the claimed identity put its name to.
//
// Both signatures are self-made, so neither says *who* the identity belongs
// to -- that link only exists once a human has compared the fingerprint over
// another channel. What they do establish is that nobody rewrote the card
// between the two of them.
//
// Throws Error on a malformed blob, an unsupported version, or a bad
// signature.
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
