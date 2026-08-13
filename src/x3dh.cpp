#include "ratchet/x3dh.hpp"

#include <sodium.h>

#include <array>
#include <cstring>
#include <vector>

#include "ratchet/kdf.hpp"
#include "ratchet/serial.hpp"
#include "ratchet/wire.hpp"

namespace ratchet::x3dh {
namespace {

constexpr std::array<uint8_t, 4> kCardMagic = {'R', 'C', 'R', 'C'};
constexpr uint8_t kCardVersion = 1;
constexpr std::string_view kCombineInfo = "Ratchet-USB/v1/x3dh";

// SK = HKDF(salt=0, ikm = 0xFF*32 || DH1 || DH2 || DH3 || [DH4], info=...).
// The 0xFF prefix is the X3DH spec's guard against a specific class of
// implementation mix-ups (it makes the input distinguishable from a bare
// Curve25519 point); the low-order-point rejection that DH1..DH4 already
// went through is the actual security-relevant check.
void derive_shared_secret(const std::vector<const SecureBytes<32>*>& dhs,
                          SecureBytes<32>& out) {
  init_sodium();
  SecureBuffer ikm;
  uint8_t prefix[32];
  std::memset(prefix, 0xFF, sizeof prefix);
  ikm.append(prefix, sizeof prefix);
  sodium_memzero(prefix, sizeof prefix);
  for (const SecureBytes<32>* dh : dhs) {
    ikm.append(dh->data(), dh->size());
  }

  kdf::Prk prk;
  kdf::extract(prk, nullptr, 0, ikm.data(), ikm.size());
  kdf::expand(out.data(), out.size(), kCombineInfo, prk);
}

}  // namespace

std::string export_card(const IdentitySigningPublicKey& identity_pk,
                        const prekey::SignedPrekey& spk,
                        const std::vector<prekey::OneTimePrekey>& otpks) {
  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> w(body);

  w.bytes(kCardMagic.data(), kCardMagic.size());
  w.u8(kCardVersion);
  w.bytes(identity_pk.data(), identity_pk.size());
  w.u32(spk.id);
  w.bytes(spk.pub.data(), spk.pub.size());
  w.bytes(spk.signature.data(), spk.signature.size());
  w.u32(static_cast<uint32_t>(otpks.size()));
  for (const prekey::OneTimePrekey& o : otpks) {
    w.u32(o.id);
    w.bytes(o.pub.data(), o.pub.size());
  }

  return wire::encode_block("CARD", body.data(), body.size());
}

ImportedCard import_card(std::string_view base64_card) {
  const std::vector<uint8_t> body = wire::decode_block("CARD", base64_card);
  serial::Reader r(body.data(), body.size());

  std::array<uint8_t, 4> magic{};
  r.bytes(magic.data(), magic.size());
  if (magic != kCardMagic) {
    throw Error("not a Ratchet-USB contact card");
  }
  const uint8_t version = r.u8();
  if (version != kCardVersion) {
    throw Error("unsupported contact card version " + std::to_string(version));
  }

  ImportedCard out;
  r.bytes(out.identity_pub.data(), out.identity_pub.size());
  out.card.spk_id = r.u32();
  r.bytes(out.card.spk_pub.data(), out.card.spk_pub.size());
  r.bytes(out.card.spk_signature.data(), out.card.spk_signature.size());

  const uint32_t otpk_count = r.u32();
  out.card.one_time_prekeys.reserve(otpk_count);
  for (uint32_t i = 0; i < otpk_count; ++i) {
    store::PeerOtpk o;
    o.id = r.u32();
    r.bytes(o.pub.data(), o.pub.size());
    out.card.one_time_prekeys.push_back(o);
  }

  if (!r.at_end()) {
    throw Error("contact card has trailing data");
  }

  if (!prekey::verify_signed_prekey_signature(out.identity_pub, out.card.spk_pub,
                                              out.card.spk_signature)) {
    throw Error(
        "the card's signed prekey signature does not match its identity key "
        "(the card may be corrupted or forged)");
  }

  return out;
}

InitiatorResult initiate(const IdentitySigningSecretKey& my_identity_sk,
                         const IdentitySigningPublicKey& my_identity_pk,
                         store::Contact& contact) {
  if (!contact.card) {
    throw Error(
        "no prekey bundle stored for this contact yet; import their card "
        "first (`add-contact`)");
  }
  store::PeerCard& card = *contact.card;

  if (!prekey::verify_signed_prekey_signature(contact.identity_pub, card.spk_pub,
                                              card.spk_signature)) {
    throw Error("stored signed prekey signature is no longer valid");
  }

  IdentityDHSecretKey my_dh_sk;
  IdentityDHPublicKey my_dh_pk;
  identity_dh_keypair(my_identity_sk, my_identity_pk, my_dh_sk, my_dh_pk);
  IdentityDHPublicKey their_dh_pk;
  identity_dh_public(contact.identity_pub, their_dh_pk);

  x25519::SecretKey eph_sk;
  x25519::PublicKey eph_pk;
  x25519::generate_keypair(eph_sk, eph_pk);

  SecureBytes<32> dh1;
  SecureBytes<32> dh2;
  SecureBytes<32> dh3;
  x25519::dh(my_dh_sk, card.spk_pub, dh1);   // DH(IK_A, SPK_B)
  x25519::dh(eph_sk, their_dh_pk, dh2);      // DH(EK_A, IK_B)
  x25519::dh(eph_sk, card.spk_pub, dh3);     // DH(EK_A, SPK_B)

  InitiatorResult result;
  result.spk_id = card.spk_id;
  result.spk_pub = card.spk_pub;
  result.ephemeral_pk = eph_pk;

  std::vector<const SecureBytes<32>*> parts = {&dh1, &dh2, &dh3};
  SecureBytes<32> dh4;
  if (!card.one_time_prekeys.empty()) {
    // Picked at random rather than from a fixed position. The same card is
    // handed to everyone, so a fixed choice makes every contact pick the very
    // same prekey: the first to write consumes it and everybody else is left
    // referring to one the recipient no longer has. Choosing at random does
    // not make that impossible -- prekeys shared by hand are finite and a
    // collision is always on the table -- but it stops it from happening
    // every single time.
    const std::size_t pick = randombytes_uniform(
        static_cast<uint32_t>(card.one_time_prekeys.size()));
    const store::PeerOtpk otpk = card.one_time_prekeys[pick];
    card.one_time_prekeys.erase(card.one_time_prekeys.begin() +
                                static_cast<std::ptrdiff_t>(pick));
    result.otpk_id = otpk.id;
    x25519::dh(eph_sk, otpk.pub, dh4);
    parts.push_back(&dh4);
  }

  derive_shared_secret(parts, result.shared_secret);
  result.ephemeral_sk = std::move(eph_sk);
  return result;
}

SecureBytes<32> respond(const IdentitySigningSecretKey& my_identity_sk,
                        const IdentitySigningPublicKey& my_identity_pk,
                        const IdentitySigningPublicKey& their_identity_pk,
                        const x25519::PublicKey& their_ephemeral_pub,
                        const prekey::SignedPrekey& my_spk,
                        const prekey::OneTimePrekey* my_otpk) {
  IdentityDHSecretKey my_dh_sk;
  IdentityDHPublicKey my_dh_pk;
  identity_dh_keypair(my_identity_sk, my_identity_pk, my_dh_sk, my_dh_pk);
  IdentityDHPublicKey their_dh_pk;
  identity_dh_public(their_identity_pk, their_dh_pk);

  SecureBytes<32> dh1;
  SecureBytes<32> dh2;
  SecureBytes<32> dh3;
  x25519::dh(my_spk.sk, their_dh_pk, dh1);    // DH(SPK_B, IK_A)
  x25519::dh(my_dh_sk, their_ephemeral_pub, dh2);    // DH(IK_B, EK_A)
  x25519::dh(my_spk.sk, their_ephemeral_pub, dh3);   // DH(SPK_B, EK_A)

  std::vector<const SecureBytes<32>*> parts = {&dh1, &dh2, &dh3};
  SecureBytes<32> dh4;
  if (my_otpk != nullptr) {
    x25519::dh(my_otpk->sk, their_ephemeral_pub, dh4);
    parts.push_back(&dh4);
  }

  SecureBytes<32> secret;
  derive_shared_secret(parts, secret);
  return secret;
}

}  // namespace ratchet::x3dh
