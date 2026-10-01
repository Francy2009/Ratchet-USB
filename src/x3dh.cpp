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
// v1 signed only the prekey and left the prekey id and every one-time prekey
// unauthenticated. There is no way to retrofit a signature onto a v1 card --
// only the identity that issued it could -- so v1 is refused rather than
// accepted with a warning, and the fix for a stale card is to ask for a new one.
constexpr uint8_t kCardVersion = 2;
constexpr std::string_view kCardContext = "Ratchet-USB/v2/contact-card";
constexpr uint8_t kHybridCardVersion = 4;
constexpr std::string_view kHybridCardContext =
    "Ratchet-USB/v4/hybrid-contact-card";
constexpr std::string_view kPqPrekeyContext =
    "Ratchet-USB/v4/ML-KEM-768/signed-prekey";

}  // namespace

namespace detail {

void derive_shared_secret(const IdentitySigningPublicKey& ik_initiator,
                          const IdentitySigningPublicKey& ik_responder,
                          const std::vector<const SecureBytes<32>*>& dhs,
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

  // See the header for why this is the Ed25519 encoding and not its X25519
  // conversion, and why the order is fixed rather than negotiated.
  std::vector<uint8_t> ad;
  ad.reserve(1 + ik_initiator.size() + ik_responder.size());
  ad.push_back(static_cast<uint8_t>(dhs.size()));
  ad.insert(ad.end(), ik_initiator.begin(), ik_initiator.end());
  ad.insert(ad.end(), ik_responder.begin(), ik_responder.end());

  kdf::Prk prk;
  kdf::extract(prk, ad.data(), ad.size(), ikm.data(), ikm.size());
  kdf::expand(out.data(), out.size(), kCombineInfo, prk);
}

}  // namespace detail

namespace {

using detail::derive_shared_secret;

void combine_hybrid(const IdentitySigningPublicKey& initiator,
                    const IdentitySigningPublicKey& responder,
                    const SecureBytes<32>& classical,
                    const pq::MlKemSharedSecret& pq_static,
                    const pq::MlKemSharedSecret* pq_one_time,
                    SecureBytes<32>& out) {
  SecureBuffer ikm;
  ikm.append(classical.data(), classical.size());
  ikm.append(pq_static.data(), pq_static.size());
  if (pq_one_time) ikm.append(pq_one_time->data(), pq_one_time->size());
  std::vector<uint8_t> salt;
  salt.insert(salt.end(), initiator.begin(), initiator.end());
  salt.insert(salt.end(), responder.begin(), responder.end());
  kdf::Prk prk;
  kdf::extract(prk, salt.data(), salt.size(), ikm.data(), ikm.size());
  kdf::expand(out.data(), out.size(),
              "Ratchet-USB/v3/PQXDH/X25519+ML-KEM-768", prk);
}

// Everything a card commits to, in one buffer: the identity, the signed
// prekey with its id, and every one-time prekey. This is what the card-wide
// signature covers, and it is deliberately built by one function so the writer
// and the reader cannot drift.
std::vector<uint8_t> build_signed_body(
    const IdentitySigningPublicKey& identity_pk, const prekey::SignedPrekey& spk,
    const std::vector<prekey::OneTimePrekey>& otpks) {
  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> w(body);
  w.str(kCardContext);
  w.bytes(identity_pk.data(), identity_pk.size());
  w.u32(spk.id);
  w.bytes(spk.pub.data(), spk.pub.size());
  w.bytes(spk.signature.data(), spk.signature.size());
  w.u32(static_cast<uint32_t>(otpks.size()));
  for (const prekey::OneTimePrekey& o : otpks) {
    w.u32(o.id);
    w.bytes(o.pub.data(), o.pub.size());
  }
  return body;
}

}  // namespace

std::string export_card(const IdentitySigningSecretKey& identity_sk,
                        const IdentitySigningPublicKey& identity_pk,
                        const prekey::SignedPrekey& spk,
                        const std::vector<prekey::OneTimePrekey>& otpks) {
  const std::vector<uint8_t> signed_body =
      build_signed_body(identity_pk, spk, otpks);

  Signature card_sig{};
  sign(identity_sk, signed_body.data(), signed_body.size(), card_sig);

  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> w(body);
  w.bytes(kCardMagic.data(), kCardMagic.size());
  w.u8(kCardVersion);
  w.blob(signed_body.data(), signed_body.size());
  w.bytes(card_sig.data(), card_sig.size());

  return wire::encode_block("CARD", body.data(), body.size());
}

std::string export_hybrid_card(
    const IdentitySigningSecretKey& identity_sk,
    const IdentitySigningPublicKey& identity_pk,
    const pq::MlDsaKeyPair& pq_identity, const prekey::SignedPrekey& spk,
    const std::vector<prekey::OneTimePrekey>& otpks,
    const store::PqPrekey& pq_spk,
    const std::vector<store::PqPrekey>& pq_otpks) {
  std::vector<uint8_t> pq_prekey_body;
  serial::Writer<std::vector<uint8_t>> pw(pq_prekey_body);
  pw.str(kPqPrekeyContext);
  pw.u32(pq_spk.id);
  pw.bytes(pq_spk.key.public_key.data(), pq_spk.key.public_key.size());
  Signature pq_spk_ed_sig{};
  pq::MlDsaSignature pq_spk_pq_sig{};
  sign(identity_sk, pq_prekey_body.data(), pq_prekey_body.size(), pq_spk_ed_sig);
  pq::ml_dsa_65_sign(pq_identity.private_seed, pq_prekey_body.data(),
                     pq_prekey_body.size(), pq_spk_pq_sig);

  std::vector<uint8_t> signed_body;
  serial::Writer<std::vector<uint8_t>> w(signed_body);
  w.str(kHybridCardContext);
  w.u8(static_cast<uint8_t>(ProtocolSuite::HybridPqxdhV1));
  w.bytes(identity_pk.data(), identity_pk.size());
  w.bytes(pq_identity.public_key.data(), pq_identity.public_key.size());
  w.u32(spk.id); w.bytes(spk.pub.data(), spk.pub.size());
  w.bytes(spk.signature.data(), spk.signature.size());
  w.u32(static_cast<uint32_t>(otpks.size()));
  for (const auto& o : otpks) { w.u32(o.id); w.bytes(o.pub.data(), o.pub.size()); }
  w.u32(pq_spk.id);
  w.bytes(pq_spk.key.public_key.data(), pq_spk.key.public_key.size());
  w.bytes(pq_spk_ed_sig.data(), pq_spk_ed_sig.size());
  w.bytes(pq_spk_pq_sig.data(), pq_spk_pq_sig.size());
  w.u32(static_cast<uint32_t>(pq_otpks.size()));
  for (const auto& p : pq_otpks) {
    w.u32(p.id); w.bytes(p.key.public_key.data(), p.key.public_key.size());
  }

  Signature ed_card_sig{};
  pq::MlDsaSignature pq_card_sig{};
  sign(identity_sk, signed_body.data(), signed_body.size(), ed_card_sig);
  pq::ml_dsa_65_sign(pq_identity.private_seed, signed_body.data(),
                     signed_body.size(), pq_card_sig);
  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> ow(body);
  ow.bytes(kCardMagic.data(), kCardMagic.size());
  ow.u8(kHybridCardVersion);
  ow.blob(signed_body.data(), signed_body.size());
  ow.bytes(ed_card_sig.data(), ed_card_sig.size());
  ow.bytes(pq_card_sig.data(), pq_card_sig.size());
  return wire::encode_block("CARD", body.data(), body.size());
}

ImportedCard import_card(std::string_view base64_card) {
  constexpr std::size_t kMaxCardBytes = 2u * 1024u * 1024u;
  const std::vector<uint8_t> body =
      wire::decode_block("CARD", base64_card, kMaxCardBytes);
  serial::Reader r(body.data(), body.size());

  std::array<uint8_t, 4> magic{};
  r.bytes(magic.data(), magic.size());
  if (magic != kCardMagic) {
    throw Error("not a Ratchet-USB contact card");
  }
  const uint8_t version = r.u8();
  if (version != kCardVersion && version != kHybridCardVersion) {
    throw Error(
        "unsupported contact card version " + std::to_string(version) +
        " (this build issues and accepts version " +
        std::to_string(kHybridCardVersion) +
        "; ask them for a freshly exported card)");
  }

  const std::vector<uint8_t> signed_body = r.blob();
  Signature card_sig{};
  r.bytes(card_sig.data(), card_sig.size());
  pq::MlDsaSignature pq_card_sig{};
  if (version == kHybridCardVersion) {
    r.bytes(pq_card_sig.data(), pq_card_sig.size());
  }
  if (!r.at_end()) {
    throw Error("contact card has trailing data");
  }

  // The identity is the first field inside the body, so it is read out and
  // then used to check the body that carries it. Everything after this point
  // is walking bytes that key has signed.
  serial::Reader br(signed_body.data(), signed_body.size());
  const std::string context = br.str();
  if ((version == kCardVersion && context != kCardContext) ||
      (version == kHybridCardVersion && context != kHybridCardContext)) {
    throw Error("not a Ratchet-USB contact card");
  }

  ImportedCard out;
  if (version == kHybridCardVersion) {
    const uint8_t suite = br.u8();
    if (suite != static_cast<uint8_t>(ProtocolSuite::HybridPqxdhV1)) {
      throw Error("unsupported hybrid protocol suite");
    }
  }
  br.bytes(out.identity_pub.data(), out.identity_pub.size());
  if (version == kHybridCardVersion) {
    br.bytes(out.card.pq_identity_pub.data(), out.card.pq_identity_pub.size());
  }
  if (!verify(out.identity_pub, signed_body.data(), signed_body.size(),
              card_sig)) {
    throw Error(
        "the card's signature does not match its identity key (the card may "
        "be corrupted or forged)");
  }
  if (version == kHybridCardVersion &&
      !pq::ml_dsa_65_verify(out.card.pq_identity_pub, signed_body.data(),
                            signed_body.size(), pq_card_sig)) {
    throw Error("the card's post-quantum signature is invalid");
  }

  out.card.spk_id = br.u32();
  br.bytes(out.card.spk_pub.data(), out.card.spk_pub.size());
  br.bytes(out.card.spk_signature.data(), out.card.spk_signature.size());

  const uint32_t otpk_count = br.u32();
  // A one-time prekey is a u32 id plus a 32-byte public key on the wire; the
  // count is capped by how many of those the rest of the card could hold.
  out.card.one_time_prekeys.reserve(br.bounded_count(otpk_count, 4 + 32));
  for (uint32_t i = 0; i < otpk_count; ++i) {
    store::PeerOtpk o;
    o.id = br.u32();
    br.bytes(o.pub.data(), o.pub.size());
    out.card.one_time_prekeys.push_back(o);
  }

  if (version == kHybridCardVersion) {
    store::PeerPqBundle bundle;
    bundle.signed_prekey.id = br.u32();
    br.bytes(bundle.signed_prekey.pub.data(), bundle.signed_prekey.pub.size());
    br.bytes(bundle.ed_signature.data(), bundle.ed_signature.size());
    br.bytes(bundle.pq_signature.data(), bundle.pq_signature.size());
    const uint32_t pq_count = br.u32();
    bundle.one_time_prekeys.reserve(
        br.bounded_count(pq_count, 4 + pq::kMlKem768PublicKeyBytes));
    for (uint32_t i = 0; i < pq_count; ++i) {
      store::PeerPqPrekey p;
      p.id = br.u32(); br.bytes(p.pub.data(), p.pub.size());
      bundle.one_time_prekeys.push_back(p);
    }
    std::vector<uint8_t> prekey_body;
    serial::Writer<std::vector<uint8_t>> pkw(prekey_body);
    pkw.str(kPqPrekeyContext);
    pkw.u32(bundle.signed_prekey.id);
    pkw.bytes(bundle.signed_prekey.pub.data(), bundle.signed_prekey.pub.size());
    if (!verify(out.identity_pub, prekey_body.data(), prekey_body.size(),
                bundle.ed_signature) ||
        !pq::ml_dsa_65_verify(out.card.pq_identity_pub, prekey_body.data(),
                              prekey_body.size(), bundle.pq_signature)) {
      throw Error("the hybrid signed prekey is invalid");
    }
    out.card.pq_bundle = std::move(bundle);
  }

  if (!br.at_end()) {
    throw Error("contact card has trailing data inside its signed body");
  }

  if (!prekey::verify_signed_prekey_signature(out.identity_pub, out.card.spk_id,
                                              out.card.spk_pub,
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

  if (!prekey::verify_signed_prekey_signature(contact.identity_pub, card.spk_id,
                                              card.spk_pub,
                                              card.spk_signature)) {
    throw Error(
        "the stored card for this contact does not verify against their "
        "identity key; ask them for a freshly exported card and import it "
        "again (`add-contact`)");
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

  // We are the initiator; the contact is the responder.
  derive_shared_secret(my_identity_pk, contact.identity_pub, parts,
                       result.shared_secret);
  if (card.pq_bundle) {
    store::PeerPqBundle& pqb = *card.pq_bundle;
    pq::MlKemSharedSecret static_secret;
    pq::MlKemCiphertext static_ct{};
    pq::ml_kem_768_encapsulate(pqb.signed_prekey.pub, static_ct, static_secret);
    result.pq_spk_id = pqb.signed_prekey.id;
    result.pq_spk_ciphertext = static_ct;
    pq::MlKemSharedSecret one_time_secret;
    pq::MlKemSharedSecret* one_time_ptr = nullptr;
    if (!pqb.one_time_prekeys.empty()) {
      const std::size_t pick = randombytes_uniform(
          static_cast<uint32_t>(pqb.one_time_prekeys.size()));
      const store::PeerPqPrekey picked = pqb.one_time_prekeys[pick];
      pqb.one_time_prekeys.erase(pqb.one_time_prekeys.begin() +
                                 static_cast<std::ptrdiff_t>(pick));
      pq::MlKemCiphertext ct{};
      pq::ml_kem_768_encapsulate(picked.pub, ct, one_time_secret);
      result.pq_otpk_id = picked.id;
      result.pq_otpk_ciphertext = ct;
      one_time_ptr = &one_time_secret;
    }
    SecureBytes<32> hybrid;
    combine_hybrid(my_identity_pk, contact.identity_pub, result.shared_secret,
                   static_secret, one_time_ptr, hybrid);
    result.shared_secret.assign(hybrid);
  }
  result.ephemeral_sk = std::move(eph_sk);
  return result;
}

SecureBytes<32> respond_hybrid(
    const IdentitySigningSecretKey& my_identity_sk,
    const IdentitySigningPublicKey& my_identity_pk,
    const IdentitySigningPublicKey& their_identity_pk,
    const x25519::PublicKey& their_ephemeral_pub,
    const prekey::SignedPrekey& my_spk,
    const prekey::OneTimePrekey* my_otpk,
    const store::PqPrekey& my_pq_spk,
    const pq::MlKemCiphertext& pq_spk_ciphertext,
    const store::PqPrekey* my_pq_otpk,
    const pq::MlKemCiphertext* pq_otpk_ciphertext) {
  SecureBytes<32> classical = respond(my_identity_sk, my_identity_pk,
                                      their_identity_pk, their_ephemeral_pub,
                                      my_spk, my_otpk);
  pq::MlKemSharedSecret pq_static;
  pq::ml_kem_768_decapsulate(my_pq_spk.key.private_seed, pq_spk_ciphertext,
                             pq_static);
  pq::MlKemSharedSecret pq_one_time;
  pq::MlKemSharedSecret* pq_one_time_ptr = nullptr;
  if (my_pq_otpk && pq_otpk_ciphertext) {
    pq::ml_kem_768_decapsulate(my_pq_otpk->key.private_seed,
                               *pq_otpk_ciphertext, pq_one_time);
    pq_one_time_ptr = &pq_one_time;
  } else if (my_pq_otpk || pq_otpk_ciphertext) {
    throw Error("message authentication failed");
  }
  SecureBytes<32> hybrid;
  combine_hybrid(their_identity_pk, my_identity_pk, classical, pq_static,
                 pq_one_time_ptr, hybrid);
  return hybrid;
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

  // Mirror of `initiate`: the peer holding the ephemeral is the initiator, so
  // their identity leads the salt on this side too.
  SecureBytes<32> secret;
  derive_shared_secret(their_identity_pk, my_identity_pk, parts, secret);
  return secret;
}

}  // namespace ratchet::x3dh
