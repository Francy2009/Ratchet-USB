#include <cstring>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "ratchet/wire.hpp"
#include "ratchet/serial.hpp"
#include "ratchet/x3dh.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

struct Identity {
  IdentitySigningSecretKey sk;
  IdentitySigningPublicKey pk{};
};

Identity make_identity() {
  bip39::Entropy entropy;
  bip39::generate_entropy(entropy);
  MasterSeed seed;
  derive_master_seed(entropy, seed);
  Identity id;
  derive_identity(seed, id.sk, id.pk);
  return id;
}

void check_xwing_agreement(bool with_classical_otpk, bool with_pq_otpk) {
  const Identity alice = make_identity();
  const Identity bob = make_identity();
  pq::MlDsaPrivateSeed pq_seed;
  randombytes_buf(pq_seed.data(), pq_seed.size());
  const pq::MlDsaKeyPair pq_identity = pq::ml_dsa_65_from_seed(pq_seed);
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::vector<prekey::OneTimePrekey> otpks =
      with_classical_otpk ? prekey::generate_one_time_prekeys(1, 1)
                          : std::vector<prekey::OneTimePrekey>{};
  store::PqPrekey pq_spk;
  pq_spk.id = 20;
  pq_spk.key = pq::generate_ml_kem_768();
  std::vector<store::PqPrekey> pq_otpks;
  if (with_pq_otpk) {
    store::PqPrekey one_time;
    one_time.id = 21;
    one_time.key = pq::generate_ml_kem_768();
    pq_otpks.push_back(std::move(one_time));
  }
  const std::string card = x3dh::export_hybrid_card(
      bob.sk, bob.pk, pq_identity, spk, otpks, pq_spk, pq_otpks);
  store::Contact contact;
  contact.identity_pub = bob.pk;
  contact.card = x3dh::import_card(card).card;

  const x3dh::InitiatorResult init =
      x3dh::initiate(alice.sk, alice.pk, contact, true);
  prekey::OneTimePrekey otpk_copy;
  const prekey::OneTimePrekey* otpk_ptr = nullptr;
  if (init.otpk_id) {
    for (const prekey::OneTimePrekey& one_time : otpks) {
      if (one_time.id == *init.otpk_id) {
        otpk_copy.id = one_time.id;
        otpk_copy.pub = one_time.pub;
        otpk_copy.sk.assign(one_time.sk.data(), one_time.sk.size());
        otpk_ptr = &otpk_copy;
      }
    }
    CHECK(otpk_ptr != nullptr);
  } else {
    CHECK(!with_classical_otpk);
  }
  const store::PqPrekey* pq_otpk_ptr = nullptr;
  if (init.pq_otpk_id) {
    for (const store::PqPrekey& one_time : pq_otpks) {
      if (one_time.id == *init.pq_otpk_id) pq_otpk_ptr = &one_time;
    }
    CHECK(pq_otpk_ptr != nullptr);
  } else {
    CHECK(!with_pq_otpk);
  }
  CHECK(init.pq_spk_ciphertext.has_value());
  const pq::MlKemCiphertext* pq_otpk_ciphertext =
      init.pq_otpk_ciphertext ? &*init.pq_otpk_ciphertext : nullptr;
  const SecureBytes<32> agreed = x3dh::respond_hybrid(
      bob.sk, bob.pk, alice.pk, init.ephemeral_pk, spk, otpk_ptr, pq_spk,
      *init.pq_spk_ciphertext, pq_otpk_ptr, pq_otpk_ciphertext, true);
  CHECK(init.shared_secret.equals(agreed));
  const SecureBytes<32> historical = x3dh::respond_hybrid(
      bob.sk, bob.pk, alice.pk, init.ephemeral_pk, spk, otpk_ptr, pq_spk,
      *init.pq_spk_ciphertext, pq_otpk_ptr, pq_otpk_ciphertext, false);
  CHECK(!init.shared_secret.equals(historical));
}

}  // namespace

TEST("a card round-trips through export/import and verifies") {
  const Identity bob = make_identity();
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::vector<prekey::OneTimePrekey> otpks =
      prekey::generate_one_time_prekeys(1, 3);

  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, spk, otpks);
  CHECK(card_text.find("-----BEGIN RATCHET CARD-----") != std::string::npos);

  const x3dh::ImportedCard imported = x3dh::import_card(card_text);
  CHECK(imported.identity_pub == bob.pk);
  CHECK_EQ(imported.card.spk_id, spk.id);
  CHECK(imported.card.spk_pub == spk.pub);
  CHECK(imported.card.spk_signature == spk.signature);
  CHECK_EQ(imported.card.one_time_prekeys.size(), otpks.size());
  for (size_t i = 0; i < otpks.size(); ++i) {
    CHECK_EQ(imported.card.one_time_prekeys[i].id, otpks[i].id);
    CHECK(imported.card.one_time_prekeys[i].pub == otpks[i].pub);
  }
}

TEST("a hybrid card requires both identity signatures and authenticates all fields") {
  const Identity bob = make_identity();
  pq::MlDsaPrivateSeed pq_seed;
  randombytes_buf(pq_seed.data(), pq_seed.size());
  const pq::MlDsaKeyPair pq_identity = pq::ml_dsa_65_from_seed(pq_seed);
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 7);
  const std::vector<prekey::OneTimePrekey> otpks =
      prekey::generate_one_time_prekeys(10, 2);
  store::PqPrekey pq_spk;
  pq_spk.id = 20;
  pq_spk.key = pq::generate_ml_kem_768();
  pq_spk.created_at = 1700000000;
  std::vector<store::PqPrekey> pq_otpks;
  store::PqPrekey pq_otpk;
  pq_otpk.id = 21;
  pq_otpk.key = pq::generate_ml_kem_768();
  pq_otpk.created_at = 1700000001;
  pq_otpks.push_back(std::move(pq_otpk));

  const std::string encoded = x3dh::export_hybrid_card(
      bob.sk, bob.pk, pq_identity, spk, otpks, pq_spk, pq_otpks);
  const std::vector<uint8_t> raw_card = wire::decode_block("CARD", encoded);
  serial::Reader card_reader(raw_card.data(), raw_card.size());
  uint8_t magic[4]{};
  card_reader.bytes(magic, sizeof magic);
  CHECK_EQ(card_reader.u8(), uint8_t(4));
  const std::vector<uint8_t> signed_body = card_reader.blob();
  serial::Reader body_reader(signed_body.data(), signed_body.size());
  CHECK_EQ(body_reader.str(),
           std::string("Ratchet-USB/v4/hybrid-contact-card"));
  CHECK_EQ(body_reader.u8(),
           static_cast<uint8_t>(ProtocolSuite::XWingTripleRatchetV1));

  // Even a correctly signed card must not claim a suite this build does not
  // implement.
  std::vector<uint8_t> unsupported_body = signed_body;
  constexpr std::string_view context = "Ratchet-USB/v4/hybrid-contact-card";
  unsupported_body[4 + context.size()] = 5;
  Signature ed_signature{};
  pq::MlDsaSignature pq_signature{};
  sign(bob.sk, unsupported_body.data(), unsupported_body.size(), ed_signature);
  pq::ml_dsa_65_sign(pq_identity.private_seed, unsupported_body.data(),
                     unsupported_body.size(), pq_signature);
  std::vector<uint8_t> unsupported_card;
  serial::Writer<std::vector<uint8_t>> writer(unsupported_card);
  writer.bytes(magic, sizeof magic);
  writer.u8(4);
  writer.blob(unsupported_body.data(), unsupported_body.size());
  writer.bytes(ed_signature.data(), ed_signature.size());
  writer.bytes(pq_signature.data(), pq_signature.size());
  CHECK_THROWS(x3dh::import_card(wire::encode_block(
      "CARD", unsupported_card.data(), unsupported_card.size())));

  // Cards issued before SPQR integration advertised the hybrid suite.
  unsupported_body[4 + context.size()] =
      static_cast<uint8_t>(ProtocolSuite::HybridPqxdhV1);
  sign(bob.sk, unsupported_body.data(), unsupported_body.size(), ed_signature);
  pq::ml_dsa_65_sign(pq_identity.private_seed, unsupported_body.data(),
                     unsupported_body.size(), pq_signature);
  unsupported_card.clear();
  serial::Writer<std::vector<uint8_t>> legacy_writer(unsupported_card);
  legacy_writer.bytes(magic, sizeof magic);
  legacy_writer.u8(4);
  legacy_writer.blob(unsupported_body.data(), unsupported_body.size());
  legacy_writer.bytes(ed_signature.data(), ed_signature.size());
  legacy_writer.bytes(pq_signature.data(), pq_signature.size());
  CHECK(x3dh::import_card(wire::encode_block(
      "CARD", unsupported_card.data(), unsupported_card.size()))
            .card.maximum_suite == ProtocolSuite::HybridPqxdhV1);

  // Suite 3 cards stay importable and keep the previous combiner.
  unsupported_body[4 + context.size()] =
      static_cast<uint8_t>(ProtocolSuite::TripleRatchetV1);
  sign(bob.sk, unsupported_body.data(), unsupported_body.size(), ed_signature);
  pq::ml_dsa_65_sign(pq_identity.private_seed, unsupported_body.data(),
                     unsupported_body.size(), pq_signature);
  unsupported_card.clear();
  serial::Writer<std::vector<uint8_t>> suite3_writer(unsupported_card);
  suite3_writer.bytes(magic, sizeof magic);
  suite3_writer.u8(4);
  suite3_writer.blob(unsupported_body.data(), unsupported_body.size());
  suite3_writer.bytes(ed_signature.data(), ed_signature.size());
  suite3_writer.bytes(pq_signature.data(), pq_signature.size());
  CHECK(x3dh::import_card(wire::encode_block(
      "CARD", unsupported_card.data(), unsupported_card.size()))
            .card.maximum_suite == ProtocolSuite::TripleRatchetV1);

  const x3dh::ImportedCard imported = x3dh::import_card(encoded);
  CHECK(imported.identity_pub == bob.pk);
  CHECK(imported.card.pq_identity_pub == pq_identity.public_key);
  CHECK(imported.card.maximum_suite == ProtocolSuite::XWingTripleRatchetV1);
  CHECK(imported.card.pq_bundle.has_value());
  CHECK_EQ(imported.card.pq_bundle->signed_prekey.id, pq_spk.id);
  CHECK_EQ(imported.card.pq_bundle->one_time_prekeys.size(), std::size_t(1));

  std::vector<uint8_t> raw = wire::decode_block("CARD", encoded);
  for (const std::size_t offset :
       {std::size_t(0), raw.size() / 5, raw.size() / 2, raw.size() - 1}) {
    std::vector<uint8_t> tampered = raw;
    tampered[offset] ^= 1;
    CHECK_THROWS(x3dh::import_card(
        wire::encode_block("CARD", tampered.data(), tampered.size())));
  }
}

TEST("X-Wing combiner matches the published SHA3-256 concatenation") {
  pq::MlKemSharedSecret ss_m;
  SecureBytes<32> ss_x;
  x25519::PublicKey ct_x{};
  x25519::PublicKey pk_x{};
  for (std::size_t i = 0; i < 32; ++i) {
    ss_m[i] = 0x01;
    ss_x[i] = 0x02;
    ct_x[i] = 0x03;
    pk_x[i] = 0x04;
  }
  SecureBytes<32> out;
  x3dh::detail::xwing_combine(ss_m, ss_x, ct_x, pk_x, out);
  static constexpr uint8_t kExpect[] = {
      0x5c, 0x6b, 0xfa, 0xf8, 0xc3, 0xec, 0x48, 0xab, 0x3c, 0xee, 0x7c,
      0x12, 0x12, 0x9b, 0x39, 0x91, 0x3b, 0x8a, 0x7f, 0xa1, 0x23, 0x41,
      0x15, 0xda, 0x7e, 0x1c, 0x55, 0x60, 0x8a, 0xd1, 0x9f, 0xb6};
  CHECK(sodium_memcmp(out.data(), kExpect, sizeof kExpect) == 0);
}

TEST("suite 4 handshake agrees and does not match the historical combiner") {
  CHECK(uses_xwing_combiner(ProtocolSuite::XWingTripleRatchetV1));
  CHECK(uses_triple_ratchet(ProtocolSuite::XWingTripleRatchetV1));
  CHECK(!uses_xwing_combiner(ProtocolSuite::TripleRatchetV1));
  CHECK(uses_triple_ratchet(ProtocolSuite::TripleRatchetV1));
  CHECK(!uses_xwing_combiner(ProtocolSuite::HybridPqxdhV1));
  check_xwing_agreement(true, true);
  check_xwing_agreement(true, false);
  check_xwing_agreement(false, false);
  check_xwing_agreement(false, true);
}

TEST("X-Wing initiate without an ML-KEM bundle consumes nothing") {
  const Identity alice = make_identity();
  const Identity bob = make_identity();
  pq::MlDsaPrivateSeed pq_seed;
  randombytes_buf(pq_seed.data(), pq_seed.size());
  const pq::MlDsaKeyPair pq_identity = pq::ml_dsa_65_from_seed(pq_seed);
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::vector<prekey::OneTimePrekey> otpks =
      prekey::generate_one_time_prekeys(1, 1);
  store::PqPrekey pq_spk;
  pq_spk.id = 20;
  pq_spk.key = pq::generate_ml_kem_768();
  const std::string card = x3dh::export_hybrid_card(
      bob.sk, bob.pk, pq_identity, spk, otpks, pq_spk, {});
  store::Contact contact;
  contact.identity_pub = bob.pk;
  contact.card = x3dh::import_card(card).card;
  contact.card->pq_bundle.reset();
  const std::size_t before = contact.card->one_time_prekeys.size();
  CHECK_THROWS(x3dh::initiate(alice.sk, alice.pk, contact, true));
  CHECK_EQ(contact.card->one_time_prekeys.size(), before);
}

TEST("import_card rejects a forged signed prekey") {
  const Identity bob = make_identity();
  prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);

  // Swap in a prekey that was never actually signed by Bob's key.
  const Identity mallory = make_identity();
  const prekey::SignedPrekey forged_spk =
      prekey::generate_signed_prekey(mallory.sk, 1);
  spk.pub = forged_spk.pub;  // the pubkey Mallory controls...
  // ...but the signature still claims to be Bob's, over the old pubkey.

  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, spk, {});
  CHECK_THROWS(x3dh::import_card(card_text));
}

TEST("import_card rejects a non-card blob and the wrong label") {
  CHECK_THROWS(x3dh::import_card("not a card at all"));
  CHECK_THROWS(x3dh::import_card(
      "-----BEGIN RATCHET MESSAGE-----\nAAAA\n-----END RATCHET MESSAGE-----\n"));
}

TEST("initiate/respond agree on the shared secret, with a one-time prekey") {
  const Identity alice = make_identity();
  const Identity bob = make_identity();

  const prekey::SignedPrekey bob_spk = prekey::generate_signed_prekey(bob.sk, 1);
  std::vector<prekey::OneTimePrekey> bob_otpks =
      prekey::generate_one_time_prekeys(1, 2);

  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, bob_spk, bob_otpks);
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact;
  contact.identity_pub = bob.pk;
  contact.card = imported.card;

  const x3dh::InitiatorResult init_result =
      x3dh::initiate(alice.sk, alice.pk, contact, false);
  CHECK(init_result.otpk_id.has_value());
  // The consumed prekey must be gone from the contact's stored card.
  CHECK_EQ(contact.card->one_time_prekeys.size(), bob_otpks.size() - 1);

  // Which prekey gets used is chosen at random, so the responder looks it up
  // by the id the initiator reported rather than assuming a position.
  const prekey::OneTimePrekey bob_otpk_copy_for_responder = [&] {
    prekey::OneTimePrekey copy;
    for (const prekey::OneTimePrekey& o : bob_otpks) {
      if (o.id == *init_result.otpk_id) {
        copy.id = o.id;
        copy.pub = o.pub;
        copy.sk.assign(o.sk.data(), o.sk.size());
        break;
      }
    }
    return copy;
  }();
  CHECK_EQ(bob_otpk_copy_for_responder.id, *init_result.otpk_id);

  const SecureBytes<32> responder_secret =
      x3dh::respond(bob.sk, bob.pk, alice.pk, init_result.ephemeral_pk, bob_spk,
                   &bob_otpk_copy_for_responder);

  CHECK(init_result.shared_secret.equals(responder_secret));
}

TEST("separate contacts holding the same card do not all pick the same prekey") {
  const Identity bob = make_identity();
  const prekey::SignedPrekey bob_spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::vector<prekey::OneTimePrekey> bob_otpks =
      prekey::generate_one_time_prekeys(1, 10);

  // One card, exported once and handed to everybody -- the case that used to
  // make every contact collide on the same prekey.
  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, bob_spk, bob_otpks);
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  std::set<uint32_t> picked;
  for (int i = 0; i < 40; ++i) {
    const Identity sender = make_identity();
    store::Contact contact;
    contact.identity_pub = bob.pk;
    contact.card = imported.card;

    const x3dh::InitiatorResult r =
        x3dh::initiate(sender.sk, sender.pk, contact, false);
    CHECK(r.otpk_id.has_value());
    // Whatever is picked has to be one Bob actually published, and exactly
    // one has to disappear from this contact's copy of the card.
    CHECK_EQ(contact.card->one_time_prekeys.size(), bob_otpks.size() - 1);
    bool known = false;
    for (const prekey::OneTimePrekey& o : bob_otpks) {
      if (o.id == *r.otpk_id) {
        known = true;
        break;
      }
    }
    CHECK(known);
    picked.insert(*r.otpk_id);
  }

  // With 10 prekeys and 40 draws, landing on the same one every time has
  // probability 10^-39, so this is a fixed choice rather than a flaky test.
  CHECK(picked.size() > 1);
}

TEST("initiate/respond agree without a one-time prekey (exhausted pool)") {
  const Identity alice = make_identity();
  const Identity bob = make_identity();

  const prekey::SignedPrekey bob_spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, bob_spk, {});
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact;
  contact.identity_pub = bob.pk;
  contact.card = imported.card;

  const x3dh::InitiatorResult init_result =
      x3dh::initiate(alice.sk, alice.pk, contact, false);
  CHECK(!init_result.otpk_id.has_value());

  const SecureBytes<32> responder_secret =
      x3dh::respond(bob.sk, bob.pk, alice.pk, init_result.ephemeral_pk, bob_spk,
                   /*my_otpk=*/nullptr);

  CHECK(init_result.shared_secret.equals(responder_secret));
}

TEST("a different initiator identity yields a different shared secret") {
  const Identity alice = make_identity();
  const Identity mallory = make_identity();
  const Identity bob = make_identity();

  const prekey::SignedPrekey bob_spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, bob_spk, {});
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact_for_alice;
  contact_for_alice.identity_pub = bob.pk;
  contact_for_alice.card = imported.card;
  const x3dh::InitiatorResult alice_result =
      x3dh::initiate(alice.sk, alice.pk, contact_for_alice, false);

  store::Contact contact_for_mallory;
  contact_for_mallory.identity_pub = bob.pk;
  contact_for_mallory.card = imported.card;
  const x3dh::InitiatorResult mallory_result =
      x3dh::initiate(mallory.sk, mallory.pk, contact_for_mallory, false);

  CHECK(!alice_result.shared_secret.equals(mallory_result.shared_secret));

  // And Bob responding to "Alice" using Mallory's ephemeral/identity does not
  // recover Alice's secret -- the handshake is bound to which identity Bob
  // thinks he is talking to.
  const SecureBytes<32> bob_thinks_alice = x3dh::respond(
      bob.sk, bob.pk, alice.pk, mallory_result.ephemeral_pk, bob_spk, nullptr);
  CHECK(!bob_thinks_alice.equals(alice_result.shared_secret));
}

// --- Identity binding in the combine step -----------------------------------

TEST("negating an identity key changes the shared secret it produces") {
  // The regression test for the birational-conversion misbinding.
  //
  // Ed25519 encodes a point as its y coordinate plus the sign of x in the top
  // bit of byte 31. The map to Montgomery form is u = (1+y)/(1-y), which never
  // looks at x -- so a key and its negation, which differ only in that one
  // bit, convert to the *same* X25519 key and yield identical Diffie-Hellman
  // output at every one of DH1..DH4.
  //
  // Before the identity keys entered the derivation, that made two distinct
  // identity keys -- two distinct fingerprints, the thing a human reads out
  // over the phone to check who they are talking to -- completely
  // interchangeable inside X3DH. What the protocol authenticated was the y
  // coordinate; what the user verified was 32 bytes containing y plus a bit
  // that went nowhere.
  const Identity alice = make_identity();
  const Identity bob = make_identity();
  const prekey::SignedPrekey bob_spk = prekey::generate_signed_prekey(bob.sk, 1);

  x25519::SecretKey eph_sk;
  x25519::PublicKey eph_pk{};
  x25519::generate_keypair(eph_sk, eph_pk);

  IdentitySigningPublicKey alice_negated = alice.pk;
  alice_negated[31] ^= 0x80;

  // The premise: the two really do convert to the same DH key. If libsodium
  // ever started rejecting one of them this test would be proving nothing, so
  // it is asserted rather than assumed.
  IdentityDHPublicKey dh_from_alice{};
  IdentityDHPublicKey dh_from_negated{};
  identity_dh_public(alice.pk, dh_from_alice);
  identity_dh_public(alice_negated, dh_from_negated);
  CHECK(dh_from_alice == dh_from_negated);
  CHECK(!(alice.pk == alice_negated));

  const SecureBytes<32> under_alice =
      x3dh::respond(bob.sk, bob.pk, alice.pk, eph_pk, bob_spk, nullptr);
  const SecureBytes<32> under_negated =
      x3dh::respond(bob.sk, bob.pk, alice_negated, eph_pk, bob_spk, nullptr);

  // Identical DH inputs, different identity encodings, different secret.
  CHECK(!under_alice.equals(under_negated));
}

TEST("the combine step binds both identities and their order") {
  const Identity a = make_identity();
  const Identity b = make_identity();

  // One fixed set of DH outputs, reused across every derivation below, so the
  // only thing that varies is what the salt says about the identities.
  SecureBytes<32> dh1;
  SecureBytes<32> dh2;
  SecureBytes<32> dh3;
  for (std::size_t i = 0; i < 32; ++i) {
    dh1[i] = static_cast<uint8_t>(i);
    dh2[i] = static_cast<uint8_t>(0x40 + i);
    dh3[i] = static_cast<uint8_t>(0x80 + i);
  }
  const std::vector<const SecureBytes<32>*> three = {&dh1, &dh2, &dh3};

  SecureBytes<32> ab;
  SecureBytes<32> ab_again;
  SecureBytes<32> ba;
  x3dh::detail::derive_shared_secret(a.pk, b.pk, three, ab);
  x3dh::detail::derive_shared_secret(a.pk, b.pk, three, ab_again);
  x3dh::detail::derive_shared_secret(b.pk, a.pk, three, ba);

  // Deterministic...
  CHECK(ab.equals(ab_again));
  // ...but not symmetric: initiator and responder are distinguishable, so the
  // two sides cannot silently disagree about who opened the conversation.
  CHECK(!ab.equals(ba));

  // A third identity in either slot is a different derivation again.
  const Identity c = make_identity();
  SecureBytes<32> cb;
  SecureBytes<32> ac;
  x3dh::detail::derive_shared_secret(c.pk, b.pk, three, cb);
  x3dh::detail::derive_shared_secret(a.pk, c.pk, three, ac);
  CHECK(!ab.equals(cb));
  CHECK(!ab.equals(ac));

  // And the DH count leads the salt, so a 3-DH transcript cannot collide with
  // a 4-DH one built from the same identities.
  SecureBytes<32> dh4;
  const std::vector<const SecureBytes<32>*> four = {&dh1, &dh2, &dh3, &dh4};
  SecureBytes<32> ab_four;
  x3dh::detail::derive_shared_secret(a.pk, b.pk, four, ab_four);
  CHECK(!ab.equals(ab_four));
}

// --- Card integrity ---------------------------------------------------------

namespace {

// Re-encodes a CARD block after handing its raw body to `mutate`, so a test
// can tamper with a field and still produce something import_card will parse.
std::string tamper_card(const std::string& card_text,
                        const std::function<void(std::vector<uint8_t>&)>& mutate) {
  std::vector<uint8_t> body = wire::decode_block("CARD", card_text);
  mutate(body);
  return wire::encode_block("CARD", body.data(), body.size());
}

// Where a field sits inside the re-encoded card body:
//   magic(4) version(1) blob_len(4) [ signed body ... ] card_signature(64)
// and inside the signed body:
//   ctx_len(4) ctx(26) identity(32) spk_id(4) spk_pub(32) spk_sig(64)
//   otpk_count(4) [ otpk_id(4) otpk_pub(32) ]...
constexpr std::size_t kBodyStart = 4 + 1 + 4;
constexpr std::size_t kCtxLen = 26;  // "Ratchet-USB/v2/contact-card"
constexpr std::size_t kSpkIdOffset = kBodyStart + 4 + kCtxLen + 32;
constexpr std::size_t kOtpkCountOffset = kSpkIdOffset + 4 + 32 + 64;
constexpr std::size_t kFirstOtpkOffset = kOtpkCountOffset + 4;

}  // namespace

TEST("import_card rejects a card whose one-time prekeys were swapped out") {
  // The X3DH spec signs only the signed prekey, because there the bundle comes
  // from a server over an authenticated channel. Here the card is pasted over
  // the same untrusted channel as everything else, so an unsigned one-time
  // prekey is one an attacker in the middle gets to choose.
  const Identity bob = make_identity();
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::vector<prekey::OneTimePrekey> otpks =
      prekey::generate_one_time_prekeys(1, 3);

  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, spk, otpks);
  CHECK(x3dh::import_card(card_text).card.one_time_prekeys.size() == 3);

  // Substitute a public key Mallory holds the private half of, leaving the id
  // alone so the recipient still believes it is Bob's prekey number one.
  const std::vector<prekey::OneTimePrekey> mallorys =
      prekey::generate_one_time_prekeys(1, 1);
  const std::string forged = tamper_card(card_text, [&](std::vector<uint8_t>& b) {
    std::memcpy(b.data() + kFirstOtpkOffset + 4, mallorys[0].pub.data(), 32);
  });
  CHECK_THROWS(x3dh::import_card(forged));
}

TEST("import_card rejects a card whose signed prekey id was rewritten") {
  // spk_id used to sit outside the signature, so a genuine card could have it
  // rewritten in transit: the signature still verified, and the peer then
  // opened a handshake against an id the recipient had never issued.
  const Identity bob = make_identity();
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 7);
  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, spk, {});
  CHECK_EQ(x3dh::import_card(card_text).card.spk_id, 7u);

  const std::string forged = tamper_card(card_text, [](std::vector<uint8_t>& b) {
    b[kSpkIdOffset] ^= 0xFF;
  });
  CHECK_THROWS(x3dh::import_card(forged));
}

TEST("import_card rejects a card with one-time prekeys appended or removed") {
  const Identity bob = make_identity();
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::vector<prekey::OneTimePrekey> otpks =
      prekey::generate_one_time_prekeys(1, 2);
  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, spk, otpks);

  // Truncating the pool to zero would force every future handshake down to the
  // weaker 3-DH path without either side noticing.
  const std::string emptied = tamper_card(card_text, [](std::vector<uint8_t>& b) {
    b[kOtpkCountOffset] = 0;
    b[kOtpkCountOffset + 1] = 0;
    b[kOtpkCountOffset + 2] = 0;
    b[kOtpkCountOffset + 3] = 0;
  });
  CHECK_THROWS(x3dh::import_card(emptied));
}

TEST("import_card rejects a v1 card rather than accepting it unsigned") {
  const Identity bob = make_identity();
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::string card_text = x3dh::export_card(bob.sk, bob.pk, spk, {});

  const std::string old_version =
      tamper_card(card_text, [](std::vector<uint8_t>& b) { b[4] = 1; });
  CHECK_THROWS(x3dh::import_card(old_version));
}

TEST("a signed prekey signature does not verify under a different id") {
  // Domain separation, from the other direction: the id is inside the signed
  // message, so the same key and signature stop verifying when the id moves.
  const Identity bob = make_identity();
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 42);

  CHECK(prekey::verify_signed_prekey_signature(bob.pk, 42, spk.pub,
                                               spk.signature));
  CHECK(!prekey::verify_signed_prekey_signature(bob.pk, 43, spk.pub,
                                                spk.signature));
}
