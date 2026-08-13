#include <set>
#include <string>

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

}  // namespace

TEST("a card round-trips through export/import and verifies") {
  const Identity bob = make_identity();
  const prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);
  const std::vector<prekey::OneTimePrekey> otpks =
      prekey::generate_one_time_prekeys(1, 3);

  const std::string card_text = x3dh::export_card(bob.pk, spk, otpks);
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

TEST("import_card rejects a forged signed prekey") {
  const Identity bob = make_identity();
  prekey::SignedPrekey spk = prekey::generate_signed_prekey(bob.sk, 1);

  // Swap in a prekey that was never actually signed by Bob's key.
  const Identity mallory = make_identity();
  const prekey::SignedPrekey forged_spk =
      prekey::generate_signed_prekey(mallory.sk, 1);
  spk.pub = forged_spk.pub;  // the pubkey Mallory controls...
  // ...but the signature still claims to be Bob's, over the old pubkey.

  const std::string card_text = x3dh::export_card(bob.pk, spk, {});
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

  const std::string card_text = x3dh::export_card(bob.pk, bob_spk, bob_otpks);
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact;
  contact.identity_pub = bob.pk;
  contact.card = imported.card;

  const x3dh::InitiatorResult init_result =
      x3dh::initiate(alice.sk, alice.pk, contact);
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
  const std::string card_text = x3dh::export_card(bob.pk, bob_spk, bob_otpks);
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  std::set<uint32_t> picked;
  for (int i = 0; i < 40; ++i) {
    const Identity sender = make_identity();
    store::Contact contact;
    contact.identity_pub = bob.pk;
    contact.card = imported.card;

    const x3dh::InitiatorResult r =
        x3dh::initiate(sender.sk, sender.pk, contact);
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
  const std::string card_text = x3dh::export_card(bob.pk, bob_spk, {});
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact;
  contact.identity_pub = bob.pk;
  contact.card = imported.card;

  const x3dh::InitiatorResult init_result =
      x3dh::initiate(alice.sk, alice.pk, contact);
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
  const std::string card_text = x3dh::export_card(bob.pk, bob_spk, {});
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact_for_alice;
  contact_for_alice.identity_pub = bob.pk;
  contact_for_alice.card = imported.card;
  const x3dh::InitiatorResult alice_result =
      x3dh::initiate(alice.sk, alice.pk, contact_for_alice);

  store::Contact contact_for_mallory;
  contact_for_mallory.identity_pub = bob.pk;
  contact_for_mallory.card = imported.card;
  const x3dh::InitiatorResult mallory_result =
      x3dh::initiate(mallory.sk, mallory.pk, contact_for_mallory);

  CHECK(!alice_result.shared_secret.equals(mallory_result.shared_secret));

  // And Bob responding to "Alice" using Mallory's ephemeral/identity does not
  // recover Alice's secret -- the handshake is bound to which identity Bob
  // thinks he is talking to.
  const SecureBytes<32> bob_thinks_alice = x3dh::respond(
      bob.sk, bob.pk, alice.pk, mallory_result.ephemeral_pk, bob_spk, nullptr);
  CHECK(!bob_thinks_alice.equals(alice_result.shared_secret));
}
