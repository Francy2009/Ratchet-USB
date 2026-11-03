// Group messages: one content key, wrapped once per member through the 1:1
// sessions those members already have with the sender. The tests use real
// cards and real sessions, because the interesting failures are the ones that
// only show up when a recipient tries a wrapper addressed to somebody else.

#include <array>
#include <string>
#include <vector>

#include "ratchet/app.hpp"
#include "ratchet/group.hpp"
#include "ratchet/session.hpp"
#include "ratchet/wire.hpp"
#include "ratchet/x3dh.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

struct Party {
  IdentitySigningSecretKey sk;
  IdentitySigningPublicKey pk{};
  store::VaultStore vault;
};

Party make_party(std::size_t otpk_count) {
  Party p;
  bip39::Entropy entropy;
  bip39::generate_entropy(entropy);
  derive_master_seed(entropy, p.vault.seed);
  derive_identity(p.vault.seed, p.sk, p.pk);

  p.vault.signed_prekeys.push_back(prekey::generate_signed_prekey(p.sk, 1));
  p.vault.next_spk_id = 2;
  p.vault.one_time_prekeys = prekey::generate_one_time_prekeys(1, otpk_count);
  p.vault.next_otpk_id = static_cast<uint32_t>(1 + otpk_count);
  app::replenish_pq_prekeys(p.vault, otpk_count);
  return p;
}

void introduce(const Party& from, Party& into, const std::string& alias) {
  const pq::MlDsaKeyPair pq_identity = derive_pq_identity(from.vault.seed);
  const std::string card_text = x3dh::export_hybrid_card(
      from.sk, from.pk, pq_identity, from.vault.signed_prekeys.back(),
      from.vault.one_time_prekeys, from.vault.pq_signed_prekeys.back(),
      from.vault.pq_one_time_prekeys);
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact;
  contact.alias = alias;
  contact.identity_pub = imported.identity_pub;
  contact.verified = true;
  contact.minimum_suite = ProtocolSuite::HybridPqxdhV1;
  contact.card = imported.card;
  into.vault.contacts.push_back(std::move(contact));
}

}  // namespace

TEST("a group message reaches every member with the same content key") {
  Party alice = make_party(3);
  Party bob = make_party(3);
  Party carol = make_party(3);
  introduce(bob, alice, "bob");
  introduce(carol, alice, "carol");
  introduce(alice, bob, "alice");
  introduce(alice, carol, "alice");

  const std::string block =
      group::send(alice.vault, alice.sk, alice.pk, {0, 1}, "hello group");
  CHECK(group::looks_like_group(block));

  const group::ReceiveResult to_bob =
      group::receive(bob.vault, bob.sk, bob.pk, block);
  CHECK_EQ(to_bob.plaintext, std::string("hello group"));
  CHECK_EQ(to_bob.alias, std::string("alice"));

  const group::ReceiveResult to_carol =
      group::receive(carol.vault, carol.sk, carol.pk, block);
  CHECK_EQ(to_carol.plaintext, std::string("hello group"));
  CHECK_EQ(to_carol.alias, std::string("alice"));
  CHECK(to_bob.group_id == to_carol.group_id);
}

TEST("group-send refuses fewer than two recipients and duplicates") {
  Party alice = make_party(2);
  Party bob = make_party(2);
  introduce(bob, alice, "bob");

  CHECK_THROWS(group::send(alice.vault, alice.sk, alice.pk, {}, "nobody"));
  CHECK_THROWS(group::send(alice.vault, alice.sk, alice.pk, {0}, "one"));
  CHECK_THROWS(
      group::send(alice.vault, alice.sk, alice.pk, {0, 0}, "duplicate"));
}

TEST("group-send refuses an unverified recipient") {
  Party alice = make_party(2);
  Party bob = make_party(2);
  Party carol = make_party(2);
  introduce(bob, alice, "bob");
  introduce(carol, alice, "carol");
  alice.vault.contacts[1].verified = false;

  CHECK_THROWS(
      group::send(alice.vault, alice.sk, alice.pk, {0, 1}, "not yet"));
}

TEST("group-receive refuses a message with no wrapper for this vault") {
  Party alice = make_party(3);
  Party bob = make_party(3);
  Party carol = make_party(3);
  Party dave = make_party(3);
  introduce(bob, alice, "bob");
  introduce(carol, alice, "carol");
  introduce(dave, alice, "dave");
  introduce(alice, bob, "alice");
  introduce(alice, carol, "alice");
  introduce(alice, dave, "alice");

  const std::string block =
      group::send(alice.vault, alice.sk, alice.pk, {0, 1}, "not for dave");
  CHECK_THROWS(group::receive(dave.vault, dave.sk, dave.pk, block));
}

TEST("group-receive rejects a tampered sender signature") {
  Party alice = make_party(3);
  Party bob = make_party(3);
  Party carol = make_party(3);
  introduce(bob, alice, "bob");
  introduce(carol, alice, "carol");
  introduce(alice, bob, "alice");
  introduce(alice, carol, "alice");

  const std::string block =
      group::send(alice.vault, alice.sk, alice.pk, {0, 1}, "tamper me");
  std::vector<uint8_t> body = wire::decode_block("GROUP", block);
  CHECK(!body.empty());
  body.back() ^= 0x01;  // last byte of the 64-byte Ed25519 signature
  const std::string forged = wire::encode_block("GROUP", body.data(), body.size());
  CHECK_THROWS(group::receive(bob.vault, bob.sk, bob.pk, forged));
}

TEST("group-receive rejects re-encrypted content under the shared key") {
  // The threat this pins down: every member learns the content key, so a
  // member could re-encrypt the body. The sender signature is what stops that
  // from being attributed to the sender; changing the ciphertext while leaving
  // the signature alone must fail before any wrapper is consumed.
  Party alice = make_party(3);
  Party bob = make_party(3);
  Party carol = make_party(3);
  introduce(bob, alice, "bob");
  introduce(carol, alice, "carol");
  introduce(alice, bob, "alice");
  introduce(alice, carol, "alice");

  const std::string block =
      group::send(alice.vault, alice.sk, alice.pk, {0, 1}, "original");
  std::vector<uint8_t> body = wire::decode_block("GROUP", block);
  CHECK(body.size() > 64);
  body[body.size() - 65] ^= 0x01;  // last ciphertext byte, signature untouched
  const std::string forged = wire::encode_block("GROUP", body.data(), body.size());
  CHECK_THROWS(group::receive(bob.vault, bob.sk, bob.pk, forged));

  // The rejected block must not have consumed Bob's wrapper: the genuine block
  // still has to decrypt afterwards.
  CHECK_EQ(group::receive(bob.vault, bob.sk, bob.pk, block).plaintext,
           std::string("original"));
}
