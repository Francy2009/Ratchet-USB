// Session-level tests: two vaults, a real card exchange, and messages passed
// between them the way `send` and `recv` do it. The ratchet tests drive the
// ratchet directly and the x3dh tests drive the handshake directly; these
// exist for the behaviour that only appears once the two are wired together
// through a VaultStore, which is where a replayed opening message does its
// damage.

#include <string>
#include <vector>

#include "ratchet/session.hpp"
#include "ratchet/store.hpp"
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

// A vault with an identity, one signed prekey, and `otpk_count` one-time
// prekeys -- what `init` produces.
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
  return p;
}

// Publishes `from`'s card and imports it into `into` under `alias`, the way
// `card` piped into `add` does.
void introduce(const Party& from, Party& into, const std::string& alias) {
  const std::string card_text = x3dh::export_card(
      from.pk, from.vault.signed_prekeys.back(), from.vault.one_time_prekeys);
  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  store::Contact contact;
  contact.alias = alias;
  contact.identity_pub = imported.identity_pub;
  contact.verified = true;
  contact.card = imported.card;
  into.vault.contacts.push_back(std::move(contact));
}

}  // namespace

TEST("an opening message that used no one-time prekey cannot be replayed") {
  // No one-time prekeys on Bob's card: this is the case the guard exists for.
  // With one, the prekey is erased on first use and the replay is already
  // refused for want of it.
  Party alice = make_party(3);
  Party bob = make_party(0);
  introduce(bob, alice, "bob");
  introduce(alice, bob, "alice");

  const std::string opening =
      session::send(alice.vault, alice.sk, alice.pk, 0, "attack at dawn");

  const session::ReceiveResult first =
      session::receive(bob.vault, bob.sk, bob.pk, opening);
  CHECK_EQ(first.plaintext, std::string("attack at dawn"));
  CHECK(first.session_established);
  CHECK_EQ(bob.vault.accepted_handshakes.size(), std::size_t(1));

  // The same block again is refused rather than re-delivered.
  CHECK_THROWS(session::receive(bob.vault, bob.sk, bob.pk, opening));
  CHECK_EQ(bob.vault.accepted_handshakes.size(), std::size_t(1));
}

TEST("a replayed opening message cannot destroy an advanced session") {
  // The damage the guard is really there to stop. The replay does not just
  // re-deliver an old message: accepting it replaces the session, so without
  // the guard everything sent after it stops decrypting for good.
  Party alice = make_party(3);
  Party bob = make_party(0);
  introduce(bob, alice, "bob");
  introduce(alice, bob, "alice");

  const std::string opening =
      session::send(alice.vault, alice.sk, alice.pk, 0, "attack at dawn");
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, opening).plaintext,
           std::string("attack at dawn"));

  // Bob replies, which ratchets both sides forward.
  const std::string reply =
      session::send(bob.vault, bob.sk, bob.pk, 0, "roger");
  CHECK_EQ(session::receive(alice.vault, alice.sk, alice.pk, reply).plaintext,
           std::string("roger"));

  const std::string later =
      session::send(alice.vault, alice.sk, alice.pk, 0, "bring the maps");

  // The attacker re-pastes the opening message from weeks ago.
  CHECK_THROWS(session::receive(bob.vault, bob.sk, bob.pk, opening));

  // The conversation survives it.
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, later).plaintext,
           std::string("bring the maps"));
}

TEST("a genuine second handshake is still accepted") {
  // The guard keys on the initiator's ephemeral, which is drawn fresh every
  // time, so re-handshaking -- after losing a vault and restoring from the
  // recovery phrase, say -- must still work.
  Party alice = make_party(3);
  Party bob = make_party(0);
  introduce(bob, alice, "bob");
  introduce(alice, bob, "alice");

  const std::string first =
      session::send(alice.vault, alice.sk, alice.pk, 0, "first");
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, first).plaintext,
           std::string("first"));

  // Alice starts over from scratch against the same card.
  alice.vault.sessions.clear();
  const std::string second =
      session::send(alice.vault, alice.sk, alice.pk, 0, "second");

  const session::ReceiveResult result =
      session::receive(bob.vault, bob.sk, bob.pk, second);
  CHECK_EQ(result.plaintext, std::string("second"));
  CHECK(result.session_established);
  CHECK_EQ(bob.vault.accepted_handshakes.size(), std::size_t(2));
}

TEST("an opening message that used a one-time prekey is also refused twice") {
  // Belt and braces: here the one-time prekey is what stops the second
  // delivery, and the guard's entry is recorded all the same.
  Party alice = make_party(3);
  Party bob = make_party(3);
  introduce(bob, alice, "bob");
  introduce(alice, bob, "alice");

  const std::string opening =
      session::send(alice.vault, alice.sk, alice.pk, 0, "hello");
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, opening).plaintext,
           std::string("hello"));
  CHECK_EQ(bob.vault.one_time_prekeys.size(), std::size_t(2));

  CHECK_THROWS(session::receive(bob.vault, bob.sk, bob.pk, opening));
}

TEST("the accepted-handshake list survives a vault round-trip") {
  store::VaultStore s;
  randombytes_buf(s.seed.data(), s.seed.size());

  store::AcceptedHandshake h;
  randombytes_buf(h.initiator_identity.data(), h.initiator_identity.size());
  randombytes_buf(h.ephemeral_pub.data(), h.ephemeral_pub.size());
  h.accepted_at = 1700000000;
  s.accepted_handshakes.push_back(h);

  const SecureBuffer bytes = store::serialize(s);
  const store::VaultStore parsed = store::parse(bytes.data(), bytes.size());

  CHECK_EQ(parsed.accepted_handshakes.size(), std::size_t(1));
  CHECK(parsed.accepted_handshakes[0].initiator_identity == h.initiator_identity);
  CHECK(parsed.accepted_handshakes[0].ephemeral_pub == h.ephemeral_pub);
  CHECK_EQ(parsed.accepted_handshakes[0].accepted_at, h.accepted_at);
  CHECK(parsed.handshake_already_accepted(h.initiator_identity, h.ephemeral_pub));
}

TEST("remember_handshake evicts the oldest once the list is full") {
  store::VaultStore s;
  IdentitySigningPublicKey id{};
  randombytes_buf(id.data(), id.size());

  std::vector<x25519::PublicKey> ephemerals;
  for (std::size_t i = 0; i < store::kMaxAcceptedHandshakes + 4; ++i) {
    x25519::PublicKey e{};
    randombytes_buf(e.data(), e.size());
    ephemerals.push_back(e);
    s.remember_handshake(id, e, 1700000000 + i);
  }

  CHECK_EQ(s.accepted_handshakes.size(), store::kMaxAcceptedHandshakes);
  // The four oldest were pushed out; the newest are all still there.
  CHECK(!s.handshake_already_accepted(id, ephemerals[0]));
  CHECK(!s.handshake_already_accepted(id, ephemerals[3]));
  CHECK(s.handshake_already_accepted(id, ephemerals[4]));
  CHECK(s.handshake_already_accepted(id, ephemerals.back()));

  // Recording the same handshake twice is a no-op, not a second entry.
  const std::size_t before = s.accepted_handshakes.size();
  s.remember_handshake(id, ephemerals.back(), 1700009999);
  CHECK_EQ(s.accepted_handshakes.size(), before);
}

// RU-03. decrypt() ratchets chains, caches skipped keys and can perform a whole
// DH step before the AEAD tag is checked -- it has to, since the tag cannot be
// verified until the key exists. So a forged message rearranges the session and
// only then fails, and the question is whether that rearrangement survives.
//
// It used to survive in memory and was saved from mattering only by `recv` not
// writing the vault when a command throws: a real property, resting on an
// invariant written down nowhere. These tests state it directly, against the
// serialised store, so it holds regardless of what any caller does afterwards.
namespace {

// The bytes a failed delivery must not change.
std::vector<uint8_t> snapshot(const store::VaultStore& vault) {
  const SecureBuffer buf = store::serialize(vault);
  return std::vector<uint8_t>(buf.data(), buf.data() + buf.size());
}

// Corrupts the last byte of the envelope body, which is inside the Poly1305
// tag. Everything structural survives -- the sender id, the flag that says
// whether this is an opening message, the ratchet header -- so the message is
// routed to the right contact and the ratchet is driven exactly as far as a
// genuine one would drive it, and only the tag check fails. Flipping a byte at
// a guessed offset in the armour is not good enough: it tends to break the
// framing instead, and the delivery then fails before the session is touched
// at all, which makes the test pass whether or not the bug is present.
std::string forge(const std::string& block) {
  std::vector<uint8_t> body = wire::decode_block("MESSAGE", block);
  body.back() ^= 0x01u;
  return wire::encode_block("MESSAGE", body.data(), body.size());
}

}  // namespace

TEST("a forged message leaves an established session byte-for-byte unchanged") {
  Party alice = make_party(3);
  Party bob = make_party(3);
  introduce(bob, alice, "bob");
  introduce(alice, bob, "alice");

  // Establish, and exchange enough that the session carries real state.
  const std::string opening =
      session::send(alice.vault, alice.sk, alice.pk, 0, "one");
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, opening).plaintext, "one");
  const std::string reply = session::send(bob.vault, bob.sk, bob.pk, 0, "two");
  CHECK_EQ(session::receive(alice.vault, alice.sk, alice.pk, reply).plaintext, "two");

  const std::string genuine =
      session::send(alice.vault, alice.sk, alice.pk, 0, "three");
  const std::vector<uint8_t> before = snapshot(bob.vault);

  CHECK_THROWS(session::receive(bob.vault, bob.sk, bob.pk, forge(genuine)));

  CHECK(snapshot(bob.vault) == before);

  // And the session is not merely unchanged, it still works: the genuine
  // message that follows the forgery decrypts exactly as it would have.
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, genuine).plaintext, "three");
}

TEST("a forged opening message consumes no one-time prekey") {
  Party alice = make_party(3);
  Party bob = make_party(3);
  introduce(bob, alice, "bob");
  introduce(alice, bob, "alice");

  const std::string opening =
      session::send(alice.vault, alice.sk, alice.pk, 0, "hello");
  const std::size_t prekeys_before = bob.vault.one_time_prekeys.size();
  const std::vector<uint8_t> before = snapshot(bob.vault);

  CHECK_THROWS(session::receive(bob.vault, bob.sk, bob.pk, forge(opening)));

  // Erasing the prekey before the message proved genuine would have let anyone
  // exhaust the pool by pasting nonsense.
  CHECK_EQ(bob.vault.one_time_prekeys.size(), prekeys_before);
  CHECK(snapshot(bob.vault) == before);

  // The real opening still establishes the session afterwards.
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, opening).plaintext, "hello");
}
