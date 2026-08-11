#include <string>
#include <vector>

#include "ratchet/ratchet.hpp"
#include "ratchet/x3dh.hpp"
#include "test_support.hpp"

using namespace ratchet;
namespace rr = ::ratchet::ratchet;

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

// Wires up a fresh Alice/Bob pair with an established Double Ratchet session
// on both sides, exactly as `send`/`recv` would after the first message.
struct Pair {
  store::Session alice;
  store::Session bob;
};

Pair make_established_pair() {
  const Identity alice = make_identity();
  const Identity bob = make_identity();

  const prekey::SignedPrekey bob_spk = prekey::generate_signed_prekey(bob.sk, 1);

  store::Contact contact;
  contact.identity_pub = bob.pk;
  store::PeerCard card;
  card.spk_id = bob_spk.id;
  card.spk_pub = bob_spk.pub;
  card.spk_signature = bob_spk.signature;
  contact.card = card;

  x3dh::InitiatorResult init_result = x3dh::initiate(alice.sk, alice.pk, contact);

  Pair pair;
  rr::init_sender(pair.alice, init_result.shared_secret,
                               init_result.ephemeral_sk, init_result.ephemeral_pk,
                               bob_spk.pub);

  const SecureBytes<32> bob_secret =
      x3dh::respond(bob.sk, bob.pk, alice.pk, init_result.ephemeral_pk, bob_spk,
                   nullptr);
  rr::init_receiver(pair.bob, bob_secret, bob_spk.sk, bob_spk.pub);

  return pair;
}

}  // namespace

TEST("a single message round-trips from Alice to Bob") {
  Pair pair = make_established_pair();

  message::RatchetHeader header;
  std::vector<uint8_t> ct;
  rr::encrypt(pair.alice, "hello bob", header, ct);

  const std::string plaintext = rr::decrypt(pair.bob, header, ct);
  CHECK_EQ(plaintext, std::string("hello bob"));
}

TEST("messages in both directions round-trip, including the DH ratchet step") {
  Pair pair = make_established_pair();

  message::RatchetHeader h1;
  std::vector<uint8_t> ct1;
  rr::encrypt(pair.alice, "alice says hi", h1, ct1);
  CHECK_EQ(rr::decrypt(pair.bob, h1, ct1), std::string("alice says hi"));

  // Bob replying triggers his first DH ratchet step (he had no sending chain
  // until now).
  message::RatchetHeader h2;
  std::vector<uint8_t> ct2;
  rr::encrypt(pair.bob, "bob says hi back", h2, ct2);
  CHECK_EQ(rr::decrypt(pair.alice, h2, ct2),
          std::string("bob says hi back"));

  // And a few more exchanges, alternating direction each time.
  for (int i = 0; i < 5; ++i) {
    message::RatchetHeader ha;
    std::vector<uint8_t> cta;
    const std::string msg_a = "alice message " + std::to_string(i);
    rr::encrypt(pair.alice, msg_a, ha, cta);
    CHECK_EQ(rr::decrypt(pair.bob, ha, cta), msg_a);

    message::RatchetHeader hb;
    std::vector<uint8_t> ctb;
    const std::string msg_b = "bob message " + std::to_string(i);
    rr::encrypt(pair.bob, msg_b, hb, ctb);
    CHECK_EQ(rr::decrypt(pair.alice, hb, ctb), msg_b);
  }
}

TEST("messages that arrive out of order still decrypt via skipped keys") {
  Pair pair = make_established_pair();

  struct Sent {
    message::RatchetHeader header;
    std::vector<uint8_t> ciphertext;
    std::string plaintext;
  };

  std::vector<Sent> sent;
  for (int i = 0; i < 4; ++i) {
    Sent s;
    s.plaintext = "message " + std::to_string(i);
    rr::encrypt(pair.alice, s.plaintext, s.header, s.ciphertext);
    sent.push_back(std::move(s));
  }

  // Deliver out of order: 2, 0, 3, 1.
  const int order[] = {2, 0, 3, 1};
  for (int idx : order) {
    const std::string decrypted =
        rr::decrypt(pair.bob, sent[idx].header, sent[idx].ciphertext);
    CHECK_EQ(decrypted, sent[idx].plaintext);
  }
}

TEST("a message cannot be decrypted twice (the skipped key is consumed)") {
  Pair pair = make_established_pair();

  message::RatchetHeader h0;
  std::vector<uint8_t> ct0;
  rr::encrypt(pair.alice, "first", h0, ct0);
  message::RatchetHeader h1;
  std::vector<uint8_t> ct1;
  rr::encrypt(pair.alice, "second", h1, ct1);

  // Deliver the second message first, which skips (and caches) the key for
  // the first.
  CHECK_EQ(rr::decrypt(pair.bob, h1, ct1), std::string("second"));
  CHECK_EQ(rr::decrypt(pair.bob, h0, ct0), std::string("first"));
  // Replaying the first message again must fail: its key is gone.
  CHECK_THROWS(rr::decrypt(pair.bob, h0, ct0));
}

TEST("tampering with the ciphertext is detected") {
  Pair pair = make_established_pair();

  message::RatchetHeader header;
  std::vector<uint8_t> ct;
  rr::encrypt(pair.alice, "do not tamper", header, ct);

  ct.back() ^= 0x01;
  CHECK_THROWS(rr::decrypt(pair.bob, header, ct));
}

TEST("tampering with the header is detected (it is authenticated as AAD)") {
  Pair pair = make_established_pair();

  message::RatchetHeader header;
  std::vector<uint8_t> ct;
  rr::encrypt(pair.alice, "header integrity matters", header, ct);

  message::RatchetHeader tampered_header = header;
  tampered_header.n += 1;
  CHECK_THROWS(rr::decrypt(pair.bob, tampered_header, ct));
}

TEST("a gap larger than kMaxSkip is refused") {
  Pair pair = make_established_pair();

  message::RatchetHeader last_header;
  std::vector<uint8_t> last_ct;
  for (std::size_t i = 0; i < rr::kMaxSkip + 5; ++i) {
    rr::encrypt(pair.alice, "x", last_header, last_ct);
  }

  CHECK_THROWS(rr::decrypt(pair.bob, last_header, last_ct));
}
