// Group messages: one content key, wrapped once per member through the 1:1
// sessions those members already have with the sender. The tests use real
// cards and real sessions, because the interesting failures are the ones that
// only show up when a recipient tries a wrapper addressed to somebody else.

#include <sodium.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#include "ratchet/app.hpp"
#include "ratchet/group.hpp"
#include "ratchet/kdf.hpp"
#include "ratchet/message.hpp"
#include "ratchet/ratchet.hpp"
#include "ratchet/serial.hpp"
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

// The following helpers mirror the GROUP format in src/group.cpp. They exist
// so the isolation test can build a block with an extra, valid 1:1 wrapper that
// is not a group-key payload. Keep them in sync with the producer.

constexpr std::array<uint8_t, 4> kTestGroupMagic = {'R', 'G', 'R', 'P'};
constexpr std::array<uint8_t, 4> kTestKeyMagic = {'R', 'G', 'K', '1'};
constexpr std::string_view kTestSignDomain = "Ratchet-USB/v1/group-sender";
constexpr uint8_t kTestGroupVersion = 1;
constexpr std::size_t kTestNonceBytes = 12;

void test_derive_wrapper_key(const SecureBytes<32>& shared, SecureBytes<32>& key) {
  constexpr std::string_view kSalt = "Ratchet-USB/v1/group-wrapper";
  constexpr std::string_view kInfo = "Ratchet-USB/v1/group-wrapper-key";
  kdf::Prk prk;
  kdf::extract(prk, reinterpret_cast<const uint8_t*>(kSalt.data()),
               kSalt.size(), shared.data(), shared.size());
  kdf::expand(key.data(), key.size(), kInfo, prk);
}

std::string test_seal(const IdentitySigningPublicKey& recipient,
                      const std::string& inner) {
  IdentityDHPublicKey recipient_dh;
  identity_dh_public(recipient, recipient_dh);
  x25519::SecretKey ephemeral_sk;
  x25519::PublicKey ephemeral_pub;
  x25519::generate_keypair(ephemeral_sk, ephemeral_pub);
  SecureBytes<32> shared;
  x25519::dh(ephemeral_sk, recipient_dh, shared);
  SecureBytes<32> key;
  test_derive_wrapper_key(shared, key);

  std::array<uint8_t, kTestNonceBytes> nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  std::vector<uint8_t> ciphertext(
      inner.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long ciphertext_len = 0;
  CHECK(crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            reinterpret_cast<const uint8_t*>(inner.data()), inner.size(),
            nullptr, 0, nullptr, nonce.data(), key.data()) == 0);
  ciphertext.resize(ciphertext_len);

  std::vector<uint8_t> out;
  serial::Writer<std::vector<uint8_t>> w(out);
  w.bytes(ephemeral_pub.data(), ephemeral_pub.size());
  w.bytes(nonce.data(), nonce.size());
  w.blob(ciphertext.data(), ciphertext.size());
  return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

std::string test_key_payload(const std::array<uint8_t, 16>& group_id,
                             const SecureBytes<32>& content_key) {
  std::vector<uint8_t> out;
  serial::Writer<std::vector<uint8_t>> w(out);
  w.bytes(kTestKeyMagic.data(), kTestKeyMagic.size());
  w.bytes(group_id.data(), group_id.size());
  w.bytes(content_key.data(), content_key.size());
  return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

std::vector<uint8_t> test_content_aad(
    const std::array<uint8_t, 16>& group_id,
    const IdentitySigningPublicKey& sender,
    const std::vector<std::string>& wrappers) {
  std::vector<uint8_t> wrapper_bytes;
  serial::Writer<std::vector<uint8_t>> ww(wrapper_bytes);
  for (const std::string& wrapper : wrappers) {
    ww.str(wrapper);
  }
  std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
  crypto_hash_sha256(digest.data(), wrapper_bytes.data(), wrapper_bytes.size());

  std::vector<uint8_t> aad;
  aad.reserve(kTestGroupMagic.size() + 1 + group_id.size() + sender.size() + 4 +
              digest.size());
  serial::Writer<std::vector<uint8_t>> w(aad);
  w.bytes(kTestGroupMagic.data(), kTestGroupMagic.size());
  w.u8(kTestGroupVersion);
  w.bytes(group_id.data(), group_id.size());
  w.bytes(sender.data(), sender.size());
  w.u32(static_cast<uint32_t>(wrappers.size()));
  w.bytes(digest.data(), digest.size());
  return aad;
}

std::array<uint8_t, crypto_hash_sha256_BYTES> test_transcript_digest(
    const std::vector<uint8_t>& aad, const std::vector<uint8_t>& ciphertext) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(
      &state, reinterpret_cast<const uint8_t*>(kTestSignDomain.data()),
      kTestSignDomain.size());
  crypto_hash_sha256_update(&state, aad.data(), aad.size());
  crypto_hash_sha256_update(&state, ciphertext.data(), ciphertext.size());
  std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
  crypto_hash_sha256_final(&state, digest.data());
  return digest;
}

std::vector<uint8_t> test_encrypt_content(
    const SecureBytes<32>& content_key, const std::string& plaintext,
    const std::array<uint8_t, kTestNonceBytes>& nonce,
    const std::vector<uint8_t>& aad) {
  const std::size_t target_len = ::ratchet::ratchet::detail::padded_payload_size(plaintext.size());
  SecureBuffer padded;
  padded.resize(target_len);
  std::memcpy(padded.data(), plaintext.data(), plaintext.size());
  padded[plaintext.size()] = 0x80;

  std::vector<uint8_t> ciphertext(
      target_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long ciphertext_len = 0;
  CHECK(crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len, padded.data(), padded.size(),
            aad.data(), aad.size(), nullptr, nonce.data(),
            content_key.data()) == 0);
  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

std::string test_build_group(
    const std::array<uint8_t, 16>& group_id,
    const IdentitySigningPublicKey& sender,
    const std::array<uint8_t, kTestNonceBytes>& nonce,
    const std::vector<std::string>& wrappers,
    const std::vector<uint8_t>& ciphertext,
    const IdentitySigningSecretKey& sender_sk) {
  const std::vector<uint8_t> aad =
      test_content_aad(group_id, sender, wrappers);
  const auto digest = test_transcript_digest(aad, ciphertext);
  Signature signature{};
  sign(sender_sk, digest.data(), digest.size(), signature);

  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> w(body);
  w.bytes(kTestGroupMagic.data(), kTestGroupMagic.size());
  w.u8(kTestGroupVersion);
  w.bytes(group_id.data(), group_id.size());
  w.bytes(sender.data(), sender.size());
  w.bytes(nonce.data(), nonce.size());
  w.u32(static_cast<uint32_t>(wrappers.size()));
  for (const std::string& wrapper : wrappers) {
    w.str(wrapper);
  }
  w.blob(ciphertext.data(), ciphertext.size());
  w.bytes(signature.data(), signature.size());
  return wire::encode_block("GROUP", body.data(), body.size());
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

TEST("a group wrapper does not reuse the session ratchet key") {
  Party alice = make_party(3);
  Party bob = make_party(3);
  Party carol = make_party(3);
  introduce(bob, alice, "bob");
  introduce(carol, alice, "carol");
  introduce(alice, bob, "alice");
  introduce(alice, carol, "alice");

  // Establish a 1:1 session and remember the ratchet key its envelope carried.
  const std::string direct =
      session::send(alice.vault, alice.sk, alice.pk, 0, "direct");
  const message::Envelope direct_env = message::decode(direct);
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, direct).plaintext,
           std::string("direct"));

  const std::string block =
      group::send(alice.vault, alice.sk, alice.pk, {0, 1}, "group");
  const std::vector<uint8_t> body = wire::decode_block("GROUP", block);

  // The wrapper is sealed to Bob's identity key, so neither the established
  // session's ratchet key nor the inner MESSAGE block (which carries it) is on
  // the wire. Either would let an observer link the wrapper to earlier 1:1
  // traffic with Bob.
  CHECK(std::search(body.begin(), body.end(), direct_env.header.dh_pub.begin(),
                    direct_env.header.dh_pub.end()) == body.end());
  CHECK(std::search(body.begin(), body.end(), direct_env.sender_id.begin(),
                    direct_env.sender_id.end()) == body.end());
  CHECK(block.find("BEGIN RATCHET MESSAGE") == std::string::npos);

  CHECK_EQ(group::receive(bob.vault, bob.sk, bob.pk, block).plaintext,
           std::string("group"));
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

TEST("group-receive rolls back when only the nonce is changed") {
  // The nonce is not part of the signed transcript, so this block still passes
  // the sender signature and Bob's wrapper opens. It must fail at content
  // authentication, and that failure must not consume Bob's wrapper: the
  // genuine block has to decrypt afterwards.
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
  // magic(4) + version(1) + group id(16) + sender(32) = 53, then the nonce.
  CHECK(body.size() > 53 + 12);
  body[53] ^= 0x01;
  const std::string forged = wire::encode_block("GROUP", body.data(), body.size());

  bool authentication_error = false;
  try {
    group::receive(bob.vault, bob.sk, bob.pk, forged);
  } catch (const Error& e) {
    authentication_error =
        std::string(e.what()).find("authentication failed") != std::string::npos;
  }
  CHECK(authentication_error);

  CHECK_EQ(group::receive(bob.vault, bob.sk, bob.pk, block).plaintext,
           std::string("original"));
}

TEST("a non-key wrapper does not consume the direct message it carries") {
  Party alice = make_party(3);
  Party bob = make_party(3);
  introduce(bob, alice, "bob");
  introduce(alice, bob, "alice");

  // Establish the session, then leave two messages in Bob's receiving chain:
  // a direct message (n=1) and the group wrapper (n=2). The crafted block puts
  // the direct message first, as a valid but non-key wrapper.
  const std::string opening =
      session::send(alice.vault, alice.sk, alice.pk, 0, "opening");
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, opening).plaintext,
           std::string("opening"));
  const std::string direct =
      session::send(alice.vault, alice.sk, alice.pk, 0, "not a group key");

  std::array<uint8_t, 16> group_id{};
  randombytes_buf(group_id.data(), group_id.size());
  SecureBytes<32> content_key;
  randombytes_buf(content_key.data(), content_key.size());
  std::array<uint8_t, kTestNonceBytes> nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  const std::string key_payload = test_key_payload(group_id, content_key);
  const std::string group_inner =
      session::send(alice.vault, alice.sk, alice.pk, 0, key_payload);

  const std::vector<std::string> wrappers = {
      test_seal(bob.pk, direct),
      test_seal(bob.pk, group_inner),
  };
  const std::vector<uint8_t> aad =
      test_content_aad(group_id, alice.pk, wrappers);
  const std::vector<uint8_t> ciphertext =
      test_encrypt_content(content_key, "original", nonce, aad);
  const std::string block = test_build_group(group_id, alice.pk, nonce,
                                             wrappers, ciphertext, alice.sk);

  CHECK_EQ(group::receive(bob.vault, bob.sk, bob.pk, block).plaintext,
           std::string("original"));

  // The direct message was not consumed by the rejected wrapper attempt.
  CHECK_EQ(session::receive(bob.vault, bob.sk, bob.pk, direct).plaintext,
           std::string("not a group key"));
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
  bool signature_error = false;
  try {
    group::receive(bob.vault, bob.sk, bob.pk, forged);
  } catch (const Error& e) {
    signature_error =
        std::string(e.what()).find("sender signature is invalid") !=
        std::string::npos;
  }
  // The AEAD would also reject this block, but the signature must be checked
  // first; otherwise a member could still make Carol consume her wrapper
  // before the forged content fails.
  CHECK(signature_error);

  // The rejected block must not have consumed Bob's wrapper: the genuine block
  // still has to decrypt afterwards.
  CHECK_EQ(group::receive(bob.vault, bob.sk, bob.pk, block).plaintext,
           std::string("original"));
}
