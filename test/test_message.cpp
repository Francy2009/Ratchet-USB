#include <sodium.h>

#include <string>

#include "ratchet/message.hpp"
#include "ratchet/wire.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

message::Envelope make_envelope(bool with_initial) {
  message::Envelope env;
  randombytes_buf(env.sender_id.data(), env.sender_id.size());
  if (with_initial) {
    message::InitialFields f;
    randombytes_buf(f.initiator_identity_pub.data(), f.initiator_identity_pub.size());
    f.spk_id = 42;
    f.otpk_id = 7;
    env.initial = f;
  }
  randombytes_buf(env.header.dh_pub.data(), env.header.dh_pub.size());
  env.header.pn = 3;
  env.header.n = 9;
  env.ciphertext = {1, 2, 3, 4, 5, 250, 251, 252};
  return env;
}

}  // namespace

TEST("an envelope with X3DH fields round-trips through encode/decode") {
  const message::Envelope original = make_envelope(/*with_initial=*/true);
  const std::string text = message::encode(original);
  CHECK(text.find("-----BEGIN RATCHET MESSAGE-----") != std::string::npos);

  const message::Envelope decoded = message::decode(text);
  CHECK(decoded.sender_id == original.sender_id);
  CHECK(decoded.initial.has_value());
  CHECK(decoded.initial->initiator_identity_pub ==
       original.initial->initiator_identity_pub);
  CHECK_EQ(decoded.initial->spk_id, original.initial->spk_id);
  CHECK(decoded.initial->otpk_id.has_value());
  CHECK_EQ(*decoded.initial->otpk_id, *original.initial->otpk_id);
  CHECK(decoded.header.dh_pub == original.header.dh_pub);
  CHECK_EQ(decoded.header.pn, original.header.pn);
  CHECK_EQ(decoded.header.n, original.header.n);
  CHECK(decoded.ciphertext == original.ciphertext);
}

TEST("an envelope without X3DH fields round-trips too") {
  const message::Envelope original = make_envelope(/*with_initial=*/false);
  const std::string text = message::encode(original);
  const message::Envelope decoded = message::decode(text);

  CHECK(decoded.sender_id == original.sender_id);
  CHECK(!decoded.initial.has_value());
  CHECK(decoded.header.dh_pub == original.header.dh_pub);
  CHECK(decoded.ciphertext == original.ciphertext);
}

TEST("decode tolerates the block being pasted with extra surrounding text and reflow") {
  const message::Envelope original = make_envelope(/*with_initial=*/false);
  std::string text = message::encode(original);

  std::string mangled = "some chat app said:\n\n" + text + "\n\n-- sent from my phone";
  // Simulate line reflow by removing a couple of newlines inside the block.
  const size_t first_nl = mangled.find('\n', mangled.find("BEGIN"));
  if (first_nl != std::string::npos) {
    mangled.erase(first_nl, 1);
  }

  const message::Envelope decoded = message::decode(mangled);
  CHECK(decoded.ciphertext == original.ciphertext);
}

TEST("header_aad changes if any header field changes") {
  message::RatchetHeader h1;
  randombytes_buf(h1.dh_pub.data(), h1.dh_pub.size());
  h1.pn = 1;
  h1.n = 2;

  message::RatchetHeader h2 = h1;
  h2.n = 3;

  CHECK(message::header_aad(h1) != message::header_aad(h2));
}

TEST("decode rejects a card block where a message was expected") {
  CHECK_THROWS(message::decode(
      "-----BEGIN RATCHET CARD-----\nAAAA\n-----END RATCHET CARD-----\n"));
}

TEST("wire encode_block/decode_block round-trip and reject a label mismatch") {
  const std::vector<uint8_t> data = {0, 1, 2, 3, 255, 254, 253};
  const std::string block = wire::encode_block("TEST", data.data(), data.size());
  const std::vector<uint8_t> decoded = wire::decode_block("TEST", block);
  CHECK(decoded == data);

  CHECK_THROWS(wire::decode_block("OTHER", block));
  CHECK_THROWS(wire::decode_block("TEST", "no markers here"));
}
