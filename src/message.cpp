#include "ratchet/message.hpp"

#include <sodium.h>

#include <cstring>

#include "ratchet/serial.hpp"
#include "ratchet/wire.hpp"

namespace ratchet::message {

SenderId sender_id_for(const IdentitySigningPublicKey& identity_pub) {
  init_sodium();
  uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, identity_pub.data(), identity_pub.size());
  SenderId id{};
  std::memcpy(id.data(), digest, kSenderIdBytes);
  sodium_memzero(digest, sizeof digest);
  return id;
}

std::vector<uint8_t> header_aad(const RatchetHeader& header) {
  std::vector<uint8_t> aad;
  serial::Writer<std::vector<uint8_t>> w(aad);
  w.bytes(header.dh_pub.data(), header.dh_pub.size());
  w.u32(header.pn);
  w.u32(header.n);
  return aad;
}

std::string encode(const Envelope& env) {
  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> w(body);

  w.bytes(env.sender_id.data(), env.sender_id.size());
  w.u8(env.initial.has_value() ? 1 : 0);
  if (env.initial) {
    const InitialFields& f = *env.initial;
    w.bytes(f.initiator_identity_pub.data(), f.initiator_identity_pub.size());
    w.u32(f.spk_id);
    w.u8(f.otpk_id.has_value() ? 1 : 0);
    if (f.otpk_id) {
      w.u32(*f.otpk_id);
    }
  }

  w.bytes(env.header.dh_pub.data(), env.header.dh_pub.size());
  w.u32(env.header.pn);
  w.u32(env.header.n);

  w.blob(env.ciphertext.data(), env.ciphertext.size());

  return wire::encode_block("MESSAGE", body.data(), body.size());
}

Envelope decode(std::string_view text) {
  const std::vector<uint8_t> body = wire::decode_block("MESSAGE", text);
  serial::Reader r(body.data(), body.size());

  Envelope env;
  r.bytes(env.sender_id.data(), env.sender_id.size());

  if (r.u8() != 0) {
    InitialFields f;
    r.bytes(f.initiator_identity_pub.data(), f.initiator_identity_pub.size());
    f.spk_id = r.u32();
    if (r.u8() != 0) {
      f.otpk_id = r.u32();
    }
    env.initial = f;
  }

  r.bytes(env.header.dh_pub.data(), env.header.dh_pub.size());
  env.header.pn = r.u32();
  env.header.n = r.u32();

  env.ciphertext = r.blob();

  if (!r.at_end()) {
    throw Error("message envelope has trailing data");
  }
  return env;
}

}  // namespace ratchet::message
