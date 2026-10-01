#include "ratchet/message.hpp"

#include <sodium.h>

#include <cstring>

#include "ratchet/serial.hpp"
#include "ratchet/wire.hpp"

namespace ratchet::message {
namespace {
constexpr std::array<uint8_t, 4> kMessageMagic = {'R', 'M', 'S', 'G'};
}

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

std::vector<uint8_t> envelope_aad_prefix(const Envelope& env) {
  std::vector<uint8_t> out;
  serial::Writer<std::vector<uint8_t>> w(out);
  w.bytes(kMessageMagic.data(), kMessageMagic.size());
  w.u8(env.version);
  w.u8(static_cast<uint8_t>(env.suite));
  w.bytes(env.sender_id.data(), env.sender_id.size());
  w.u8(env.initial ? 1 : 0);
  if (env.initial) {
    const InitialFields& f = *env.initial;
    w.bytes(f.initiator_identity_pub.data(), f.initiator_identity_pub.size());
    w.u32(f.spk_id);
    w.u8(f.otpk_id ? 1 : 0); if (f.otpk_id) w.u32(*f.otpk_id);
    w.u8(f.pq_spk_id && f.pq_spk_ciphertext ? 1 : 0);
    if (f.pq_spk_id && f.pq_spk_ciphertext) {
      w.u32(*f.pq_spk_id);
      w.bytes(f.pq_spk_ciphertext->data(), f.pq_spk_ciphertext->size());
    }
    w.u8(f.pq_otpk_id && f.pq_otpk_ciphertext ? 1 : 0);
    if (f.pq_otpk_id && f.pq_otpk_ciphertext) {
      w.u32(*f.pq_otpk_id);
      w.bytes(f.pq_otpk_ciphertext->data(), f.pq_otpk_ciphertext->size());
    }
  }
  if (env.version == 3) {
    w.blob(env.spqr_message.data(), env.spqr_message.size());
  }
  return out;
}

std::string encode(const Envelope& env) {
  const bool hybrid = env.version == 2 &&
      env.suite == ProtocolSuite::HybridPqxdhV1 && env.spqr_message.empty();
  const bool triple = env.version == 3 &&
      env.suite == ProtocolSuite::TripleRatchetV1 &&
      !env.spqr_message.empty() && env.spqr_message.size() <= 1024u * 1024u;
  if (!hybrid && !triple) {
    throw Error("unsupported message protocol version or suite");
  }
  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> w(body);

  w.bytes(kMessageMagic.data(), kMessageMagic.size());
  w.u8(env.version);
  w.u8(static_cast<uint8_t>(env.suite));

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
    w.u8(f.pq_spk_id && f.pq_spk_ciphertext ? 1 : 0);
    if (f.pq_spk_id && f.pq_spk_ciphertext) {
      w.u32(*f.pq_spk_id);
      w.bytes(f.pq_spk_ciphertext->data(), f.pq_spk_ciphertext->size());
    }
    w.u8(f.pq_otpk_id && f.pq_otpk_ciphertext ? 1 : 0);
    if (f.pq_otpk_id && f.pq_otpk_ciphertext) {
      w.u32(*f.pq_otpk_id);
      w.bytes(f.pq_otpk_ciphertext->data(), f.pq_otpk_ciphertext->size());
    }
  }

  if (triple) {
    w.blob(env.spqr_message.data(), env.spqr_message.size());
  }

  w.bytes(env.header.dh_pub.data(), env.header.dh_pub.size());
  w.u32(env.header.pn);
  w.u32(env.header.n);

  w.blob(env.ciphertext.data(), env.ciphertext.size());

  return wire::encode_block("MESSAGE", body.data(), body.size());
}

Envelope decode(std::string_view text) {
  const std::vector<uint8_t> body =
      wire::decode_block("MESSAGE", text, kMaxEnvelopeBytes);
  serial::Reader r(body.data(), body.size());

  Envelope env;
  std::array<uint8_t, 4> magic{};
  r.bytes(magic.data(), magic.size());
  if (magic != kMessageMagic) throw Error("legacy message format is read-only");
  env.version = r.u8();
  const uint8_t suite = r.u8();
  const bool hybrid = env.version == 2 &&
      suite == static_cast<uint8_t>(ProtocolSuite::HybridPqxdhV1);
  const bool triple = env.version == 3 &&
      suite == static_cast<uint8_t>(ProtocolSuite::TripleRatchetV1);
  if (!hybrid && !triple) {
    throw Error("unsupported message protocol version or suite");
  }
  env.suite = static_cast<ProtocolSuite>(suite);
  r.bytes(env.sender_id.data(), env.sender_id.size());

  if (r.u8() != 0) {
    InitialFields f;
    r.bytes(f.initiator_identity_pub.data(), f.initiator_identity_pub.size());
    f.spk_id = r.u32();
    if (r.u8() != 0) {
      f.otpk_id = r.u32();
    }
    if (r.u8() != 0) {
      f.pq_spk_id = r.u32();
      pq::MlKemCiphertext ct{};
      r.bytes(ct.data(), ct.size());
      f.pq_spk_ciphertext = ct;
    }
    if (r.u8() != 0) {
      f.pq_otpk_id = r.u32();
      pq::MlKemCiphertext ct{};
      r.bytes(ct.data(), ct.size());
      f.pq_otpk_ciphertext = ct;
    }
    env.initial = f;
  }

  if (triple) {
    env.spqr_message = r.blob();
    if (env.spqr_message.empty() || env.spqr_message.size() > 1024u * 1024u) {
      throw Error("SPQR message has an invalid length");
    }
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
