#include "ratchet/prekey.hpp"

#include <ctime>

#include "ratchet/serial.hpp"

namespace ratchet::prekey {
namespace {

// What the identity key actually puts its name to when it signs a prekey.
//
// The bytes signed used to be the 32-byte public key on its own, which is a
// signature over an anonymous point: nothing in it says what kind of object
// was signed, or which one. Two consequences, one of them already exploitable
// and one waiting to be.
//
// The exploitable one: `id` was not covered, so a genuine card could have its
// spk_id rewritten in transit and the signature would still verify. The peer
// then opens a handshake against an id the recipient has never issued.
//
// The one waiting: the day this identity signs any other 32-byte value -- a
// ratchet key, a revocation token -- a signature over one could be presented
// as a signature over the other. A length-prefixed context string and the id
// make each signed structure unambiguous, at the cost of three lines.
std::vector<uint8_t> spk_signing_payload(uint32_t id,
                                         const x25519::PublicKey& pub) {
  std::vector<uint8_t> msg;
  serial::Writer<std::vector<uint8_t>> w(msg);
  w.str(kSignedPrekeyContext);
  w.u32(id);
  w.bytes(pub.data(), pub.size());
  return msg;
}

}  // namespace

SignedPrekey generate_signed_prekey(const IdentitySigningSecretKey& identity_sk,
                                    uint32_t id) {
  SignedPrekey record;
  record.id = id;
  x25519::generate_keypair(record.sk, record.pub);
  const std::vector<uint8_t> msg = spk_signing_payload(id, record.pub);
  sign(identity_sk, msg.data(), msg.size(), record.signature);
  record.created_at = static_cast<uint64_t>(std::time(nullptr));
  return record;
}

void resign_signed_prekey(const IdentitySigningSecretKey& identity_sk,
                          SignedPrekey& record) {
  const std::vector<uint8_t> msg = spk_signing_payload(record.id, record.pub);
  sign(identity_sk, msg.data(), msg.size(), record.signature);
}

bool verify_signed_prekey_signature(const IdentitySigningPublicKey& identity_pk,
                                    uint32_t spk_id,
                                    const x25519::PublicKey& spk_pub,
                                    const Signature& signature) {
  const std::vector<uint8_t> msg = spk_signing_payload(spk_id, spk_pub);
  return verify(identity_pk, msg.data(), msg.size(), signature);
}

std::vector<OneTimePrekey> generate_one_time_prekeys(uint32_t start_id,
                                                      std::size_t count) {
  std::vector<OneTimePrekey> out;
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    OneTimePrekey record;
    record.id = start_id + static_cast<uint32_t>(i);
    x25519::generate_keypair(record.sk, record.pub);
    out.push_back(std::move(record));
  }
  return out;
}

}  // namespace ratchet::prekey
