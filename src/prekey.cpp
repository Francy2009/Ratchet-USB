#include "ratchet/prekey.hpp"

namespace ratchet::prekey {

SignedPrekey generate_signed_prekey(const IdentitySigningSecretKey& identity_sk,
                                    uint32_t id) {
  SignedPrekey record;
  record.id = id;
  x25519::generate_keypair(record.sk, record.pub);
  sign(identity_sk, record.pub.data(), record.pub.size(), record.signature);
  return record;
}

bool verify_signed_prekey_signature(const IdentitySigningPublicKey& identity_pk,
                                    const x25519::PublicKey& spk_pub,
                                    const Signature& signature) {
  return verify(identity_pk, spk_pub.data(), spk_pub.size(), signature);
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
