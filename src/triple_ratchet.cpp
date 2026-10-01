#include "ratchet/triple_ratchet.hpp"

#include <array>

#include "ratchet/kdf.hpp"

namespace ratchet::triple_ratchet {

void split_initial_secret(const SecureBytes<32>& pqxdh_secret,
                          SecureBytes<32>& ec_secret,
                          SecureBytes<32>& scka_secret) {
  const std::array<uint8_t, 32> zero_salt{};
  kdf::Prk prk;
  kdf::extract(prk, zero_salt.data(), zero_salt.size(), pqxdh_secret.data(),
               pqxdh_secret.size());
  SecureBytes<64> output;
  kdf::expand(output.data(), output.size(), kInitialInfo, prk);
  ec_secret.assign(output.data(), ec_secret.size());
  scka_secret.assign(output.data() + ec_secret.size(), scka_secret.size());
}

void combine_message_keys(const SecureBytes<32>& ec_message_key,
                          const SecureBytes<32>& pq_message_key,
                          SecureBytes<32>& aead_key) {
  kdf::Prk prk;
  kdf::extract(prk, pq_message_key.data(), pq_message_key.size(),
               ec_message_key.data(), ec_message_key.size());
  kdf::expand(aead_key.data(), aead_key.size(), kProtocolInfo, prk);
}

}  // namespace ratchet::triple_ratchet
