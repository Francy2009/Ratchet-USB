#ifndef RATCHET_PQ_HPP
#define RATCHET_PQ_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "ratchet/secure.hpp"

namespace ratchet::pq {

inline constexpr std::size_t kMlKem768PublicKeyBytes = 1184;
inline constexpr std::size_t kMlKem768PrivateSeedBytes = 64;
inline constexpr std::size_t kMlKem768CiphertextBytes = 1088;
inline constexpr std::size_t kMlKemSharedSecretBytes = 32;

using MlKemPublicKey = std::array<uint8_t, kMlKem768PublicKeyBytes>;
using MlKemPrivateSeed = SecureBytes<kMlKem768PrivateSeedBytes>;
using MlKemCiphertext = std::array<uint8_t, kMlKem768CiphertextBytes>;
using MlKemSharedSecret = SecureBytes<kMlKemSharedSecretBytes>;

struct MlKemKeyPair {
  MlKemPublicKey public_key{};
  MlKemPrivateSeed private_seed;
};

MlKemKeyPair generate_ml_kem_768();
MlKemKeyPair ml_kem_768_from_seed(const MlKemPrivateSeed& seed);
void ml_kem_768_encapsulate(const MlKemPublicKey& public_key,
                            MlKemCiphertext& ciphertext,
                            MlKemSharedSecret& shared_secret);
void ml_kem_768_decapsulate(const MlKemPrivateSeed& private_seed,
                            const MlKemCiphertext& ciphertext,
                            MlKemSharedSecret& shared_secret);

inline constexpr std::size_t kMlDsa65PublicKeyBytes = 1952;
inline constexpr std::size_t kMlDsa65PrivateSeedBytes = 32;
inline constexpr std::size_t kMlDsa65SignatureBytes = 3309;
using MlDsaPublicKey = std::array<uint8_t, kMlDsa65PublicKeyBytes>;
using MlDsaPrivateSeed = SecureBytes<kMlDsa65PrivateSeedBytes>;
using MlDsaSignature = std::array<uint8_t, kMlDsa65SignatureBytes>;

struct MlDsaKeyPair {
  MlDsaPublicKey public_key{};
  MlDsaPrivateSeed private_seed;
};

MlDsaKeyPair ml_dsa_65_from_seed(const MlDsaPrivateSeed& seed);
void ml_dsa_65_sign(const MlDsaPrivateSeed& seed, const uint8_t* message,
                    std::size_t message_len, MlDsaSignature& signature);
bool ml_dsa_65_verify(const MlDsaPublicKey& public_key, const uint8_t* message,
                      std::size_t message_len,
                      const MlDsaSignature& signature);

}  // namespace ratchet::pq

#endif
