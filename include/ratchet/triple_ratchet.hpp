#ifndef RATCHET_TRIPLE_RATCHET_HPP
#define RATCHET_TRIPLE_RATCHET_HPP

#include <string_view>

#include "ratchet/secure.hpp"

namespace ratchet::triple_ratchet {

inline constexpr std::string_view kProtocolInfo =
    "Ratchet-USB/v3/TripleRatchet/X25519+ML-KEM-768";
inline constexpr std::string_view kInitialInfo =
    "Ratchet-USB/v3/TripleRatchet/X25519+ML-KEM-768/InitialSplit";

// PQXDH supplies one hybrid secret. Triple Ratchet initialization requires
// independent EC and SCKA inputs, so expand it with explicit domain separation.
void split_initial_secret(const SecureBytes<32>& pqxdh_secret,
                          SecureBytes<32>& ec_secret,
                          SecureBytes<32>& scka_secret);

// KDF_HYBRID from the Signal Triple Ratchet specification: the PQ message key
// is the HKDF salt and the EC message key is the IKM. Either family remaining
// secret is sufficient to keep the resulting AEAD key secret.
void combine_message_keys(const SecureBytes<32>& ec_message_key,
                          const SecureBytes<32>& pq_message_key,
                          SecureBytes<32>& aead_key);

}  // namespace ratchet::triple_ratchet

#endif
