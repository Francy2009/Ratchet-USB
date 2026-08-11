#ifndef RATCHET_X25519_HPP
#define RATCHET_X25519_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "ratchet/secure.hpp"

namespace ratchet::x25519 {

inline constexpr std::size_t kSecretBytes = 32;
inline constexpr std::size_t kPublicBytes = 32;

using SecretKey = SecureBytes<kSecretBytes>;
using PublicKey = std::array<uint8_t, kPublicBytes>;

// A fresh random X25519 keypair. Used for ephemeral keys, signed prekeys and
// one-time prekeys -- everything that is not the long-term identity, which is
// derived from the seed instead.
void generate_keypair(SecretKey& sk, PublicKey& pk);

// Diffie-Hellman. Throws Error if the result is the all-zero point, which is
// what a maliciously crafted low-order public key produces; silently using
// such an output would hand an attacker a predictable shared secret.
void dh(const SecretKey& sk, const PublicKey& pk, SecureBytes<32>& out);

}  // namespace ratchet::x25519

#endif  // RATCHET_X25519_HPP
