#ifndef RATCHET_KDF_HPP
#define RATCHET_KDF_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ratchet/secure.hpp"

namespace ratchet::kdf {

inline constexpr std::size_t kPrkBytes = 32;  // SHA-256 output

using Prk = SecureBytes<kPrkBytes>;

// HKDF-SHA256 (RFC 5869).
//
// These forward to crypto_kdf_hkdf_sha256_* when the linked libsodium exposes
// them (1.0.19 and later). Older releases ship Argon2 and HMAC-SHA256 but not
// the HKDF wrapper, so a fallback built on crypto_auth_hmacsha256 is compiled
// in instead. Both paths are plain RFC 5869 and produce identical bytes; the
// RFC's own test vectors are in the test suite to keep them that way.
void extract(Prk& prk, const uint8_t* salt, std::size_t salt_len,
             const uint8_t* ikm, std::size_t ikm_len);

void expand(uint8_t* out, std::size_t out_len, std::string_view info,
            const Prk& prk);

// True when the build is using libsodium's own HKDF rather than the fallback.
bool using_libsodium_hkdf();

}  // namespace ratchet::kdf

#endif  // RATCHET_KDF_HPP
