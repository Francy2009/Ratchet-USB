#include "ratchet/kdf.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>

namespace ratchet::kdf {
namespace {

#ifndef RATCHET_HAVE_SODIUM_HKDF

// RFC 5869 HKDF-SHA256, for libsodium releases that predate
// crypto_kdf_hkdf_sha256_*. Byte-for-byte identical to the libsodium
// implementation; both are checked against the RFC test vectors in the tests.

void hmac(uint8_t out[crypto_auth_hmacsha256_BYTES], const uint8_t* key,
          std::size_t key_len, const uint8_t* msg, std::size_t msg_len) {
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init(&state, key, key_len);
  crypto_auth_hmacsha256_update(&state, msg, msg_len);
  crypto_auth_hmacsha256_final(&state, out);
  sodium_memzero(&state, sizeof state);
}

void fallback_extract(uint8_t prk[kPrkBytes], const uint8_t* salt,
                      std::size_t salt_len, const uint8_t* ikm,
                      std::size_t ikm_len) {
  // PRK = HMAC(key = salt, msg = IKM). An absent salt is a string of zeros.
  static const uint8_t zero_salt[crypto_auth_hmacsha256_KEYBYTES] = {0};
  if (salt == nullptr || salt_len == 0) {
    hmac(prk, zero_salt, sizeof zero_salt, ikm, ikm_len);
  } else {
    hmac(prk, salt, salt_len, ikm, ikm_len);
  }
}

void fallback_expand(uint8_t* out, std::size_t out_len, const char* info,
                     std::size_t info_len, const uint8_t prk[kPrkBytes]) {
  // T(i) = HMAC(PRK, T(i-1) || info || i), output = T(1) || T(2) || ...
  uint8_t block[crypto_auth_hmacsha256_BYTES];
  std::size_t produced = 0;
  uint8_t counter = 0;

  while (produced < out_len) {
    ++counter;
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, prk, kPrkBytes);
    if (counter > 1) {
      crypto_auth_hmacsha256_update(&state, block, sizeof block);
    }
    if (info_len > 0) {
      crypto_auth_hmacsha256_update(&state,
                                    reinterpret_cast<const uint8_t*>(info),
                                    info_len);
    }
    crypto_auth_hmacsha256_update(&state, &counter, 1);
    crypto_auth_hmacsha256_final(&state, block);
    sodium_memzero(&state, sizeof state);

    const std::size_t take =
        std::min(sizeof block, out_len - produced);
    std::memcpy(out + produced, block, take);
    produced += take;
  }
  sodium_memzero(block, sizeof block);
}

#endif  // !RATCHET_HAVE_SODIUM_HKDF

}  // namespace

void extract(Prk& prk, const uint8_t* salt, std::size_t salt_len,
             const uint8_t* ikm, std::size_t ikm_len) {
  init_sodium();
#ifdef RATCHET_HAVE_SODIUM_HKDF
  static_assert(kPrkBytes == crypto_kdf_hkdf_sha256_KEYBYTES,
                "HKDF-SHA256 PRK is one SHA-256 block");
  if (crypto_kdf_hkdf_sha256_extract(prk.data(), salt, salt_len, ikm,
                                     ikm_len) != 0) {
    throw Error("HKDF-Extract failed");
  }
#else
  fallback_extract(prk.data(), salt, salt_len, ikm, ikm_len);
#endif
}

void expand(uint8_t* out, std::size_t out_len, std::string_view info,
            const Prk& prk) {
  init_sodium();
  // RFC 5869 caps the output of one expansion at 255 hash blocks.
  if (out_len == 0 || out_len > 255 * kPrkBytes) {
    throw Error("HKDF-Expand: unsupported output length");
  }
#ifdef RATCHET_HAVE_SODIUM_HKDF
  if (crypto_kdf_hkdf_sha256_expand(out, out_len, info.data(), info.size(),
                                    prk.data()) != 0) {
    throw Error("HKDF-Expand failed");
  }
#else
  fallback_expand(out, out_len, info.data(), info.size(), prk.data());
#endif
}

bool using_libsodium_hkdf() {
#ifdef RATCHET_HAVE_SODIUM_HKDF
  return true;
#else
  return false;
#endif
}

}  // namespace ratchet::kdf
