#include "ratchet/x25519.hpp"

#include <sodium.h>

namespace ratchet::x25519 {

void generate_keypair(SecretKey& sk, PublicKey& pk) {
  init_sodium();
  static_assert(kPublicBytes == crypto_box_PUBLICKEYBYTES);
  static_assert(kSecretBytes == crypto_box_SECRETKEYBYTES);
  if (crypto_box_keypair(pk.data(), sk.data()) != 0) {
    throw Error("X25519 keypair generation failed");
  }
}

void dh(const SecretKey& sk, const PublicKey& pk, SecureBytes<32>& out) {
  init_sodium();
  if (crypto_scalarmult(out.data(), sk.data(), pk.data()) != 0) {
    throw Error(
        "X25519 Diffie-Hellman failed (the peer's public key may be a "
        "low-order point)");
  }
}

}  // namespace ratchet::x25519
