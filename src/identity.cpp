#include "ratchet/identity.hpp"

#include <sodium.h>

#include "ratchet/kdf.hpp"

namespace ratchet {

void derive_master_seed(const bip39::Entropy& entropy, MasterSeed& out) {
  init_sodium();
  static_assert(kSeedBytes == kdf::kPrkBytes,
                "the master seed is one HKDF-Extract output");

  kdf::Prk prk;
  kdf::extract(prk, reinterpret_cast<const uint8_t*>(kSeedSalt.data()),
               kSeedSalt.size(), entropy.data(), entropy.size());
  out.assign(prk.data(), prk.size());
  // prk wipes itself on scope exit.
}

void derive_identity(const MasterSeed& seed, IdentitySecretKey& sk,
                     IdentityPublicKey& pk) {
  init_sodium();
  static_assert(kX25519SecretBytes == crypto_scalarmult_curve25519_SCALARBYTES,
                "identity secret key is an X25519 scalar");

  // The master seed is already a uniformly random PRK, so it is used directly
  // as the HKDF-Expand key with an info string that pins this output to the
  // identity key. Later phases (X3DH prekeys, ratchet root key) get their own
  // info strings from the same seed.
  kdf::Prk prk;
  prk.assign(seed.data(), seed.size());
  kdf::expand(sk.data(), sk.size(), kIdentityInfo, prk);

  // crypto_scalarmult_base clamps internally, but clamping here too means the
  // stored scalar is exactly the one that will be used, so the private key on
  // disk and the key in memory can never disagree.
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;

  identity_public_from_secret(sk, pk);
}

void identity_public_from_secret(const IdentitySecretKey& sk,
                                 IdentityPublicKey& pk) {
  init_sodium();
  if (crypto_scalarmult_base(pk.data(), sk.data()) != 0) {
    throw Error("X25519 public key derivation failed");
  }
}

std::string to_hex(const uint8_t* data, std::size_t len) {
  std::string hex(len * 2 + 1, '\0');
  sodium_bin2hex(hex.data(), hex.size(), data, len);
  hex.resize(len * 2);
  return hex;
}

}  // namespace ratchet
