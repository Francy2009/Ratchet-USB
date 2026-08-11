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
}

void derive_identity(const MasterSeed& seed, IdentitySigningSecretKey& sk,
                     IdentitySigningPublicKey& pk) {
  init_sodium();
  static_assert(kdf::kPrkBytes == crypto_sign_SEEDBYTES,
               "an Ed25519 seed is one HKDF-Extract/Expand output");

  kdf::Prk seed_prk;
  seed_prk.assign(seed.data(), seed.size());

  SecureBytes<crypto_sign_SEEDBYTES> ed_seed;
  kdf::expand(ed_seed.data(), ed_seed.size(), kIdentityEdSeedInfo, seed_prk);

  if (crypto_sign_seed_keypair(pk.data(), sk.data(), ed_seed.data()) != 0) {
    throw Error("Ed25519 identity derivation failed");
  }
}

void identity_dh_keypair(const IdentitySigningSecretKey& ed_sk,
                         const IdentitySigningPublicKey& ed_pk,
                         IdentityDHSecretKey& dh_sk, IdentityDHPublicKey& dh_pk) {
  init_sodium();
  if (crypto_sign_ed25519_sk_to_curve25519(dh_sk.data(), ed_sk.data()) != 0) {
    throw Error("Ed25519 to X25519 secret key conversion failed");
  }
  if (crypto_sign_ed25519_pk_to_curve25519(dh_pk.data(), ed_pk.data()) != 0) {
    throw Error("Ed25519 to X25519 public key conversion failed");
  }
}

void identity_dh_public(const IdentitySigningPublicKey& ed_pk,
                        IdentityDHPublicKey& dh_pk) {
  init_sodium();
  if (crypto_sign_ed25519_pk_to_curve25519(dh_pk.data(), ed_pk.data()) != 0) {
    throw Error("Ed25519 to X25519 public key conversion failed");
  }
}

void sign(const IdentitySigningSecretKey& sk, const uint8_t* msg,
         std::size_t msg_len, Signature& sig) {
  init_sodium();
  if (crypto_sign_detached(sig.data(), nullptr, msg, msg_len, sk.data()) != 0) {
    throw Error("Ed25519 signing failed");
  }
}

bool verify(const IdentitySigningPublicKey& pk, const uint8_t* msg,
           std::size_t msg_len, const Signature& sig) {
  init_sodium();
  return crypto_sign_verify_detached(sig.data(), msg, msg_len, pk.data()) == 0;
}

std::string to_hex(const uint8_t* data, std::size_t len) {
  std::string hex(len * 2 + 1, '\0');
  sodium_bin2hex(hex.data(), hex.size(), data, len);
  hex.resize(len * 2);
  return hex;
}

std::string fingerprint(const IdentitySigningPublicKey& pk) {
  const std::string hex = to_hex(pk.data(), pk.size());
  std::string out;
  for (std::size_t i = 0; i < hex.size(); i += 4) {
    if (i > 0) {
      out += (i % 16 == 0) ? '\n' : ' ';
    }
    out += hex.substr(i, 4);
  }
  return out;
}

}  // namespace ratchet
