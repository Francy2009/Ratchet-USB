#ifndef RATCHET_IDENTITY_HPP
#define RATCHET_IDENTITY_HPP

#include <array>
#include <cstdint>
#include <string>

#include "ratchet/bip39.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/x25519.hpp"

namespace ratchet {

inline constexpr std::size_t kSeedBytes = 32;
using MasterSeed = SecureBytes<kSeedBytes>;

inline constexpr std::size_t kEdSecretBytes = 64;    // crypto_sign_SECRETKEYBYTES
inline constexpr std::size_t kEdPublicBytes = 32;    // crypto_sign_PUBLICKEYBYTES
inline constexpr std::size_t kEdSignatureBytes = 64;  // crypto_sign_BYTES

using IdentitySigningSecretKey = SecureBytes<kEdSecretBytes>;
using IdentitySigningPublicKey = std::array<uint8_t, kEdPublicBytes>;
using Signature = std::array<uint8_t, kEdSignatureBytes>;

using IdentityDHSecretKey = x25519::SecretKey;
using IdentityDHPublicKey = x25519::PublicKey;

inline constexpr std::string_view kSeedSalt = "Ratchet-USB/v1/master-seed";
inline constexpr std::string_view kIdentityEdSeedInfo =
    "Ratchet-USB/v1/identity-ed25519-seed";

// 128-bit mnemonic entropy -> 256-bit master seed, via HKDF-Extract.
void derive_master_seed(const bip39::Entropy& entropy, MasterSeed& out);

// The long-term identity: an Ed25519 keypair, deterministic from the seed.
// Both signing (for the signed prekey) and Diffie-Hellman (for X3DH) need a
// key, and X25519 cannot sign; Ed25519 can do both, by converting it to its
// birationally equivalent Montgomery form for DH (identity_dh_keypair below).
// One key pair, one fingerprint to verify, one thing the mnemonic backs up.
void derive_identity(const MasterSeed& seed, IdentitySigningSecretKey& sk,
                     IdentitySigningPublicKey& pk);

// Converts the Ed25519 identity to the X25519 keypair X3DH's Diffie-Hellman
// steps run on.
void identity_dh_keypair(const IdentitySigningSecretKey& ed_sk,
                         const IdentitySigningPublicKey& ed_pk,
                         IdentityDHSecretKey& dh_sk, IdentityDHPublicKey& dh_pk);

// Same conversion for a public key alone, e.g. a contact's identity key.
void identity_dh_public(const IdentitySigningPublicKey& ed_pk,
                        IdentityDHPublicKey& dh_pk);

void sign(const IdentitySigningSecretKey& sk, const uint8_t* msg,
         std::size_t msg_len, Signature& sig);

bool verify(const IdentitySigningPublicKey& pk, const uint8_t* msg,
           std::size_t msg_len, const Signature& sig);

std::string to_hex(const uint8_t* data, std::size_t len);

// A human-checkable fingerprint of an identity public key: its hex form,
// grouped for reading aloud over a call. This shows the raw key rather than a
// hash of it -- at 32 bytes there is nothing a hash of it would buy over
// showing the key itself, and one fewer thing to get subtly wrong.
std::string fingerprint(const IdentitySigningPublicKey& pk);

}  // namespace ratchet

#endif  // RATCHET_IDENTITY_HPP
