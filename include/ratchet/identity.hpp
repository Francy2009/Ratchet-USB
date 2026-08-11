#ifndef RATCHET_IDENTITY_HPP
#define RATCHET_IDENTITY_HPP

#include <array>
#include <cstdint>
#include <string>

#include "ratchet/bip39.hpp"
#include "ratchet/secure.hpp"

namespace ratchet {

inline constexpr std::size_t kSeedBytes = 32;
inline constexpr std::size_t kX25519SecretBytes = 32;
inline constexpr std::size_t kX25519PublicBytes = 32;

using MasterSeed = SecureBytes<kSeedBytes>;
using IdentitySecretKey = SecureBytes<kX25519SecretBytes>;
using IdentityPublicKey = std::array<uint8_t, kX25519PublicBytes>;

// Domain separation strings. Changing any of these changes every key the tool
// derives, so they are versioned and must stay byte-stable across releases.
inline constexpr std::string_view kSeedSalt = "Ratchet-USB/v1/master-seed";
inline constexpr std::string_view kIdentityInfo = "Ratchet-USB/v1/identity-x25519";

// 128-bit mnemonic entropy -> 256-bit master seed, via HKDF-Extract.
//
// Note this is *not* the BIP-39 PBKDF2 seed derivation: the mnemonic here is a
// transcribable backup of the entropy, and the passphrase protects the vault
// rather than being mixed into the seed. Recovering from the 12 words alone is
// therefore enough to rebuild every key, with no passphrase involved.
void derive_master_seed(const bip39::Entropy& entropy, MasterSeed& out);

// Master seed -> long-term X25519 identity key pair. Deterministic: the same
// seed always yields the same pair, which is what makes the mnemonic a
// complete backup.
void derive_identity(const MasterSeed& seed, IdentitySecretKey& sk,
                     IdentityPublicKey& pk);

// Recomputes the public key from a stored private key, so `unlock` can show
// the identity without keeping the public half in the vault.
void identity_public_from_secret(const IdentitySecretKey& sk,
                                 IdentityPublicKey& pk);

// Lowercase hex, for displaying the public key. Public data only.
std::string to_hex(const uint8_t* data, std::size_t len);

}  // namespace ratchet

#endif  // RATCHET_IDENTITY_HPP
