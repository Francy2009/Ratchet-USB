#ifndef RATCHET_VAULT_HPP
#define RATCHET_VAULT_HPP

#include <sodium.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <vector>

#include "ratchet/secure.hpp"

namespace ratchet::vault {

// On-disk layout of vault.bin:
//
//   VaultHeader (41 bytes, little-endian, no padding)
//   ciphertext  (the serialised VaultStore, see store.hpp)
//   Poly1305 tag(16 bytes)
//
// The header is serialised field by field rather than written as a raw struct:
// the in-memory struct carries alignment padding that would otherwise leak into
// the file and make the format compiler-dependent. The whole serialised header
// is fed to the AEAD as additional data, so flipping a bit in the salt, the
// nonce or the Argon2 cost parameters makes decryption fail instead of quietly
// deriving a different key.
struct VaultHeader {
  uint8_t magic[4];  // "RCHT"
  uint8_t version;
  uint8_t argon2_salt[16];
  uint32_t argon2_time_cost;
  uint32_t argon2_mem_cost_kb;
  uint8_t nonce[12];
};

inline constexpr std::array<uint8_t, 4> kMagic = {'R', 'C', 'H', 'T'};
// v1 held a fixed 64-byte seed+identity-key pair; v2 holds the full store
// (prekeys, contacts, sessions), serialised to a variable length.
inline constexpr uint8_t kVersion = 2;

inline constexpr std::size_t kHeaderBytes = 4 + 1 + 16 + 4 + 4 + 12;  // 41
inline constexpr std::size_t kTagBytes = crypto_aead_chacha20poly1305_ietf_ABYTES;

inline constexpr const char* kVaultFilename = "vault.bin";

// Argon2id cost bounds. The upper bounds exist because the parameters are read
// back from an attacker-supplied file: without them, a doctored header could
// make `unlock` try to allocate an absurd amount of memory.
inline constexpr uint32_t kMinTimeCost = 1;
inline constexpr uint32_t kMaxTimeCost = 64;
inline constexpr uint32_t kMinMemCostKb = 8;             // libsodium's floor
inline constexpr uint32_t kMaxMemCostKb = 4u * 1024 * 1024;  // 4 GiB

// Defaults, roughly libsodium's "moderate" profile: ~256 MiB, 3 passes.
inline constexpr uint32_t kDefaultTimeCost = 3;
inline constexpr uint32_t kDefaultMemCostKb = 256 * 1024;

struct Params {
  uint32_t time_cost = kDefaultTimeCost;
  uint32_t mem_cost_kb = kDefaultMemCostKb;
};

// Serialises a header into exactly kHeaderBytes bytes (little-endian).
std::vector<uint8_t> serialize_header(const VaultHeader& header);

// Parses and validates a header: magic, version and cost bounds. Throws Error
// on anything unexpected.
VaultHeader parse_header(const uint8_t* data, std::size_t len);

// Encrypts arbitrary-length `plaintext` (the serialised VaultStore) under
// `passphrase` and returns the complete file image. A fresh Argon2id salt and
// AEAD nonce are drawn for every call, so sealing the same plaintext twice
// never produces the same bytes.
std::vector<uint8_t> seal(const SecureBuffer& plaintext,
                          const SecureString& passphrase, const Params& params);

// Reverse of seal(). Throws Error if the passphrase is wrong or the file has
// been altered in any way; the two cases are deliberately indistinguishable.
void unseal(const uint8_t* data, std::size_t len, const SecureString& passphrase,
           SecureBuffer& out);

// vault.bin inside the given USB directory. This is the only path the tool
// ever reads or writes secrets from.
std::filesystem::path vault_path(const std::filesystem::path& usb_path);

// Writes the vault to `path` with mode 0600, via a temporary file in the same
// directory plus fsync and rename, so an interrupted write cannot leave a
// half-written vault behind. Refuses to clobber an existing file unless
// `overwrite` is set.
void write_file(const std::filesystem::path& path, const std::vector<uint8_t>& bytes,
                bool overwrite);

// Reads a vault file, rejecting anything shorter than a header plus an AEAD
// tag -- the smallest a valid vault could ever be.
std::vector<uint8_t> read_file(const std::filesystem::path& path);

}  // namespace ratchet::vault

#endif  // RATCHET_VAULT_HPP
