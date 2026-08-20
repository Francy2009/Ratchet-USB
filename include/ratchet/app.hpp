#ifndef RATCHET_APP_HPP
#define RATCHET_APP_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ostream>
#include <string>
#include <vector>

#include "ratchet/identity.hpp"
#include "ratchet/prekey.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/store.hpp"
#include "ratchet/vault.hpp"

// The operations a front end performs on a vault, with no front end in them.
//
// These used to live in the anonymous namespace of main.cpp, which was fine
// while the command line was the only way in. It is not any more: the terminal
// interface in ui.cpp needs the same open-modify-reseal sequence, and two
// copies of the code that decides when a prekey is stale is exactly the kind of
// duplication that ends with the two of them disagreeing.
//
// Nothing here prompts, and nothing here prints except where an ostream is
// passed in explicitly. A full-screen interface cannot have a library writing
// to stdout behind its back, so anything a caller might want to report is
// returned rather than printed.
namespace ratchet::app {

// Below this many one-time prekeys left, the pool gets topped back up.
inline constexpr std::size_t kReplenishThreshold = 5;
// How long a signed prekey is trusted before it is rotated automatically.
inline constexpr uint64_t kSpkMaxAgeDays = 30;
inline constexpr uint64_t kSpkMaxAgeSeconds = kSpkMaxAgeDays * 24 * 60 * 60;

// A vault as it sits on the drive: the raw bytes and the parsed header. Split
// out from opening it so a caller can find out whether a path holds a real
// vault -- and fail on a truncated or corrupt one -- before asking anybody for
// a passphrase.
struct VaultFile {
  std::vector<uint8_t> bytes;
  vault::VaultHeader header{};
};

// Reads and validates the container. Throws Error if the file is missing, too
// short, or does not carry the magic and a supported version.
VaultFile read_vault(const std::filesystem::path& path);

struct OpenedVault {
  store::VaultStore store;
  vault::Params params;     // reused on save, so a re-seal keeps the original cost
  SecureString passphrase;  // held so a mutating command only has to ask once
};

// Derives the key with Argon2id, unseals and parses. Throws Error on a wrong
// passphrase -- deliberately the same error a tampered file gives.
OpenedVault open_vault(const VaultFile& file, SecureString passphrase);

void save_vault(const std::filesystem::path& path, const store::VaultStore& store,
                const vault::Params& params, const SecureString& passphrase);

// Canonicalises `usb_path` and checks it is a directory this user can write
// to. Throws Error naming the problem otherwise.
std::filesystem::path validate_usb_path(const std::filesystem::path& usb_path);

// Whether `usb_path` sits on the same filesystem as the user's home directory,
// which usually means it is the host disk rather than a removable drive. Best
// effort: a mount layout cannot be told apart from a removable one with
// certainty, so the callers warn rather than refuse.
bool is_on_host_filesystem(const std::filesystem::path& usb_path);

// Seconds elapsed since `stamped_at`, saturating at zero.
//
// Both operands are unsigned, so a timestamp in the future -- a clock that
// went backwards, a drive carried to a machine whose clock is wrong -- makes
// the plain subtraction wrap to something enormous. Where that fed a
// "is this too old?" test the answer came back yes, every time.
uint64_t age_seconds(uint64_t now, uint64_t stamped_at);

// Re-signs any stored prekey whose signature does not verify under the current
// scheme. A vault written before the signature covered a context string and
// the prekey id has perfectly good key pairs and stale signatures; rotating
// them instead would invalidate every card already handed out, for no reason.
bool resign_stale_prekeys(store::VaultStore& store,
                          const IdentitySigningPublicKey& identity_pk,
                          const IdentitySigningSecretKey& identity_sk);

// What maintain_prekeys did, so the caller can report it in its own way.
struct MaintenanceReport {
  bool resigned = false;
  bool spk_rotated = false;
  std::size_t otpk_had = 0;    // how many were left before topping up
  std::size_t otpk_added = 0;  // zero when the pool was healthy
  bool changed() const { return resigned || spk_rotated || otpk_added > 0; }
};

// Rotates the signed prekey once it has aged past kSpkMaxAgeDays, and tops the
// one-time prekey pool back up when it drops below kReplenishThreshold.
MaintenanceReport maintain_prekeys(store::VaultStore& store,
                                   const IdentitySigningPublicKey& identity_pk,
                                   const IdentitySigningSecretKey& identity_sk);

// Adds `count` fresh one-time prekeys, advancing the id counter.
void replenish_one_time_prekeys(store::VaultStore& store, std::size_t count);

// Generates a new signed prekey and keeps only the newest two: a peer who
// grabbed the card just before rotation may still send against the old one.
void rotate_signed_prekey(store::VaultStore& store,
                          const IdentitySigningSecretKey& identity_sk);

// Throws away every skipped message key nobody claimed in time, returning how
// many were dropped. `session::receive` already does this for the session it
// touches; this is the sweep a vault that is only ever opened still needs.
std::size_t expire_skipped_keys(store::VaultStore& store);

// Writes the 12 words as a numbered grid.
//
// The mnemonic arrives in a SecureString and must not leave it. The words are
// referred to as string_views into that buffer and streamed straight out, so
// no copy of a recovery word is made that the caller cannot wipe -- which is
// exactly what building padded cells as std::string used to do. It is also why
// this writes to a stream rather than returning lines: a returned
// vector<string> would be that copy.
void print_mnemonic(const SecureString& mnemonic, std::ostream& os);

}  // namespace ratchet::app

#endif  // RATCHET_APP_HPP
