#ifndef RATCHET_ROLLBACK_HPP
#define RATCHET_ROLLBACK_HPP

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "ratchet/store.hpp"

namespace ratchet::rollback {

using Digest = std::array<uint8_t, 32>;

struct AnchorRecord {
  store::VaultId vault_id{};
  uint64_t generation = 0;
  Digest vault_digest{};
  // False only for a legacy RANCHOR1 record, which has no tag. store() sets
  // this and fills mac before writing. The tag is not a secret. load() never
  // returns an unauthenticated record and validate() refuses one, so a legacy
  // anchor can never be trusted by accident.
  bool authenticated = false;
  std::array<uint8_t, 32> mac{};
};

enum class Status : uint8_t {
  Protected,
  Unprotected,
  AdvancedAfterCrash,
};

Digest digest(const uint8_t* bytes, std::size_t size);
std::string vault_id_text(const store::VaultId& id);

// Validates the USB state against an already loaded host anchor. This pure
// function is intentionally public so rollback/crash-recovery invariants can
// be tested without a desktop keyring. The record must be authenticated: an
// unauthenticated (legacy) record is refused, because generation-only checks
// are forgeable by anyone able to write the host anchor store.
Status validate(const AnchorRecord& anchor, const store::VaultStore& usb,
                const Digest& usb_digest);

// Attaches an HMAC-SHA256 tag derived from the vault master seed. The MAC
// input is the RANCHOR2 prefix, so a legacy blob cannot be replayed as a
// signed record.
void authenticate(AnchorRecord& record, const MasterSeed& seed);

std::string encode(const AnchorRecord& record);
AnchorRecord decode(std::string_view text);

// The host backend is Secret Service. A missing
// service is not silently treated as protection: load returns nullopt and the
// caller must expose USB-only mode to the user. A legacy, unauthenticated
// record is returned as nullopt too, so it is never trusted.
bool backend_available();
std::optional<AnchorRecord> load(const store::VaultId& vault_id);

// Always writes an authenticated record. `seed` is the vault master seed and
// does not leave the vault; the host service stores only the tag.
void store(const AnchorRecord& record, const MasterSeed& seed);

// Explicit first-host enrollment. The vault must already have been unlocked
// successfully; this never derives trust from unauthenticated file metadata.
void enroll(const store::VaultStore& usb, const Digest& usb_digest);

}  // namespace ratchet::rollback

#endif
