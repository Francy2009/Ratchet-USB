#ifndef RATCHET_ROLLBACK_HPP
#define RATCHET_ROLLBACK_HPP

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#include "ratchet/store.hpp"

namespace ratchet::rollback {

using Digest = std::array<uint8_t, 32>;

struct AnchorRecord {
  store::VaultId vault_id{};
  uint64_t generation = 0;
  Digest vault_digest{};
};

enum class Status {
  Protected,
  Unprotected,
  AdvancedAfterCrash,
};

Digest digest(const uint8_t* bytes, std::size_t size);
std::string vault_id_text(const store::VaultId& id);

// Validates the USB state against an already loaded host anchor. This pure
// function is intentionally public so rollback/crash-recovery invariants can
// be tested without a desktop keyring.
Status validate(const AnchorRecord& anchor, const store::VaultStore& usb,
                const Digest& usb_digest);

// The host backend is Secret Service on Linux and Keychain on macOS. A missing
// service is not silently treated as protection: load returns nullopt and the
// caller must expose USB-only mode to the user.
bool backend_available();
std::optional<AnchorRecord> load(const store::VaultId& vault_id);
void store(const AnchorRecord& record);

// Explicit first-host enrollment. The vault must already have been unlocked
// successfully; this never derives trust from unauthenticated file metadata.
void enroll(const store::VaultStore& usb, const Digest& usb_digest);

}  // namespace ratchet::rollback

#endif
