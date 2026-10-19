#include "ratchet/app.hpp"

#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <string_view>
#include <utility>
#include <vector>

#include "ratchet/cli.hpp"
#include "ratchet/session.hpp"

namespace fs = std::filesystem;

namespace ratchet::app {

VaultFile read_vault(const fs::path& path) {
  VaultFile file;
  file.lock = vault::FileLock(path);
  file.path = path;
  file.bytes = vault::read_file(path);
  file.header = vault::parse_header(file.bytes.data(), file.bytes.size());
  file.digest = rollback::digest(file.bytes.data(), file.bytes.size());
  return file;
}

OpenedVault open_vault(VaultFile file, SecureString passphrase,
                       bool allow_legacy) {
  if (file.header.version == vault::kLegacyVersion && !allow_legacy) {
    throw Error("legacy vault requires `ratchet-usb migrate` before use");
  }
  SecureBuffer plaintext;
  vault::unseal(file.bytes.data(), file.bytes.size(), passphrase, plaintext);

  OpenedVault result;
  result.lock = std::move(file.lock);
  result.store = store::parse(plaintext.data(), plaintext.size());
  result.params = vault::Params{file.header.argon2_time_cost,
                                file.header.argon2_mem_cost_kb};
  result.passphrase = std::move(passphrase);
  result.vault_digest = file.digest;
  result.vault_version = file.header.version;
  const std::optional<rollback::AnchorRecord> anchor =
      rollback::load(result.store.vault_id);
  if (anchor) {
    bool validated = false;
    try {
      result.rollback_status =
          rollback::validate(*anchor, result.store, result.vault_digest);
      validated = true;
    } catch (const Error&) {
      // The drive is ahead of the host anchor. That is what a run of anchor
      // updates which never landed leaves behind -- a keyring outage, or a
      // crash between the vault write and the anchor write. Being *ahead* is
      // not the rollback the anchor exists to catch (that is the drive being
      // older than the anchor), so the anchor is advanced to the state in hand
      // instead of locking the vault out. Only an anchor that is genuinely ours
      // and behind the drive may be advanced: a failed tag or a foreign vault
      // still stands, so a forged anchor cannot be laundered into a valid one.
      if (!rollback::authentic_for(*anchor, result.store) ||
          result.store.generation <= anchor->generation) {
        throw;
      }
    }
    if (!validated ||
        result.rollback_status == rollback::Status::AdvancedAfterCrash) {
      // Refresh the anchor to the current drive. A keyring that can be read but
      // not written degrades to USB-only mode rather than failing the open.
      try {
        rollback::store(rollback::AnchorRecord{result.store.vault_id,
                                                result.store.generation,
                                                result.vault_digest},
                        result.store.seed);
        result.rollback_status = rollback::Status::Protected;
      } catch (const Error&) {
        result.rollback_status = rollback::Status::Unprotected;
      }
    }
  }
  return result;
}

void save_vault(const fs::path& path, store::VaultStore& store,
                const vault::Params& params, const SecureString& passphrase) {
  init_sodium();
  const bool id_missing =
      std::all_of(store.vault_id.begin(), store.vault_id.end(),
                  [](uint8_t b) { return b == 0; });
  if (id_missing) randombytes_buf(store.vault_id.data(), store.vault_id.size());
  std::error_code ec;
  std::optional<rollback::AnchorRecord> anchor;
  rollback::Digest previous_digest{};
  // A save keeps the vault's passphrase kind: a v3 vault stays v3 (one-line
  // password), a v4 vault stays v4 (word phrase). Only a brand-new file -- the
  // migration's prepared vault -- starts on the classic version.
  uint8_t version = vault::kVersion;
  if (fs::exists(path, ec)) {
    const std::vector<uint8_t> previous = vault::read_file(path);
    version = vault::parse_header(previous.data(), previous.size()).version;
    previous_digest = rollback::digest(previous.data(), previous.size());
    anchor = rollback::load(store.vault_id);
    if (anchor) {
      try {
        const rollback::Status status =
            rollback::validate(*anchor, store, previous_digest);
        if (status == rollback::Status::AdvancedAfterCrash) {
          rollback::store(rollback::AnchorRecord{store.vault_id, store.generation,
                                                  previous_digest},
                          store.seed);
        }
      } catch (const Error&) {
        // A drive ahead of an anchor that is genuinely ours is a lagging
        // anchor, not a rollback; the write below re-anchors to the new
        // generation, so there is nothing to correct here. A failed tag, a
        // foreign vault, or a drive that is behind or forked still stands.
        if (!rollback::authentic_for(*anchor, store) ||
            store.generation <= anchor->generation) {
          throw;
        }
      }
    }
    store.previous_digest = previous_digest;
  }
  if (store.generation == UINT64_MAX) {
    throw Error("vault generation counter exhausted");
  }
  ++store.generation;
  const SecureBuffer plaintext = store::serialize(store);
  const std::vector<uint8_t> file =
      vault::seal(plaintext, passphrase, params, version);
  vault::write_file(path, file, /*overwrite=*/true);
  if (anchor) {
    rollback::store(rollback::AnchorRecord{
                        store.vault_id, store.generation,
                        rollback::digest(file.data(), file.size())},
                    store.seed);
  }
}

void rekey_vault(const fs::path& path, store::VaultStore& store,
                 const vault::Params& params, const SecureString& new_passphrase) {
  init_sodium();
  const fs::path prepared = path.parent_path() / vault::kRekeyPreparedFilename;

  // The generation advances by one. That is what keeps the change recoverable
  // if the host anchor below cannot be written: on the next open the anchor is
  // seen to lag a vault that is genuinely ours and is advanced to the new
  // digest, instead of the digest mismatch being read as a rollback. It is
  // incremented before serialising so the written container and the anchor
  // agree.
  if (store.generation == UINT64_MAX) {
    throw Error("vault generation counter exhausted");
  }
  ++store.generation;

  const SecureBuffer plaintext = store::serialize(store);
  // A change of passphrase always installs a generated word phrase, so the new
  // container is stamped v4 whatever the old one was. This is also how an old
  // one-line-password vault moves to the word format.
  const std::vector<uint8_t> file =
      vault::seal(plaintext, new_passphrase, params, vault::kWordVersion);
  // Never over the original: write a sibling copy first. write_file is itself
  // atomic (temp + fsync + rename), so an interrupted write leaves no partial
  // prepared file, and it overwrites any leftover from an earlier attempt.
  vault::write_file(prepared, file, /*overwrite=*/true);

  // Verify the exact bytes just written before the original is replaced: they
  // must decrypt under the new passphrase and parse back to the same vault.
  const std::vector<uint8_t> written = vault::read_file(prepared);
  const vault::VaultHeader header =
      vault::parse_header(written.data(), written.size());
  if (header.version != vault::kWordVersion) {
    throw Error("re-encrypted vault is not a word-passphrase vault");
  }
  SecureBuffer reopened;
  vault::unseal(written.data(), written.size(), new_passphrase, reopened);
  const store::VaultStore verified = store::parse(reopened.data(), reopened.size());
  if (verified.vault_id != store.vault_id ||
      verified.generation != store.generation ||
      !verified.seed.equals(store.seed) ||
      verified.contacts.size() != store.contacts.size() ||
      verified.sessions.size() != store.sessions.size()) {
    throw Error("re-encrypted vault failed its identity check");
  }

  vault::promote_prepared(prepared, path);

  const rollback::Digest digest = rollback::digest(written.data(), written.size());
  if (rollback::backend_available()) {
    if (const auto anchor = rollback::load(store.vault_id)) {
      rollback::store(
          rollback::AnchorRecord{store.vault_id, store.generation, digest},
          store.seed);
    }
  }
}

void enroll_rollback_anchor(const OpenedVault& opened) {
  rollback::enroll(opened.store, opened.vault_digest);
}

fs::path validate_usb_path(const fs::path& usb_path) {
  std::error_code ec;
  const fs::path resolved = fs::canonical(usb_path, ec);
  if (ec) {
    throw Error("--usb-path does not exist: " + usb_path.string());
  }
  if (!fs::is_directory(resolved, ec)) {
    throw Error("--usb-path is not a directory: " + resolved.string());
  }
  if (::access(resolved.c_str(), W_OK | X_OK) != 0) {
    throw Error("--usb-path is not writable: " + resolved.string());
  }
  return resolved;
}

bool is_on_host_filesystem(const fs::path& usb_path) {
  const char* home = std::getenv("HOME");
  if (home == nullptr) {
    return false;
  }
  struct stat usb_st {};
  struct stat home_st {};
  if (::stat(usb_path.c_str(), &usb_st) != 0 || ::stat(home, &home_st) != 0) {
    return false;
  }
  return usb_st.st_dev == home_st.st_dev;
}

uint64_t age_seconds(uint64_t now, uint64_t stamped_at) {
  return now > stamped_at ? now - stamped_at : 0;
}

bool resign_stale_prekeys(store::VaultStore& store,
                          const IdentitySigningPublicKey& identity_pk,
                          const IdentitySigningSecretKey& identity_sk) {
  bool changed = false;
  for (prekey::SignedPrekey& spk : store.signed_prekeys) {
    if (!prekey::verify_signed_prekey_signature(identity_pk, spk.id, spk.pub,
                                                spk.signature)) {
      prekey::resign_signed_prekey(identity_sk, spk);
      changed = true;
    }
  }
  return changed;
}

void replenish_one_time_prekeys(store::VaultStore& store, std::size_t count) {
  std::vector<prekey::OneTimePrekey> fresh =
      prekey::generate_one_time_prekeys(store.next_otpk_id, count);
  store.next_otpk_id += static_cast<uint32_t>(count);
  for (auto& otpk : fresh) {
    store.one_time_prekeys.push_back(std::move(otpk));
  }
}

void replenish_pq_prekeys(store::VaultStore& store, std::size_t one_time_count) {
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  if (store.pq_signed_prekeys.empty()) {
    store::PqPrekey p;
    p.id = store.next_pq_prekey_id++;
    p.key = pq::generate_ml_kem_768();
    p.created_at = now;
    store.pq_signed_prekeys.push_back(std::move(p));
  }
  while (store.pq_one_time_prekeys.size() < one_time_count) {
    store::PqPrekey p;
    p.id = store.next_pq_prekey_id++;
    p.key = pq::generate_ml_kem_768();
    p.created_at = now;
    store.pq_one_time_prekeys.push_back(std::move(p));
  }
}

void rotate_signed_prekey(store::VaultStore& store,
                          const IdentitySigningSecretKey& identity_sk) {
  store.signed_prekeys.push_back(
      prekey::generate_signed_prekey(identity_sk, store.next_spk_id));
  store.next_spk_id += 1;
  // Keep only the newest two: a peer whose card we handed out just before
  // rotating might still send an initial message against the old one.
  while (store.signed_prekeys.size() > 2) {
    store.signed_prekeys.erase(store.signed_prekeys.begin());
  }
}

MaintenanceReport maintain_prekeys(store::VaultStore& store,
                                   const IdentitySigningPublicKey& identity_pk,
                                   const IdentitySigningSecretKey& identity_sk) {
  MaintenanceReport report;
  report.resigned = resign_stale_prekeys(store, identity_pk, identity_sk);

  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  const bool spk_stale =
      store.signed_prekeys.empty() ||
      age_seconds(now, store.signed_prekeys.back().created_at) > kSpkMaxAgeSeconds;
  if (spk_stale) {
    rotate_signed_prekey(store, identity_sk);
    report.spk_rotated = true;
  }

  if (store.one_time_prekeys.size() < kReplenishThreshold) {
    report.otpk_had = store.one_time_prekeys.size();
    replenish_one_time_prekeys(store, cli::kDefaultOtpkCount);
    report.otpk_added = cli::kDefaultOtpkCount;
  }

  return report;
}

std::size_t expire_skipped_keys(store::VaultStore& store) {
  return session::expire_skipped_keys(store);
}

void print_word_grid(const SecureString& phrase, std::ostream& os,
                     std::string_view heading, std::string_view note) {
  os << "\n" << heading << "\n\n";

  const std::string_view all(phrase.data(), phrase.size());
  std::vector<std::string_view> words;
  std::size_t pos = 0;
  while (pos <= all.size()) {
    const std::size_t space = all.find(' ', pos);
    const std::size_t end = (space == std::string_view::npos) ? all.size() : space;
    words.push_back(all.substr(pos, end - pos));
    if (space == std::string_view::npos) {
      break;
    }
    pos = space + 1;
  }

  constexpr std::size_t kCellWidth = 16;
  constexpr std::size_t kColumns = 4;
  std::size_t index = 1;
  for (std::size_t row = 0; row * kColumns < words.size(); ++row) {
    os << "  ";
    for (std::size_t col = 0; col < kColumns; ++col) {
      const std::size_t w = row * kColumns + col;
      if (w >= words.size()) {
        break;
      }
      const std::size_t digits = (index < 10) ? 1 : 2;
      os << index << ". " << words[w];
      ++index;
      // Pad to the column width without ever materialising the cell.
      for (std::size_t pad = digits + 2 + words[w].size(); pad < kCellWidth; ++pad) {
        os << ' ';
      }
    }
    os << "\n";
  }

  os << "\n" << note << "\n\n";
}

}  // namespace ratchet::app
