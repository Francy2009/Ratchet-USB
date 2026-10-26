#include "ratchet/command_io.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/identity.hpp"
#include "ratchet/media.hpp"
#include "ratchet/ratchet.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/terminal.hpp"
#include "ratchet/vault.hpp"

namespace fs = std::filesystem;

namespace ratchet::commands {

using app::OpenedVault;
using cli::Options;
using cli::kProgram;

// Only for the message `unlock` prints; the expiry rule itself lives in
// ratchet::kSkippedKeyMaxAgeSeconds.
constexpr uint64_t kSkippedKeyMaxAgeDays =
    ::ratchet::ratchet::kSkippedKeyMaxAgeDays;

namespace {

// Asks the user to pick one of `choices`, or returns an empty path if there is
// no terminal to ask on or the answer was not a choice.
fs::path choose_drive(const std::vector<fs::path>& choices, const char* what) {
  if (choices.empty() || !terminal::stdin_is_tty()) {
    return {};
  }

  if (choices.size() == 1) {
    std::cerr << "Found a removable drive " << what << ":\n  "
              << choices.front().string() << "\n";
    const std::string answer = terminal::read_line("Use it? [Y/n] ");
    if (answer.empty() || answer == "y" || answer == "Y" || answer == "yes") {
      return choices.front();
    }
    return {};
  }

  std::cerr << "Several removable drives " << what << ":\n";
  for (std::size_t i = 0; i < choices.size(); ++i) {
    std::cerr << "  " << (i + 1) << ") " << choices[i].string() << "\n";
  }
  const std::string answer = terminal::read_line("Which one? [1-" +
                                                 std::to_string(choices.size()) +
                                                 "] ");
  std::size_t pick = 0;
  const auto result =
      std::from_chars(answer.data(), answer.data() + answer.size(), pick);
  if (result.ec != std::errc() || pick < 1 || pick > choices.size()) {
    return {};
  }
  return choices[pick - 1];
}

}  // namespace

fs::path require_usb_path(const Options& opts, bool for_init) {
  fs::path usb_path = opts.usb_path;
  bool auto_detected = false;

  if (usb_path.empty()) {
    if (const char* env = std::getenv("RATCHET_USB_PATH");
        env != nullptr && env[0] != '\0') {
      usb_path = fs::path(env);
    }
  }

  if (usb_path.empty()) {
    const std::vector<fs::path> candidates =
        for_init ? media::removable_drives() : media::drives_with_vault();
    usb_path = choose_drive(candidates, for_init ? "to set up" : "with a vault");
    auto_detected = !usb_path.empty();
  }

  if (usb_path.empty()) {
    const std::string entered = terminal::read_line("USB drive path: ");
    if (!entered.empty()) {
      usb_path = fs::path(entered);
    }
  }

  if (usb_path.empty()) {
    throw Error("--usb-path is required (or set RATCHET_USB_PATH)");
  }

  // The directory is created only when its parent is a mounted removable drive.
  // A bare typo cannot reach this: it would have to name a subdirectory of a
  // drive the user has actually plugged in.
  std::error_code ec;
  if (for_init && !fs::exists(usb_path, ec)) {
    const fs::path parent = usb_path.parent_path();
    const std::vector<fs::path> drives = media::removable_drives();
    if (!parent.empty() &&
        std::find(drives.begin(), drives.end(), parent) != drives.end()) {
      if (!fs::create_directory(usb_path, ec) || ec) {
        throw Error("cannot create " + usb_path.string());
      }
      std::cerr << "Created " << usb_path.string() << "\n";
    }
  }

  const fs::path resolved = app::validate_usb_path(usb_path);
  if (auto_detected) {
    std::cerr << "Using " << resolved.string() << "\n";
  }
  return resolved;
}

void warn_if_host_disk(const fs::path& usb_path) {
  if (app::is_on_host_filesystem(usb_path)) {
    std::cerr << "warning: " << usb_path.string()
              << " is on the same filesystem as your home directory.\n"
              << "warning: the vault is meant to live on a removable drive.\n";
  }
}

std::string require_value(const std::string& value, const std::string& prompt,
                          const char* flag_error) {
  if (!value.empty()) {
    return value;
  }
  const std::string entered = terminal::read_line(prompt);
  if (entered.empty()) {
    throw Error(flag_error);
  }
  return entered;
}

OpenedVault unlock_vault(const fs::path& path, const std::string& label) {
  const fs::path prepared = path.parent_path() / vault::kPreparedVaultFilename;
  if (fs::exists(prepared)) {
    throw Error("a verified migration is waiting for commit; run `" +
                std::string(kProgram) + " migrate --commit --usb-path <dir>`");
  }
  // The container is read and validated before the prompt, so a path that
  // holds no vault says so instead of asking for a passphrase first -- and so
  // the vault's version can decide which prompt is the right one.
  app::VaultFile file = app::read_vault(path);
  if (file.header.version == vault::kLegacyVersion) {
    throw Error("legacy vault requires `" + std::string(kProgram) +
                " migrate` before use");
  }
  SecureString passphrase;
  if (vault::uses_word_passphrase(file.header.version)) {
    passphrase = terminal::read_word_phrase(
        label + " (one word per line; empty line to finish): ");
  } else {
    // v3 and older: a passphrase the user typed on a single line. Enter
    // confirms, exactly as it always has.
    passphrase = terminal::read_passphrase(label + ": ");
  }
  std::cerr << "Deriving the vault key with Argon2id...\n";
  OpenedVault opened = app::open_vault(std::move(file), std::move(passphrase));
  if (opened.rollback_status == rollback::Status::Unprotected) {
    std::cerr << "SECURITY WARNING: rollback protection is not enrolled on "
                 "this host.\nRun `"
              << kProgram << " anchor --usb-path <dir>` after verifying this "
                 "USB state.\n";
  }
  return opened;
}

std::string read_bounded(std::istream& input, std::size_t max_bytes,
                         const char* what) {
  std::string out;
  StringWipe wipe(out);
  out.reserve(std::min<std::size_t>(max_bytes, std::size_t{64} * 1024u));
  std::array<char, 8192> chunk{};
  while (input) {
    input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    const std::size_t got = static_cast<std::size_t>(input.gcount());
    if (got > max_bytes - out.size()) {
      throw Error(std::string(what) + " exceeds its input size limit");
    }
    // A pipe's length is not known up front, so this string can reallocate.
    // append_string_wiped zeroes the previous block before releasing it: a
    // message typed into stdin is plaintext, and the old block used to stay
    // readable on the heap until the allocator reused it.
    append_string_wiped(out, std::string_view(chunk.data(), got));
  }
  wipe.dismiss();
  return out;
}

std::string read_exact(std::istream& input, std::size_t bytes, const char* what) {
  if (bytes > static_cast<std::size_t>(
                  std::numeric_limits<std::streamsize>::max())) {
    throw Error(std::string(what) + " is too large to read");
  }
  std::string out;
  out.resize(bytes);
  // The guard covers a short read, an I/O exception and the pathological case
  // where the caller asked for a length the stream never supplies.
  StringWipe wipe(out);
  std::size_t got = 0;
  while (got < bytes) {
    input.read(out.data() + got,
               static_cast<std::streamsize>(bytes - got));
    const std::streamsize chunk = input.gcount();
    if (chunk <= 0) {
      throw Error(std::string(what) +
                  " ended before its declared length");
    }
    got += static_cast<std::size_t>(chunk);
  }
  wipe.dismiss();
  return out;
}

std::string read_text_arg_or_stdin(const std::optional<std::string>& arg,
                                   const char* prompt_if_tty,
                                   std::size_t max_bytes) {
  if (arg) {
    if (arg->size() > max_bytes) throw Error("input exceeds its size limit");
    return *arg;
  }
  if (terminal::stdin_is_tty()) {
    std::cerr << prompt_if_tty << std::flush;
  }
  return read_bounded(std::cin, max_bytes, "input");
}

std::string read_file_text(const std::string& path, std::size_t max_bytes) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw Error("cannot open " + path);
  }
  return read_bounded(in, max_bytes, "file");
}

bool maintain_prekeys(store::VaultStore& store,
                      const IdentitySigningPublicKey& identity_pk,
                      const IdentitySigningSecretKey& identity_sk) {
  const app::MaintenanceReport report =
      app::maintain_prekeys(store, identity_pk, identity_sk);
  if (report.spk_rotated) {
    std::cout << "Signed prekey was older than " << app::kSpkMaxAgeDays
              << " days; rotated it automatically.\n";
  }
  if (report.otpk_added > 0) {
    std::cout << "Only " << report.otpk_had
              << " one-time prekey(s) were left; replenished "
              << report.otpk_added << " automatically.\n";
  }
  return report.changed();
}

bool expire_skipped_keys(store::VaultStore& store) {
  const std::size_t dropped = app::expire_skipped_keys(store);
  if (dropped > 0) {
    std::cout << "Dropped " << dropped << " skipped message key(s) unclaimed for\n"
              << "more than " << kSkippedKeyMaxAgeDays
              << " days; those messages can no longer be decrypted.\n";
  }
  return dropped > 0;
}

}  // namespace ratchet::commands
