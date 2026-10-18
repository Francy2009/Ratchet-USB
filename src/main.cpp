// Ratchet-USB -- hybrid PQXDH identity/handshake migration in progress.
//
// Everything sensitive lives on the removable drive passed as --usb-path;
// nothing is ever written to the host's filesystem.

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/app.hpp"
#include "ratchet/bip39.hpp"
#include "ratchet/cli.hpp"
#include "ratchet/i18n.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/media.hpp"
#include "ratchet/file.hpp"
#include "ratchet/ratchet.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/session.hpp"
#include "ratchet/screen.hpp"
#include "ratchet/store.hpp"
#include "ratchet/terminal.hpp"
#include "ratchet/ui.hpp"
#include "ratchet/vault.hpp"
#include "ratchet/x3dh.hpp"

namespace fs = std::filesystem;
using namespace ratchet;

namespace {

using cli::kDefaultOtpkCount;
using cli::kProgram;
using cli::Options;

using app::kReplenishThreshold;
using app::kSpkMaxAgeDays;
// Only for the message `unlock` prints; the expiry rule itself lives in
// ratchet::kSkippedKeyMaxAgeSeconds.
constexpr uint64_t kSkippedKeyMaxAgeDays =
    ::ratchet::ratchet::kSkippedKeyMaxAgeDays;

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

// Where the vault lives. Resolved in this order: --usb-path, the
// RATCHET_USB_PATH environment variable, an auto-detected removable drive, and
// finally a prompt.
//
// `for_init` splits the two questions being asked. Every other command wants a
// drive that already holds a vault, so a single match can be offered straight
// away. `init` is about to write, so it looks at removable drives generally and
// always asks before touching one -- guessing would be the one mistake this
// tool cannot afford.
fs::path require_usb_path(const Options& opts, bool for_init = false) {
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

// Falls back to an interactive prompt for a required, non-secret value (an
// alias, a contact name) when it was not passed as a flag and stdin is a
// terminal; throws flag_error otherwise.
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

// Best-effort warning when the given path sits on the same filesystem as the
// user's home directory, which usually means it is the host disk rather than a
// removable drive. It stays a warning: a mount layout cannot be told apart
// from a removable one with certainty.
void warn_if_host_disk(const fs::path& usb_path) {
  if (app::is_on_host_filesystem(usb_path)) {
    std::cerr << "warning: " << usb_path.string()
              << " is on the same filesystem as your home directory.\n"
              << "warning: the vault is meant to live on a removable drive.\n";
  }
}

// --- vault open/save helpers ------------------------------------------------

using app::OpenedVault;

OpenedVault unlock_vault(const fs::path& path,
                         const char* prompt = "Vault passphrase: ") {
  const fs::path prepared = path.parent_path() / vault::kPreparedVaultFilename;
  if (fs::exists(prepared)) {
    throw Error("a verified migration is waiting for commit; run `" +
                std::string(kProgram) + " migrate --commit --usb-path <dir>`");
  }
  // The container is read and validated before the prompt, so a path that
  // holds no vault says so instead of asking for a passphrase first.
  app::VaultFile file = app::read_vault(path);
  SecureString passphrase = terminal::read_passphrase(prompt);
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
  out.reserve(std::min<std::size_t>(max_bytes, std::size_t{64} * 1024u));
  std::array<char, 8192> chunk{};
  while (input) {
    input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    const std::size_t got = static_cast<std::size_t>(input.gcount());
    if (got > max_bytes - out.size()) {
      throw Error(std::string(what) + " exceeds its input size limit");
    }
    out.append(chunk.data(), got);
  }
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

// Runs the automatic maintenance and prints what it did, in the wording
// `unlock` has always used. The decisions themselves live in app.cpp, so the
// terminal interface applies exactly the same rules.
bool maintain_prekeys(store::VaultStore& store,
                      const IdentitySigningPublicKey& identity_pk,
                      const IdentitySigningSecretKey& identity_sk) {
  const app::MaintenanceReport report =
      app::maintain_prekeys(store, identity_pk, identity_sk);
  if (report.spk_rotated) {
    std::cout << "Signed prekey was older than " << kSpkMaxAgeDays
              << " days; rotated it automatically.\n";
  }
  if (report.otpk_added > 0) {
    std::cout << "Only " << report.otpk_had
              << " one-time prekey(s) were left; replenished "
              << report.otpk_added << " automatically.\n";
  }
  return report.changed();
}

// Throws away skipped message keys nobody claimed in time. `recv` already
// does this for the session it touches, but a vault that is only ever opened
// would keep them indefinitely, so `unlock` sweeps all of them. Returns
// whether anything was dropped (and so whether the store needs saving).
bool expire_skipped_keys(store::VaultStore& store) {
  const std::size_t dropped = app::expire_skipped_keys(store);
  if (dropped > 0) {
    std::cout << "Dropped " << dropped << " skipped message key(s) unclaimed for\n"
              << "more than " << kSkippedKeyMaxAgeDays
              << " days; those messages can no longer be decrypted.\n";
  }
  return dropped > 0;
}

// --- commands ----------------------------------------------------------------

int cmd_init(const Options& opts) {
  const fs::path usb = require_usb_path(opts, /*for_init=*/true);
  warn_if_host_disk(usb);

  const fs::path path = vault::vault_path(usb);
  if (!opts.force && fs::exists(path)) {
    throw Error("a vault already exists at " + path.string() +
               " (pass --force to replace it)");
  }
  vault::FileLock init_lock(path);

  bip39::Entropy entropy;
  if (opts.from_mnemonic) {
    SecureString mnemonic =
        terminal::read_passphrase("Recovery words (12, space-separated): ");
    bip39::decode(std::string_view(mnemonic.data(), mnemonic.size()), entropy);
    mnemonic.clear();
    std::cout << "\nMnemonic verified. Rebuilding the identity from it -- this\n"
                 "vault starts with no contacts or chat history; those only\n"
                 "ever lived in the old vault.bin, never in the words.\n\n";
  } else {
    bip39::generate_entropy(entropy);
    SecureString mnemonic;
    bip39::encode(entropy, mnemonic);
    // English on the command line whatever the locale says: the CLI's output
    // is part of the project's public face, and scripts read it.
    app::print_mnemonic(mnemonic, std::cout,
                        i18n::t(i18n::Lang::En, i18n::Str::RecoveryHeading),
                        i18n::t(i18n::Lang::En, i18n::Str::RecoveryNote));
    terminal::wait_for_enter("Press ENTER once you have written them down...");
    terminal::clear_screen();
    // The words are on paper by now; nothing is served by keeping them in
    // memory for the rest of `init`.
    mnemonic.clear();
  }

  store::VaultStore store;
  randombytes_buf(store.vault_id.data(), store.vault_id.size());
  store.generation = 1;
  derive_master_seed(entropy, store.seed);
  entropy.wipe();

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  store.signed_prekeys.push_back(
      prekey::generate_signed_prekey(identity_sk, store.next_spk_id));
  store.next_spk_id += 1;

  store.one_time_prekeys =
      prekey::generate_one_time_prekeys(store.next_otpk_id, opts.otpk_count);
  store.next_otpk_id += static_cast<uint32_t>(opts.otpk_count);
  app::replenish_pq_prekeys(store, opts.otpk_count);
  identity_sk.wipe();

  SecureString passphrase =
      terminal::read_new_passphrase("Vault passphrase: ", "Confirm passphrase: ");

  std::cerr << "Deriving the vault key with Argon2id ("
            << opts.params.mem_cost_kb / 1024 << " MiB, " << opts.params.time_cost
            << " passes)...\n";

  const SecureBuffer plaintext = store::serialize(store);
  const std::vector<uint8_t> file = vault::seal(plaintext, passphrase, opts.params);
  passphrase.clear();

  vault::write_file(path, file, opts.force);

  std::cout << "\nVault written to " << path.string() << "\n"
            << "Hybrid identity fingerprint:\n"
            << hybrid_fingerprint(identity_pk,
                                  derive_pq_identity(store.seed).public_key)
            << "\n\n"
            << "Run `" << kProgram
            << " anchor --usb-path <dir>` to enroll host rollback protection,\n"
            << "then `" << kProgram
            << " card --usb-path <dir>` to get the contact card to share.\n";
  return 0;
}

int cmd_anchor(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);
  OpenedVault opened = unlock_vault(path);
  if (opened.rollback_status == rollback::Status::Protected) {
    std::cout << "Rollback protection is already active for this vault on this host.\n";
    return 0;
  }
  app::enroll_rollback_anchor(opened);
  std::cout << "Rollback protection enrolled for vault "
            << rollback::vault_id_text(opened.store.vault_id) << ", generation "
            << opened.store.generation << ".\n";
  return 0;
}

int cmd_migrate(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);
  const fs::path prepared = usb / vault::kPreparedVaultFilename;

  app::VaultFile legacy_file = app::read_vault(path);
  if (legacy_file.header.version != vault::kLegacyVersion) {
    throw Error("this vault already uses format v3; no legacy migration is needed");
  }
  SecureString passphrase = terminal::read_passphrase("Legacy vault passphrase: ");
  std::cerr << "Deriving the legacy vault key with Argon2id...\n";
  OpenedVault legacy =
      app::open_vault(std::move(legacy_file), std::move(passphrase), true);

  if (!opts.commit) {
    if (fs::exists(prepared)) {
      throw Error("a prepared vault already exists; verify and use migrate --commit");
    }
    for (store::Session& session : legacy.store.sessions) {
      session.legacy_read_only = true;
      session.suite = ProtocolSuite::ClassicV2;
    }
    app::replenish_pq_prekeys(legacy.store, kDefaultOtpkCount);
    app::save_vault(prepared, legacy.store, legacy.params, legacy.passphrase);

    // Phase one is not successful until the exact bytes just written decrypt
    // and the complete upgraded store parses again.
    const std::vector<uint8_t> bytes = vault::read_file(prepared);
    const vault::VaultHeader header =
        vault::parse_header(bytes.data(), bytes.size());
    if (header.version != vault::kVersion) {
      throw Error("prepared migration did not produce a v3 vault");
    }
    SecureBuffer plaintext;
    vault::unseal(bytes.data(), bytes.size(), legacy.passphrase, plaintext);
    const store::VaultStore verified = store::parse(plaintext.data(), plaintext.size());
    if (verified.vault_id != legacy.store.vault_id ||
        verified.generation != legacy.store.generation) {
      throw Error("prepared migration failed its identity/generation check");
    }
    std::cout << "Migration prepared and cryptographically verified at "
              << prepared.string() << ".\n"
              << "Messaging is blocked until you run `" << kProgram
              << " migrate --commit --usb-path " << usb.string() << "`.\n";
    return 0;
  }

  if (!fs::exists(prepared)) {
    throw Error("no prepared migration exists; run migrate without --commit first");
  }
  const std::vector<uint8_t> bytes = vault::read_file(prepared);
  const vault::VaultHeader header = vault::parse_header(bytes.data(), bytes.size());
  if (header.version != vault::kVersion) {
    throw Error("prepared migration is not a v3 vault");
  }
  SecureBuffer plaintext;
  vault::unseal(bytes.data(), bytes.size(), legacy.passphrase, plaintext);
  const store::VaultStore migrated = store::parse(plaintext.data(), plaintext.size());
  const bool legacy_has_id = std::any_of(
      legacy.store.vault_id.begin(), legacy.store.vault_id.end(),
      [](uint8_t b) { return b != 0; });
  if (legacy_has_id && migrated.vault_id != legacy.store.vault_id) {
    throw Error("prepared vault identity does not match the legacy vault");
  }
  IdentitySigningSecretKey legacy_identity_sk;
  IdentitySigningPublicKey legacy_identity_pk;
  IdentitySigningSecretKey migrated_identity_sk;
  IdentitySigningPublicKey migrated_identity_pk;
  derive_identity(legacy.store.seed, legacy_identity_sk, legacy_identity_pk);
  derive_identity(migrated.seed, migrated_identity_sk, migrated_identity_pk);
  legacy_identity_sk.wipe();
  migrated_identity_sk.wipe();
  if (legacy_identity_pk != migrated_identity_pk) {
    throw Error("prepared vault master identity does not match the legacy vault");
  }
  if (migrated.generation <= legacy.store.generation) {
    throw Error("prepared vault generation did not advance");
  }

  vault::promote_prepared(prepared, path);
  const rollback::Digest promoted_digest = rollback::digest(bytes.data(), bytes.size());
  if (rollback::backend_available()) {
    if (legacy_has_id) {
      if (const auto anchor = rollback::load(migrated.vault_id)) {
      rollback::validate(*anchor, legacy.store, legacy.vault_digest);
      rollback::store(
          rollback::AnchorRecord{migrated.vault_id, migrated.generation,
                                 promoted_digest},
          migrated.seed);
      } else {
        rollback::enroll(migrated, promoted_digest);
      }
    } else {
      rollback::enroll(migrated, promoted_digest);
    }
  }
  std::cout << "Migration committed atomically. Legacy sessions are read-only; "
               "import post-quantum cards before sending.\n"
            << "The old vault file was removed, but physical erasure cannot be "
               "guaranteed on flash storage.\n";
  return 0;
}

int cmd_unlock(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  bool changed = maintain_prekeys(store, identity_pk, identity_sk);
  identity_sk.wipe();
  changed = expire_skipped_keys(store) || changed;

  if (changed) {
    app::save_vault(path, store, opened.params, opened.passphrase);
  }

  std::cout << "Vault unlocked (" << store.contacts.size() << " contact(s), "
            << store.sessions.size() << " session(s)).\n"
            << "Hybrid identity fingerprint:\n"
            << hybrid_fingerprint(identity_pk,
                                  derive_pq_identity(store.seed).public_key)
            << "\n";
  return 0;
}

int cmd_card(const Options& opts) {
  // --fingerprint only reads, so pairing it with a key-refreshing flag asks for
  // two different things at once. Refusing beats quietly skipping the refresh
  // and letting the user believe their keys rotated.
  if (opts.fingerprint_only && (opts.rotate_spk || opts.replenish_otpk > 0)) {
    throw Error("--fingerprint cannot be combined with --rotate-spk or "
                "--replenish-otpk");
  }

  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  if (opts.fingerprint_only) {
    identity_sk.wipe();
    std::cout << hybrid_fingerprint(
                     identity_pk, derive_pq_identity(store.seed).public_key)
              << "\n";
    return 0;
  }

  bool changed = false;

  if (opts.rotate_spk) {
    app::rotate_signed_prekey(store, identity_sk);
    changed = true;
  }

  if (opts.replenish_otpk > 0) {
    app::replenish_one_time_prekeys(store, opts.replenish_otpk);
    changed = true;
  }

  // A card is only worth handing out if its signatures verify, and `card` can
  // be the first command run against a vault written before the signature
  // scheme changed -- so this cannot wait for the next `unlock`.
  changed = app::resign_stale_prekeys(store, identity_pk, identity_sk) || changed;

  if (store.signed_prekeys.empty()) {
    throw Error("internal: vault has no signed prekey");
  }
  const prekey::SignedPrekey& spk = store.signed_prekeys.back();

  // The identity key signs the card as a whole, so it has to still be here.
  const std::size_t pq_before = store.pq_one_time_prekeys.size();
  const bool had_pq_spk = !store.pq_signed_prekeys.empty();
  app::replenish_pq_prekeys(store, kDefaultOtpkCount);
  changed = changed || !had_pq_spk ||
            store.pq_one_time_prekeys.size() != pq_before;
  const pq::MlDsaKeyPair pq_identity = derive_pq_identity(store.seed);
  std::cout << x3dh::export_hybrid_card(
      identity_sk, identity_pk, pq_identity, spk, store.one_time_prekeys,
      store.pq_signed_prekeys.back(), store.pq_one_time_prekeys);
  identity_sk.wipe();

  if (store.one_time_prekeys.size() < kReplenishThreshold) {
    std::cerr << "warning: only " << store.one_time_prekeys.size()
              << " one-time prekey(s) left; consider `card --replenish-otpk "
              << kDefaultOtpkCount << "`.\n";
  }

  if (changed || store.generation == 0) {
    app::save_vault(path, store, opened.params, opened.passphrase);
  }
  return 0;
}

int cmd_add_contact(const Options& opts) {
  // The drive is resolved before anything else is asked for: it is the one
  // answer that can turn out to be wrong, and there is no point collecting an
  // alias the user then has to retype.
  const fs::path usb = require_usb_path(opts);
  const std::string name =
      require_value(opts.name, "Contact alias: ", "an alias is required");
  if (name.size() > store::kMaxAliasBytes) {
    throw Error("contact alias exceeds the 128-byte limit");
  }
  const fs::path path = vault::vault_path(usb);

  const std::string card_text =
      opts.card_file.empty()
          ? read_bounded(std::cin, std::size_t{3} * 1024u * 1024u, "contact card")
          : read_file_text(opts.card_file, std::size_t{3} * 1024u * 1024u);

  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  const int alias_index = store.find_contact(name);
  const int identity_index = store.find_contact_by_identity(imported.identity_pub);
  if (alias_index >= 0 || identity_index >= 0) {
    if (alias_index < 0 || identity_index < 0 || alias_index != identity_index) {
      throw Error("contact alias or identity belongs to a different saved contact");
    }
    if (!imported.card.pq_bundle) {
      throw Error("a saved contact can only be upgraded with a hybrid card");
    }
    store::Contact& existing = store.contacts[static_cast<std::size_t>(alias_index)];
    if (!suite_at_least(imported.card.maximum_suite,
                        existing.minimum_suite)) {
      throw Error("contact card would downgrade the saved protocol suite");
    }
    existing.card = imported.card;
    existing.minimum_suite = imported.card.maximum_suite;
    existing.verified = false;
    store.sessions.erase(
        std::remove_if(store.sessions.begin(), store.sessions.end(),
                       [&](const store::Session& session) {
                         return session.contact_index ==
                                static_cast<std::size_t>(alias_index);
                       }),
        store.sessions.end());
    app::save_vault(path, store, opened.params, opened.passphrase);
    std::cout << "Updated '" << name
              << "' to a hybrid identity and closed its legacy session.\n"
              << "The previous verified flag was intentionally cleared. Verify "
                 "this new safety number out of band:\n\n"
              << hybrid_fingerprint(imported.identity_pub,
                                    imported.card.pq_identity_pub)
              << "\n";
    return 0;
  }

  store::Contact contact;
  contact.alias = name;
  contact.identity_pub = imported.identity_pub;
  contact.minimum_suite = imported.card.maximum_suite;
  contact.card = imported.card;
  store.contacts.push_back(std::move(contact));

  app::save_vault(path, store, opened.params, opened.passphrase);

  std::cout << "Added '" << name << "'. Verify this fingerprint with them\n"
            << "over a separate channel (in person, a phone call) before "
               "trusting it:\n\n"
            << (imported.card.pq_bundle
                    ? hybrid_fingerprint(imported.identity_pub,
                                         imported.card.pq_identity_pub)
                    : fingerprint(imported.identity_pub))
            << "\n\n"
            << "Then run `" << kProgram << " trust --usb-path <dir> "
            << name << "`.\n";
  return 0;
}

int cmd_contacts(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  OpenedVault opened = unlock_vault(path);
  const store::VaultStore& store = opened.store;

  if (store.contacts.empty()) {
    std::cout << "No contacts yet.\n";
    return 0;
  }

  for (std::size_t i = 0; i < store.contacts.size(); ++i) {
    const store::Contact& c = store.contacts[i];
    const int session_idx = store.find_session(i);
    // Read back out of the vault and printed long after it was typed, so it
    // goes through the same escaping as anything else headed for a terminal.
    std::cout << terminal::escape_control_chars(c.alias)
              << (c.verified ? " [verified]" : " [unverified]")
              << (session_idx >= 0 ? " [session established]" : " [no session yet]")
              << "\n"
              << (c.card && c.card->pq_bundle
                      ? hybrid_fingerprint(c.identity_pub,
                                           c.card->pq_identity_pub)
                      : fingerprint(c.identity_pub))
              << "\n\n";
  }
  return 0;
}

int cmd_trust(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const std::string name =
      require_value(opts.name, "Contact alias: ", "an alias is required");
  const fs::path path = vault::vault_path(usb);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  const int idx = store.find_contact(name);
  if (idx < 0) {
    throw Error("no contact named '" + name + "'");
  }
  store.contacts[static_cast<std::size_t>(idx)].verified = true;

  app::save_vault(path, store, opened.params, opened.passphrase);
  std::cout << "'" << name << "' marked as verified.\n";
  return 0;
}

int cmd_reset_session(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const std::string name = require_value(
      opts.name, "Contact alias: ", "a contact alias is required");
  const fs::path path = vault::vault_path(usb);
  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;
  const int contact_idx = store.find_contact(name);
  if (contact_idx < 0) throw Error("no contact named '" + name + "'");
  const int session_idx =
      store.find_session(static_cast<std::size_t>(contact_idx));
  if (session_idx < 0) throw Error("this contact has no session to reset");
  if (!terminal::stdin_is_tty()) {
    throw Error("reset-session requires an interactive confirmation");
  }
  const std::string answer = terminal::read_line(
      "Close this session and discard pending/skipped message keys? Type RESET: ");
  if (answer != "RESET") throw Error("session reset cancelled");
  store.sessions.erase(store.sessions.begin() + session_idx);
  app::save_vault(path, store, opened.params, opened.passphrase);
  std::cout << "Session with '" << terminal::escape_control_chars(name)
            << "' reset. A fresh authenticated PQ opening is required.\n";
  return 0;
}

int cmd_send(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const std::string to =
      require_value(opts.to, "Send to (contact alias): ", "a recipient alias is required");
  const fs::path path = vault::vault_path(usb);

  if (!opts.file_path.empty() && opts.message.has_value()) {
    throw Error("--file and a message cannot be combined");
  }

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  const int idx = store.find_contact(to);
  if (idx < 0) {
    throw Error("no contact named '" + to + "' (see `contacts`)");
  }
  const std::size_t contact_index = static_cast<std::size_t>(idx);

  // With --file the message is the framed file; otherwise it is the text the
  // user typed. Either way the same session::send call does the encryption, so
  // a file is protected by exactly the keys a message is.
  std::string plaintext;
  std::vector<uint8_t> raw;
  if (!opts.file_path.empty()) {
    raw = file::load_file(fs::path(opts.file_path));
    const std::string ext = file::extension_for(fs::path(opts.file_path), raw);
    plaintext = file::encode_file_payload(raw, ext);
    sodium_memzero(raw.data(), raw.size());
  } else {
    plaintext = read_text_arg_or_stdin(opts.message, "Message (end with Ctrl-D): ",
                                       message::kMaxPlaintextBytes);
    if (plaintext.empty()) {
      throw Error("message must not be empty");
    }
  }

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  const std::string block =
      session::send(store, identity_sk, identity_pk, contact_index, plaintext);
  identity_sk.wipe();
  wipe_string(plaintext);

  app::save_vault(path, store, opened.params, opened.passphrase);

  // stdout is only the block, so `send alice "hi" > msg.txt` yields a file that
  // can be pasted as-is; the blank separator is part of the terminal display.
  std::cerr << "\n";
  std::cout << block;
  return 0;
}

int cmd_recv(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  // Fork the staging reaper before the vault is opened, so the long-lived
  // helper never inherits key material.
  file::prepare_staging();

  const std::string block =
      read_text_arg_or_stdin(opts.message, "Paste the message block, then Ctrl-D: ",
                             std::size_t{12} * 1024u * 1024u);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  session::ReceiveResult result =
      session::receive(store, identity_sk, identity_pk, block);
  identity_sk.wipe();

  app::save_vault(path, store, opened.params, opened.passphrase);

  const std::string alias = terminal::escape_control_chars(result.alias);
  if (result.session_established) {
    std::cerr << "(new session established with '" << alias << "')\n";
  }
  if (!store.contacts[result.contact_index].verified) {
    std::cerr << "warning: '" << alias
              << "' has not been marked as trusted.\n";
  }

  // A decrypted file is not text: printing it would dump binary to the
  // terminal. Detect the framing byte and, on an interactive terminal, offer to
  // stage the bytes in a private temporary folder and open that folder in the
  // file manager -- never to open the file itself. The extension is always
  // shown first, and a type the desktop might execute is never staged at all.
  std::optional<file::FilePayload> received =
      file::decode_file_payload(result.plaintext);
  if (received.has_value()) {
    std::cerr << alias << ": [encrypted file received: ." << received->ext
              << "]\n";
    if (file::is_dangerous_extension(received->ext)) {
      std::cerr << "not opening it: a '." << received->ext
                << "' file can run code; save it and inspect it yourself if "
                   "you trust the sender\n";
    } else if (terminal::stdin_is_tty()) {
      const std::string answer = terminal::read_line(
          "Show the ." + received->ext +
          " file in a temporary folder (removed when ratchet-usb closes)? "
          "[y/N] ");
      if (answer == "y" || answer == "Y" || answer == "yes") {
        file::open_in_file_manager(*received);
      }
    } else {
      std::cerr << "not opening it: standard input is not a terminal\n";
    }
    sodium_memzero(received->bytes.data(), received->bytes.size());
  } else {
    // The message body is whatever the sender chose to put in it. Escaped when
    // it is going to a terminal, verbatim when it is going to a file or a pipe.
    std::cout << alias << ": " << terminal::escape_if_tty(result.plaintext)
              << "\n";
  }
  // `plaintext` still holds the decrypted body (and, for a file, a second copy
  // of its bytes); it is wiped here whether it was a message or a file.
  wipe_string(result.plaintext);
  return 0;
}

// The terminal interface, and the one gate in front of it.
//
// It runs only when stdin and stdout are both a terminal. That is what keeps
// every script, pipe and test that has ever driven this program on exactly the
// path it was on before the interface existed: with the input or the output
// redirected, a bare `ratchet-usb` produces the error it always produced, down
// to the wording.
int cmd_ui(const Options& opts) {
  if (!screen::usable()) {
    if (opts.no_arguments) {
      throw Error("no command given (try `" + std::string(kProgram) +
                  " --help`)");
    }
    throw Error("`ui` needs a terminal: run it without redirecting the input "
                "or the output");
  }

  ui::Config config;
  config.usb_path = opts.usb_path.string();
  config.lang = i18n::detect(opts.lang);
  config.idle_lock_seconds = opts.idle_lock_seconds;
  // The reaper is forked before the interface can unlock a vault, so the
  // long-lived helper never inherits key material.
  file::prepare_staging();
  return ui::run(config);
}

}  // namespace

int main(int argc, char** argv) {
  try {
    // Before anything else, and before any secret exists to protect: from here
    // on a crash cannot write a core dump and a sibling process cannot attach.
    harden_process();
    init_sodium();
    const Options opts =
        cli::parse_args(std::vector<std::string_view>(argv + 1, argv + argc));

    if (opts.command == "help") {
      cli::print_usage(std::cout);
      return 0;
    }
    if (opts.command == "version") {
      std::cout << kProgram << " " << cli::kVersion << "\n";
      return 0;
    }
    if (opts.command == "init") {
      return cmd_init(opts);
    }
    if (opts.command == "unlock") {
      return cmd_unlock(opts);
    }
    if (opts.command == "anchor") {
      return cmd_anchor(opts);
    }
    if (opts.command == "migrate") {
      return cmd_migrate(opts);
    }
    if (opts.command == "card") {
      return cmd_card(opts);
    }
    if (opts.command == "add") {
      return cmd_add_contact(opts);
    }
    if (opts.command == "contacts") {
      return cmd_contacts(opts);
    }
    if (opts.command == "trust") {
      return cmd_trust(opts);
    }
    if (opts.command == "reset-session") {
      return cmd_reset_session(opts);
    }
    if (opts.command == "send") {
      return cmd_send(opts);
    }
    if (opts.command == "recv") {
      return cmd_recv(opts);
    }
    if (opts.command == "ui") {
      return cmd_ui(opts);
    }
    throw Error("unknown command: " + opts.command);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
