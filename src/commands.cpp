#include "ratchet/commands.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/app.hpp"
#include "ratchet/bip39.hpp"
#include "ratchet/cli.hpp"
#include "ratchet/command_io.hpp"
#include "ratchet/file.hpp"
#include "ratchet/gui_format.hpp"
#include "ratchet/group.hpp"
#include "ratchet/i18n.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/media.hpp"
#include "ratchet/passphrase.hpp"
#include "ratchet/ratchet.hpp"
#include "ratchet/screen.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/session.hpp"
#include "ratchet/store.hpp"
#include "ratchet/terminal.hpp"
#include "ratchet/ui.hpp"
#include "ratchet/vault.hpp"
#include "ratchet/x3dh.hpp"

namespace fs = std::filesystem;

namespace ratchet::commands {

using app::OpenedVault;
using cli::kDefaultOtpkCount;
using cli::kProgram;
using cli::Options;

using app::kReplenishThreshold;

namespace {

// --stdin-payload is a front-end protocol: the payload occupies the beginning
// of stdin, so the drive must already be known and must not be resolved by a
// prompt that would consume those bytes. The GUI always passes --usb-path; the
// environment fallback is accepted because it needs no reading either.
void require_known_usb_for_payload(const Options& opts) {
  if (!opts.stdin_payload_bytes || !opts.usb_path.empty()) {
    return;
  }
  const char* env = std::getenv("RATCHET_USB_PATH");
  if (env != nullptr && env[0] != '\0') {
    return;
  }
  throw Error("--stdin-payload requires --usb-path or RATCHET_USB_PATH");
}

// A view over a SecureString, without copying it. An empty SecureString has no
// buffer worth exposing, so it maps to an empty view.
std::string_view view_of(const SecureString& text) {
  return text.empty() ? std::string_view{}
                      : std::string_view(text.data(), text.size());
}

void write_structured_or_throw(const gui_format::Result& result) {
  if (!gui_format::write_result(std::cout, result)) {
    throw Error("could not write structured output");
  }
}

// Writes the pasteable block and makes sure it left the process. The caller
// has already persisted the block in the outbox beside the vault, so a failed
// write leaves a recoverable copy and the advanced ratchet state is committed.
void write_block_or_throw(const std::string& block, const fs::path& outbox) {
  std::cout << block;
  std::cout.flush();
  if (!std::cout) {
    throw Error("could not write the message block; it is saved at " +
                outbox.string() + " (run `" + std::string(kProgram) +
                " outbox --usb-path <dir>` to print it again)");
  }
}

// Refuse to start a new send while a block from an earlier interrupted write
// is still pending: overwriting the outbox would lose that block.
void ensure_no_pending_outbox(const fs::path& usb) {
  const fs::path outbox = vault::outbox_path(usb);
  if (fs::exists(outbox)) {
    throw Error("a previously generated block is pending at " +
                outbox.string() + "; run `" + std::string(kProgram) +
                " outbox --usb-path <dir>` to print it, then delete it");
  }
}

void write_pending_outbox(const fs::path& usb, const std::string& block) {
  const std::vector<uint8_t> bytes(block.begin(), block.end());
  vault::write_file(vault::outbox_path(usb), bytes, /*overwrite=*/false);
}

void discard_pending_outbox(const fs::path& usb) {
  std::error_code ec;
  fs::remove(vault::outbox_path(usb), ec);
}

void remove_pending_outbox(const fs::path& usb) {
  std::error_code ec;
  fs::remove(vault::outbox_path(usb), ec);
  if (ec) {
    throw Error("the block was written, but the pending copy at " +
                vault::outbox_path(usb).string() +
                " could not be removed: " + ec.message());
  }
}

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
  // Kept alive until the structured result has been written, but only in that
  // mode: the default path still drops it as soon as it has been printed.
  SecureString recovery;
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
    bip39::encode(entropy, recovery);
    if (!opts.structured_output) {
      // English on the command line whatever the locale says: the CLI's output
      // is part of the project's public face, and scripts read it.
      app::print_word_grid(recovery, std::cout,
                           i18n::t(i18n::Lang::En, i18n::Str::RecoveryHeading),
                           i18n::t(i18n::Lang::En, i18n::Str::RecoveryNote));
      terminal::wait_for_enter("Press ENTER once you have written them down...");
      terminal::clear_screen();
      // The words are on paper by now; nothing is served by keeping them in
      // memory for the rest of `init`.
      recovery.clear();
    }
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

  SecureString passphrase;
  passphrase::generate(passphrase, opts.passphrase_words);
  // The passphrase is generated, shown once and never chosen. A phrase a person
  // invents is usually far weaker than one the program draws from a 2048-word
  // list, and one passed on the command line would land in the shell history.
  // This is the vault passphrase, not the recovery phrase above: it unlocks the
  // vault and nothing else.
  if (!opts.structured_output) {
    app::print_word_grid(
        passphrase, std::cerr,
        i18n::t(i18n::Lang::En, i18n::Str::PassphraseHeading),
        i18n::t(i18n::Lang::En, i18n::Str::PassphraseNote));
    terminal::wait_for_enter(
        "Press ENTER once you have written the passphrase down...");
    terminal::clear_screen();
  }

  std::cerr << "Deriving the vault key with Argon2id ("
            << opts.params.mem_cost_kb / 1024 << " MiB, " << opts.params.time_cost
            << " passes)...\n";

  const SecureBuffer plaintext = store::serialize(store);
  // Stamped v4: a new vault is sealed with a generated word phrase, so unlock
  // asks for it one word per line rather than one line.
  const std::vector<uint8_t> file =
      vault::seal(plaintext, passphrase, opts.params, vault::kWordVersion);
  if (!opts.structured_output) {
    passphrase.clear();
  }

  vault::write_file(path, file, opts.force);
  // A block generated from the old vault cannot be delivered against the new
  // one, so do not leave a stale outbox behind to block the first send.
  discard_pending_outbox(usb);

  std::cout << "\nVault written to " << path.string() << "\n"
            << "Hybrid identity fingerprint:\n"
            << hybrid_fingerprint(identity_pk,
                                  derive_pq_identity(store.seed).public_key)
            << "\n\n"
            << "Run `" << kProgram
            << " anchor --usb-path <dir>` to enroll host rollback protection,\n"
            << "then `" << kProgram
            << " card --usb-path <dir>` to get the contact card to share.\n";

  if (opts.structured_output) {
    // Only after the vault is on disk. A failed init leaves no structured
    // block, so the GUI can never display a passphrase for a vault that was
    // not written.
    write_structured_or_throw(gui_format::Result{
        "init", "ok", opts.from_mnemonic ? "mnemonic" : "generated",
        view_of(passphrase), opts.passphrase_words, view_of(recovery),
        opts.from_mnemonic ? 0 : bip39::kWordCount});
    passphrase.clear();
    recovery.clear();
  }
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
    throw Error("this vault already uses a current format; no legacy migration "
                "is needed");
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

int cmd_passphrase(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);
  OpenedVault opened = unlock_vault(
      path, "Current vault passphrase");

  // A new passphrase is generated and shown once, exactly as at init. The old
  // one is never shown and cannot be recovered; that is the point of changing
  // it, not a limitation of this command.
  SecureString next;
  passphrase::generate(next, opts.passphrase_words);
  if (!opts.structured_output) {
    app::print_word_grid(
        next, std::cerr,
        i18n::t(i18n::Lang::En, i18n::Str::PassphraseHeading),
        i18n::t(i18n::Lang::En, i18n::Str::PassphraseNote));
  }
  // The new phrase is shown before anything is re-encrypted, and Enter is not
  // the only way on: Esc backs out and leaves the vault exactly as it was.
  if (!terminal::confirm_enter_or_escape(
          std::string(i18n::t(i18n::Lang::En, i18n::Str::PassphraseConfirm)))) {
    next.clear();
    std::cout << i18n::t(i18n::Lang::En, i18n::Str::PassphraseCancelled) << "\n";
    if (opts.structured_output) {
      write_structured_or_throw(gui_format::Result{
          "passphrase", "cancelled", {}, {}, 0, {}, 0});
    }
    return 0;
  }
  if (!opts.structured_output) {
    terminal::clear_screen();
  }

  app::rekey_vault(path, opened.store, opened.params, next);
  if (!opts.structured_output) {
    next.clear();
  }
  std::cout << i18n::t(i18n::Lang::En, i18n::Str::PassphraseChanged) << "\n";
  if (opts.structured_output) {
    // After the rekey has completed: a failure leaves no block, so the GUI
    // cannot show a new passphrase that the vault does not use.
    write_structured_or_throw(gui_format::Result{
        "passphrase", "ok", {}, view_of(next), opts.passphrase_words, {}, 0});
    next.clear();
  }
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
    // A legacy alias may contain a control character this build refuses for
    // new imports. It still has to be printable here, because the upgrade is
    // the only way to repair that contact, so it goes out line-safe.
    std::cout << "Updated '" << terminal::escape_line_control_chars(name)
              << "' to a hybrid identity and closed its legacy session.\n"
              << "The previous verified flag was intentionally cleared. Verify "
                 "this new safety number out of band:\n\n"
              << hybrid_fingerprint(imported.identity_pub,
                                    imported.card.pq_identity_pub)
              << "\n";
    return 0;
  }

  // An alias is borrowed text: it is chosen by whoever sent the card, and it
  // is printed again later in `contacts`, `recv` and the GUI. A format or
  // control character in it draws as nothing but can reorder or forge the line
  // around it, so it is refused here -- where it enters the vault -- rather
  // than escaped at one of the places it is shown.
  //
  // Checked only for a new contact: a vault written by an older build can hold
  // an alias this build would refuse, and `add` with that alias is how its
  // owner upgrades the card. The upgrade branch above runs before this and
  // prints the legacy alias line-safe.
  if (const char* problem = contact_alias_problem(name)) {
    throw Error(problem);
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
    std::cout << terminal::escape_line_control_chars(c.alias)
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
  // Not validated here on purpose: a vault written by an older build can hold
  // an alias this build would refuse to import, and the owner still has to be
  // able to mark that contact verified. The alias is matched as it is stored
  // and only ever *printed* through escape_line_control_chars, because the
  // fingerprint lines it is printed beside are parsed line by line.
  const fs::path path = vault::vault_path(usb);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  const int idx = store.find_contact(name);
  if (idx < 0) {
    throw Error("no contact named '" +
                terminal::escape_line_control_chars(name) + "'");
  }
  const store::Contact& contact = store.contacts[static_cast<std::size_t>(idx)];
  // What is printed, never what is compared or stored: the vault keeps the
  // alias exactly as it was entered, which cmd_add_contact has already checked
  // for control and format characters. This is only so an alias imported by an
  // older build cannot rewrite the line the fingerprint is on: for that, a
  // newline is as dangerous as an escape, so the line-safe escaping is used.
  const std::string shown_name = terminal::escape_line_control_chars(name);

  // The fingerprint is what the user compares with the contact over a channel
  // nobody else controls, so "verified" means nothing unless it has just been
  // shown. Printing it here means the string being confirmed is the one this
  // command is about. It goes to stderr, where every other prompt goes, so
  // stdout stays free for a caller that captures the result.
  std::string shown_fingerprint =
      contact.card && contact.card->pq_bundle
          ? hybrid_fingerprint(contact.identity_pub, contact.card->pq_identity_pub)
          : fingerprint(contact.identity_pub);
  // A legacy (non-hybrid) fingerprint is grouped on two lines for reading
  // aloud. The trust output is line-oriented -- the GUI takes the value after
  // "fingerprint: " up to the newline -- so flatten it here and compare the
  // flattened form. Otherwise --show-fingerprint and --expect-fingerprint
  // disagree about which string was shown, and a hybrid card would be the only
  // one that could be trusted from a front end.
  std::replace(shown_fingerprint.begin(), shown_fingerprint.end(), '\n', ' ');
  // A front end that showed a fingerprint passes it back here. Between the two
  // commands the vault can change: a card replaced under the same alias, or a
  // legacy card upgraded to a hybrid one, would make this command mark a key
  // the user never looked at. The confirmation belongs to the string that was
  // shown, so a different one is refused instead of inherited.
  if (opts.expect_fingerprint.has_value() &&
      *opts.expect_fingerprint != shown_fingerprint) {
    throw Error("the fingerprint of '" + shown_name +
                "' is not the one that was shown, so nothing was marked as "
                "verified; run trust again and compare the new value");
  }
  std::cerr << "\nFingerprint for '" << shown_name << "':\n\n"
            << shown_fingerprint
            << "\n\nCompare this with the value the person behind '"
            << shown_name << "'\nreads out over a separate channel (in person, "
               "a phone call) before\nmarking them verified.\n\n";

  if (opts.show_fingerprint) {
    // The GUI's first step. stdout carries the fingerprint and nothing else,
    // so the window can show exactly the value this command read from the
    // vault; nothing has been changed at this point, whatever the caller does
    // next.
    std::cout << "alias: " << shown_name << "\n"
              << "fingerprint: " << shown_fingerprint << "\n"
              << "verified: " << (contact.verified ? "yes" : "no") << "\n";
    std::cout.flush();
    if (!std::cout) {
      throw Error("could not write the fingerprint");
    }
    return 0;
  }

  // Being verified is an authorization, not a note: it is what lets `send`
  // and `recv` accept this contact's traffic. So it is confirmed instead of
  // just printed -- unless `--confirmed` says a front end has already asked,
  // and in this build only the GUI's dialog, which follows the step above.
  if (!opts.confirmed) {
    if (!terminal::stdin_is_tty()) {
      throw Error(
          "trust requires an interactive confirmation; run it on a terminal, "
          "or pass --confirmed once the fingerprint has been shown and the "
          "user has confirmed");
    }
    if (!terminal::confirm_enter_or_escape(
            "Press ENTER once you have compared the fingerprint, or Esc to "
            "cancel: ")) {
      throw Error("cancelled; '" + shown_name +
                  "' was not marked as verified");
    }
  }

  store::Contact& verified = store.contacts[static_cast<std::size_t>(idx)];
  if (verified.verified) {
    // Already trusted. Still after the fingerprint has been shown, so a
    // repeated run re-confirms rather than quietly succeeding.
    std::cout << "'" << shown_name << "' was already marked as verified.\n";
    return 0;
  }
  verified.verified = true;

  app::save_vault(path, store, opened.params, opened.passphrase);
  std::cout << "'" << shown_name << "' marked as verified.\n";
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

int cmd_remove(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const std::string name = require_value(
      opts.name, "Contact alias: ", "a contact alias is required");
  const fs::path path = vault::vault_path(usb);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  const int contact_idx = store.find_contact(name);
  if (contact_idx < 0) throw Error("no contact named '" + name + "'");

  // Deleting a contact also deletes the ratchet keys in its session, so it is
  // a destructive operation: ask unless the caller has already confirmed with
  // its own dialog (--yes, as the GUI does).
  if (!opts.assume_yes) {
    if (!terminal::stdin_is_tty()) {
      throw Error("remove requires --yes or an interactive confirmation");
    }
    const std::string answer = terminal::read_line(
        "Delete '" + terminal::escape_control_chars(name) +
        "' and its session keys? Type REMOVE: ");
    if (answer != "REMOVE") throw Error("contact removal cancelled");
  }

  const std::size_t idx = static_cast<std::size_t>(contact_idx);

  // Sessions index into `contacts` by position, so drop this one first, then
  // the contact, then renumber the sessions that followed it. Erasing the
  // Session destroys its SecureBytes (root key, chain keys, skipped keys), the
  // same way reset-session does.
  store.sessions.erase(
      std::remove_if(store.sessions.begin(), store.sessions.end(),
                     [idx](const store::Session& session) {
                       return session.contact_index == idx;
                     }),
      store.sessions.end());
  store.contacts.erase(store.contacts.begin() + contact_idx);
  for (store::Session& session : store.sessions) {
    if (session.contact_index > idx) --session.contact_index;
  }

  app::save_vault(path, store, opened.params, opened.passphrase);
  std::cout << "Removed '" << terminal::escape_control_chars(name)
            << "' and its session.\n";
  return 0;
}

int cmd_group_send(const Options& opts) {
  if (opts.group_members.size() < 2) {
    throw Error("group-send needs at least two --to recipients");
  }
  if (opts.group_members.size() > group::kMaxMembers) {
    throw Error("group-send accepts at most " +
                std::to_string(group::kMaxMembers) + " recipients");
  }
  if (opts.stdin_payload_bytes && opts.message.has_value()) {
    throw Error("--stdin-payload and a message cannot be combined");
  }
  require_known_usb_for_payload(opts);
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);
  ensure_no_pending_outbox(usb);

  if (opts.message.has_value()) {
    std::cerr
        << "warning: the message was passed on the command line; it is visible "
           "in the shell history and in /proc/<pid>/cmdline.\n"
           "warning: omit it (read from standard input) or use --stdin-payload "
           "to keep the plaintext out of argv.\n";
  }

  std::string plaintext;
  StringWipe wipe_plaintext(plaintext);
  if (opts.stdin_payload_bytes) {
    if (*opts.stdin_payload_bytes > message::kMaxPlaintextBytes) {
      throw Error("--stdin-payload exceeds the 4 MiB plaintext limit");
    }
    plaintext = read_exact(std::cin, *opts.stdin_payload_bytes, "message");
    if (plaintext.empty()) {
      throw Error("message must not be empty");
    }
  }

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;
  // The early check avoids a passphrase prompt, but this one runs under the
  // vault lock and is what makes two concurrent sends unable to race past it.
  ensure_no_pending_outbox(usb);

  std::vector<std::size_t> indices;
  indices.reserve(opts.group_members.size());
  for (const std::string& member : opts.group_members) {
    const int idx = store.find_contact(member);
    if (idx < 0) {
      throw Error("no contact named '" +
                  terminal::escape_line_control_chars(member) +
                  "' (see `contacts`)");
    }
    indices.push_back(static_cast<std::size_t>(idx));
  }

  if (!opts.stdin_payload_bytes) {
    plaintext = read_text_arg_or_stdin(
        opts.message, "Message (end with Ctrl-D): ",
        message::kMaxPlaintextBytes);
    if (plaintext.empty()) {
      throw Error("message must not be empty");
    }
  }

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  const std::string block = group::send(store, identity_sk, identity_pk,
                                        indices, plaintext);
  identity_sk.wipe();
  wipe_string(plaintext);
  wipe_plaintext.dismiss();

  // Persist the exact block and the advanced state together. If stdout fails,
  // the block is still in the outbox and can be exported with `outbox`; if the
  // vault save fails, remove the outbox because the state it belongs to was
  // not committed.
  write_pending_outbox(usb, block);
  try {
    app::save_vault(path, store, opened.params, opened.passphrase);
  } catch (...) {
    discard_pending_outbox(usb);
    throw;
  }

  std::cerr << "\n";
  write_block_or_throw(block, vault::outbox_path(usb));
  remove_pending_outbox(usb);
  return 0;
}

int cmd_send(const Options& opts) {
  if (opts.stdin_payload_bytes && opts.message.has_value()) {
    throw Error("--stdin-payload and a message cannot be combined");
  }
  if (opts.stdin_payload_bytes && !opts.file_path.empty()) {
    throw Error("--stdin-payload and --file cannot be combined");
  }
  require_known_usb_for_payload(opts);
  const fs::path usb = require_usb_path(opts);
  if (opts.stdin_payload_bytes && opts.to.empty()) {
    // A prompt here would read from the same stdin as the payload and consume
    // its first bytes as an alias.
    throw Error("a recipient alias is required with --stdin-payload");
  }
  const std::string to =
      require_value(opts.to, "Send to (contact alias): ", "a recipient alias is required");
  const fs::path path = vault::vault_path(usb);
  ensure_no_pending_outbox(usb);

  if (!opts.file_path.empty() && opts.message.has_value()) {
    throw Error("--file and a message cannot be combined");
  }

  // A positional message is plaintext in argv, which every process of the same
  // user can read from /proc/<pid>/cmdline and which the shell has already
  // written to its history file. It is still accepted for compatibility, but
  // the user is told what it costs and pointed at the two safe ways in.
  if (opts.message.has_value()) {
    std::cerr
        << "warning: the message was passed on the command line; it is visible "
           "in the shell history and in /proc/<pid>/cmdline.\n"
           "warning: omit it (read from standard input) or use --stdin-payload "
           "to keep the plaintext out of argv.\n";
  }

  // Read a front-end payload before the passphrase: the two share stdin, and
  // the exact byte count is what lets a multiline, blank-line-containing or
  // NUL-containing message end where the passphrase begins.
  //
  // The guard wipes on every path out, including the ones that never reach
  // session::send(): a wrong passphrase, a missing contact, a failed save.
  std::string plaintext;
  StringWipe wipe_plaintext(plaintext);
  std::vector<uint8_t> raw;
  struct RawWipe {
    std::vector<uint8_t>& bytes;
    ~RawWipe() { wipe_vector(bytes); }
  } raw_wipe{raw};
  if (opts.stdin_payload_bytes) {
    if (*opts.stdin_payload_bytes > message::kMaxPlaintextBytes) {
      throw Error("--stdin-payload exceeds the 4 MiB plaintext limit");
    }
    plaintext = read_exact(std::cin, *opts.stdin_payload_bytes, "message");
    if (plaintext.empty()) {
      throw Error("message must not be empty");
    }
  }

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;
  ensure_no_pending_outbox(usb);

  const int idx = store.find_contact(to);
  if (idx < 0) {
    throw Error("no contact named '" + to + "' (see `contacts`)");
  }
  const std::size_t contact_index = static_cast<std::size_t>(idx);

  // With --file the message is the framed file; otherwise it is the text the
  // user typed. Either way the same session::send call does the encryption, so
  // a file is protected by exactly the keys a message is.
  if (!opts.stdin_payload_bytes) {
    if (!opts.file_path.empty()) {
      raw = file::load_file(fs::path(opts.file_path));
      const std::string ext =
          file::extension_for(fs::path(opts.file_path), raw);
      plaintext = file::encode_file_payload(raw, ext);
      wipe_vector(raw);
    } else {
      plaintext = read_text_arg_or_stdin(
          opts.message, "Message (end with Ctrl-D): ",
          message::kMaxPlaintextBytes);
      if (plaintext.empty()) {
        throw Error("message must not be empty");
      }
    }
  }

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  const std::string block =
      session::send(store, identity_sk, identity_pk, contact_index, plaintext);
  identity_sk.wipe();
  wipe_string(plaintext);
  wipe_plaintext.dismiss();

  // stdout is only the block, so `send alice "hi" > msg.txt` yields a file that
  // can be pasted as-is; the blank separator is part of the terminal display.
  write_pending_outbox(usb, block);
  try {
    app::save_vault(path, store, opened.params, opened.passphrase);
  } catch (...) {
    discard_pending_outbox(usb);
    throw;
  }

  std::cerr << "\n";
  write_block_or_throw(block, vault::outbox_path(usb));
  remove_pending_outbox(usb);
  return 0;
}

int cmd_recv(const Options& opts) {
  if (opts.stdin_payload_bytes && opts.message.has_value()) {
    throw Error("--stdin-payload and a block cannot be combined");
  }
  require_known_usb_for_payload(opts);
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  // Fork the staging reaper before the vault is opened, so the long-lived
  // helper never inherits key material.
  file::prepare_staging();

  std::string block;
  if (opts.stdin_payload_bytes) {
    constexpr std::size_t kMaxBlockBytes = std::size_t{12} * 1024u * 1024u;
    if (*opts.stdin_payload_bytes > kMaxBlockBytes) {
      throw Error("--stdin-payload exceeds the block size limit");
    }
    block = read_exact(std::cin, *opts.stdin_payload_bytes, "message block");
    if (block.empty()) {
      throw Error("message block must not be empty");
    }
  } else {
    block = read_text_arg_or_stdin(
        opts.message, "Paste the message block, then Ctrl-D: ",
        std::size_t{12} * 1024u * 1024u);
  }

  if (group::looks_like_group(block) && opts.structured_output) {
    throw Error("--structured-output does not support group messages yet");
  }

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  const bool group_block = group::looks_like_group(block);
  std::array<uint8_t, 16> group_id{};
  session::ReceiveResult result;
  if (group_block) {
    group::ReceiveResult received =
        group::receive(store, identity_sk, identity_pk, block);
    result.contact_index = received.contact_index;
    result.alias = std::move(received.alias);
    result.plaintext = std::move(received.plaintext);
    result.session_established = false;
    group_id = received.group_id;
  } else {
    result = session::receive(store, identity_sk, identity_pk, block);
  }
  identity_sk.wipe();

  // The decrypted body is an ordinary std::string because it has to leave the
  // ratchet and reach the terminal. It still must not survive an exception from
  // file decoding, output or a later vault save.
  StringWipe wipe_plaintext(result.plaintext);

  app::save_vault(path, store, opened.params, opened.passphrase);

  const std::string alias = terminal::escape_line_control_chars(result.alias);
  if (group_block) {
    std::cerr << "(group " << group::group_id_hex(group_id) << ")\n";
  }
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
  // The file bytes are a second copy of the plaintext (the first is
  // result.plaintext, wiped by its own guard). Zero and release them even if
  // staging, the terminal prompt or the file manager throws.
  struct ReceivedWipe {
    std::optional<file::FilePayload>& file;
    ~ReceivedWipe() {
      if (file.has_value()) {
        wipe_vector(file->bytes);
      }
    }
  } received_wipe{received};
  // `--structured-output`: what the desktop GUI reads. The kind comes from the
  // framing byte that decode_file_payload just checked, never from the alias
  // or any other text a sender chose, and it is written after the body so a
  // reader that only wants the human output sees what it always saw.
  const bool structured = opts.structured_output;
  // stdout has a structured block only in the front-end mode. Everything that
  // writes the message body has to know, so the block stays the last thing in
  // the stream and a sender's text cannot be mistaken for it.
  gui_format::RecvResult structured_result;
  // `RecvResult::path` is a string_view. The string that backs it has to
  // outlive the try block below, because write_recv_result runs at the very
  // end of this function.
  std::string staged_path;
  if (received.has_value()) {
    std::cerr << alias << ": [encrypted file received: ." << received->ext
              << "]\n";
    structured_result.kind = gui_format::kRecvFile;
    structured_result.ext = received->ext;
    if (file::is_dangerous_extension(received->ext)) {
      std::cerr << "not opening it: a '." << received->ext
                << "' file can run code; save it and inspect it yourself if "
                   "you trust the sender\n";
    } else if (opts.stage_received) {
      // No terminal to ask on (the GUI drives this as a child process): stage
      // the file and print its path so the front end can show it and open the
      // folder itself. In the structured mode the path goes in the block
      // instead, so stdout holds one machine-readable value rather than a bare
      // line next to one.
      try {
        staged_path = file::stage_file(*received);
        structured_result.staged = true;
        structured_result.path = staged_path;
        if (!structured) {
          std::cout << staged_path << "\n";
        }
      } catch (const std::exception& e) {
        std::cerr << "could not stage the received file: " << e.what() << "\n";
      }
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
  } else if (structured) {
    // The front-end mode: the body first, then the block, and the block begins
    // on a line of its own. The body goes out exactly as it arrived except for
    // two rewrites -- control characters escaped (so a window is not handed a
    // terminal sequence) and the escape used to keep a literal marker out of
    // the stream (so the only marker is the real one). The text is the
    // sender's; the block, not this, is what a reader parses.
    std::cout << alias << ": ";
    gui_format::write_body_escaped(
        std::cout, terminal::escape_control_chars(result.plaintext));
    std::cout << "\n";
    structured_result.kind = gui_format::kRecvText;
  } else {
    std::cout << alias << ": " << terminal::escape_if_tty(result.plaintext)
              << "\n";
  }
  if (structured) {
    // Too late to help a caller that has already shown the text, so a failure
    // here is loud but does not undo the message that decrypted fine.
    if (!gui_format::write_recv_result(std::cout, structured_result)) {
      std::cerr << "warning: could not write the structured result\n";
    }
  }
  // Both guards run here: result.plaintext is wiped even when file decoding or
  // output threw, and the framed file bytes are zeroed and released.
  return 0;
}

int cmd_outbox(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  // Serialise with send/group-send, which hold the same lock while they create
  // or remove the outbox.
  vault::FileLock lock(vault::vault_path(usb));
  const fs::path path = vault::outbox_path(usb);
  if (!fs::exists(path)) {
    throw Error("no pending block at " + path.string());
  }
  const std::vector<uint8_t> bytes = vault::read_file(path);
  const std::string block(bytes.begin(), bytes.end());

  std::cerr << "\n";
  write_block_or_throw(block, path);
  remove_pending_outbox(usb);
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

int run(const Options& opts) {
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
  if (opts.command == "passphrase") {
    return cmd_passphrase(opts);
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
  if (opts.command == "remove") {
    return cmd_remove(opts);
  }
  if (opts.command == "send") {
    return cmd_send(opts);
  }
  if (opts.command == "group-send") {
    return cmd_group_send(opts);
  }
  if (opts.command == "outbox") {
    return cmd_outbox(opts);
  }
  if (opts.command == "recv") {
    return cmd_recv(opts);
  }
  if (opts.command == "ui") {
    return cmd_ui(opts);
  }
  throw Error("unknown command: " + opts.command);
}

}  // namespace ratchet::commands
