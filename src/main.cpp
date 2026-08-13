// Ratchet-USB -- phase 2: X3DH handshake and Double Ratchet messaging.
//
// Everything sensitive lives on the removable drive passed as --usb-path;
// nothing is ever written to the host's filesystem.

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/bip39.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/session.hpp"
#include "ratchet/store.hpp"
#include "ratchet/terminal.hpp"
#include "ratchet/vault.hpp"
#include "ratchet/x3dh.hpp"

namespace fs = std::filesystem;
using namespace ratchet;

namespace {

constexpr const char* kProgram = "ratchet-usb";
constexpr const char* kVersion = "0.2.0";
constexpr std::size_t kDefaultOtpkCount = 10;
constexpr std::size_t kReplenishThreshold = 5;
// How long a signed prekey is trusted before `unlock` rotates it on its own.
constexpr uint64_t kSpkMaxAgeDays = 30;
constexpr uint64_t kSpkMaxAgeSeconds = kSpkMaxAgeDays * 24 * 60 * 60;

void print_usage(std::ostream& os) {
  os << "Ratchet-USB " << kVersion
     << " -- encrypted seed vault, X3DH and Double Ratchet messaging\n"
     << "\n"
     << "Usage:\n"
     << "  " << kProgram
     << " init     --usb-path <dir> [--from-mnemonic] [options]\n"
     << "  " << kProgram << " unlock   --usb-path <dir>\n"
     << "  " << kProgram
     << " card     --usb-path <dir> [--fingerprint] [--rotate-spk] "
        "[--replenish-otpk <n>]\n"
     << "  " << kProgram
     << " add      --usb-path <dir> <alias> [--card <file>]\n"
     << "  " << kProgram << " contacts --usb-path <dir>\n"
     << "  " << kProgram << " trust    --usb-path <dir> <alias>\n"
     << "  " << kProgram
     << " send     --usb-path <dir> <alias> [message]\n"
     << "  " << kProgram << " recv     --usb-path <dir> [message]\n"
     << "\n"
     << "Commands:\n"
     << "  init      Generate a 128-bit seed, show its 12-word BIP-39 backup,\n"
     << "            and create the vault (identity, a signed prekey, one-\n"
     << "            time prekeys) at <dir>/vault.bin. With --from-mnemonic,\n"
     << "            rebuild the identity from an existing 12-word backup\n"
     << "            instead of generating a new one (no contacts or chat\n"
     << "            history come back with it; those only ever lived in\n"
     << "            the old vault.bin).\n"
     << "  unlock    Decrypt the vault and print the identity fingerprint.\n"
     << "  card      Print this identity's contact card, to paste to a\n"
     << "            contact so they can start a conversation. With\n"
     << "            --fingerprint, print only the fingerprint.\n"
     << "  add       Import a contact's card (read from --card, or from\n"
     << "            standard input) under <alias>.\n"
     << "  contacts  List known contacts, their fingerprint and trust state.\n"
     << "  trust     Mark <alias>'s fingerprint as verified out of band.\n"
     << "  send      Encrypt a message for <alias> (running the initial\n"
     << "            handshake automatically if needed) and print the block\n"
     << "            to paste into the chat. [message] falls back to standard\n"
     << "            input, or a prompt, when omitted.\n"
     << "  recv      Decrypt a pasted message block (establishing the\n"
     << "            session automatically if it is the first one). [message]\n"
     << "            falls back to standard input, or a prompt, when omitted.\n"
     << "\n"
     << "Options:\n"
     << "  --usb-path <dir>     Directory on the removable drive. Falls back to\n"
     << "                       the RATCHET_USB_PATH environment variable, then\n"
     << "                       to an interactive prompt if the terminal allows.\n"
     << "  --force              Replace an existing vault (init only).\n"
     << "  --otpk-count <n>     One-time prekeys to generate at init (default "
     << kDefaultOtpkCount << ").\n"
     << "  --argon2-time <n>    Argon2id passes (default "
     << vault::kDefaultTimeCost << ").\n"
     << "  --argon2-mem-kb <n>  Argon2id memory in KiB (default "
     << vault::kDefaultMemCostKb << ").\n"
     << "  --from-mnemonic      Prompt for an existing 12-word backup instead\n"
     << "                       of generating a new one (init only).\n"
     << "  --fingerprint        Print only the identity fingerprint (card only).\n"
     << "  -h, --help           Show this help.\n"
     << "  -V, --version        Show the version.\n";
}

struct Options {
  std::string command;
  fs::path usb_path;
  bool force = false;
  vault::Params params;
  std::size_t otpk_count = kDefaultOtpkCount;
  bool rotate_spk = false;
  std::size_t replenish_otpk = 0;
  bool fingerprint_only = false;
  bool from_mnemonic = false;
  std::string name;
  std::string to;
  std::string card_file;
  std::optional<std::string> message;
};

uint32_t parse_u32(std::string_view text, const char* flag) {
  uint32_t value = 0;
  const auto* begin = text.data();
  const auto* end = text.data() + text.size();
  const auto result = std::from_chars(begin, end, value);
  if (result.ec != std::errc() || result.ptr != end) {
    throw Error(std::string(flag) + " expects a positive integer");
  }
  return value;
}

// Commands read their "subject" (a contact alias, a message) as a positional
// argument rather than a --flag, so `send alice "hi"` replaces
// `send --to alice --message "hi"`. This pulls any leftover positional
// arguments off the front of `positional` and assigns them in the order each
// command expects.
void assign_positional(Options& opts, std::vector<std::string>& positional) {
  auto take = [&]() -> std::optional<std::string> {
    if (positional.empty()) {
      return std::nullopt;
    }
    std::string value = std::move(positional.front());
    positional.erase(positional.begin());
    return value;
  };

  if (opts.command == "add" || opts.command == "trust") {
    if (auto v = take()) {
      opts.name = *v;
    }
  } else if (opts.command == "send") {
    if (auto v = take()) {
      opts.to = *v;
    }
    if (auto v = take()) {
      opts.message = *v;
    }
  } else if (opts.command == "recv") {
    if (auto v = take()) {
      opts.message = *v;
    }
  }

  if (!positional.empty()) {
    throw Error("unexpected argument: " + positional.front());
  }
}

Options parse_args(int argc, char** argv) {
  Options opts;
  std::vector<std::string_view> args(argv + 1, argv + argc);
  std::vector<std::string> positional;

  if (args.empty()) {
    throw Error("no command given (try `" + std::string(kProgram) + " --help`)");
  }

  std::size_t i = 0;
  if (!args[0].starts_with("-")) {
    opts.command = std::string(args[0]);
    i = 1;
  }

  bool flags_done = false;
  for (; i < args.size(); ++i) {
    const std::string_view arg = args[i];
    auto next = [&](const char* flag) -> std::string_view {
      if (i + 1 >= args.size()) {
        throw Error(std::string(flag) + " needs a value");
      }
      return args[++i];
    };

    // Everything after a bare `--` is a value, however it starts.
    if (arg == "--") {
      flags_done = true;
      continue;
    }
    if (flags_done) {
      positional.emplace_back(arg);
      continue;
    }

    // A pasted card or message block opens with `-----BEGIN RATCHET ...`, so it
    // would otherwise look like a flag. No flag here carries a run of dashes,
    // which makes this unambiguous and saves the user from having to type `--`
    // before every pasted block.
    if (arg.starts_with("-----BEGIN")) {
      positional.emplace_back(arg);
      continue;
    }

    if (arg == "-h" || arg == "--help") {
      opts.command = "help";
      return opts;
    } else if (arg == "-V" || arg == "--version") {
      opts.command = "version";
      return opts;
    } else if (arg == "--usb-path") {
      opts.usb_path = fs::path(next("--usb-path"));
    } else if (arg == "--force") {
      opts.force = true;
    } else if (arg == "--otpk-count") {
      opts.otpk_count = parse_u32(next("--otpk-count"), "--otpk-count");
    } else if (arg == "--argon2-time") {
      opts.params.time_cost = parse_u32(next("--argon2-time"), "--argon2-time");
    } else if (arg == "--argon2-mem-kb") {
      opts.params.mem_cost_kb =
          parse_u32(next("--argon2-mem-kb"), "--argon2-mem-kb");
    } else if (arg == "--rotate-spk") {
      opts.rotate_spk = true;
    } else if (arg == "--replenish-otpk") {
      opts.replenish_otpk = parse_u32(next("--replenish-otpk"), "--replenish-otpk");
    } else if (arg == "--fingerprint") {
      opts.fingerprint_only = true;
    } else if (arg == "--from-mnemonic") {
      opts.from_mnemonic = true;
    } else if (arg == "--card") {
      opts.card_file = std::string(next("--card"));
    } else if (arg.starts_with("-") && arg != "-") {
      throw Error("unknown argument: " + std::string(arg));
    } else {
      positional.emplace_back(arg);
    }
  }

  if (opts.command.empty()) {
    throw Error("no command given (try `" + std::string(kProgram) + " --help`)");
  }
  assign_positional(opts, positional);
  return opts;
}

// The vault must live on the removable drive, so the path has to be an
// existing, writable directory. It is never created for the user: a typo would
// otherwise silently produce a vault in a directory on the host disk.
//
// Resolved in this order: --usb-path, then the RATCHET_USB_PATH environment
// variable, then (only when stdin is a terminal) an interactive prompt.
fs::path require_usb_path(const Options& opts) {
  fs::path usb_path = opts.usb_path;

  if (usb_path.empty()) {
    if (const char* env = std::getenv("RATCHET_USB_PATH");
        env != nullptr && env[0] != '\0') {
      usb_path = fs::path(env);
    }
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
  const char* home = std::getenv("HOME");
  if (home == nullptr) {
    return;
  }
  struct stat usb_st {};
  struct stat home_st {};
  if (::stat(usb_path.c_str(), &usb_st) != 0 || ::stat(home, &home_st) != 0) {
    return;
  }
  if (usb_st.st_dev == home_st.st_dev) {
    std::cerr << "warning: " << usb_path.string()
              << " is on the same filesystem as your home directory.\n"
              << "warning: the vault is meant to live on a removable drive.\n";
  }
}

void print_mnemonic(const std::string& mnemonic) {
  std::cout << "\nRecovery phrase (12 words, BIP-39):\n\n";

  std::size_t index = 1;
  std::size_t pos = 0;
  std::vector<std::string> words;
  while (pos <= mnemonic.size()) {
    const std::size_t space = mnemonic.find(' ', pos);
    const std::size_t end = (space == std::string::npos) ? mnemonic.size() : space;
    words.push_back(mnemonic.substr(pos, end - pos));
    if (space == std::string::npos) {
      break;
    }
    pos = space + 1;
  }

  for (std::size_t row = 0; row < 3; ++row) {
    std::cout << "  ";
    for (std::size_t col = 0; col < 4; ++col) {
      const std::size_t w = row * 4 + col;
      if (w >= words.size()) {
        break;
      }
      std::string cell = std::to_string(index++) + ". " + words[w];
      cell.resize(std::max<std::size_t>(cell.size(), 16), ' ');
      std::cout << cell;
    }
    std::cout << "\n";
  }

  std::cout << "\nWrite these words down on paper, in order. They are the only\n"
               "way to recover the seed and identity if the drive is lost; a\n"
               "vault restored from them alone starts with no prekeys, no\n"
               "contacts and no sessions -- those live only in vault.bin.\n\n";
}

// --- vault open/save helpers ------------------------------------------------

struct OpenedVault {
  store::VaultStore store;
  vault::Params params;    // reused on save, so a re-seal keeps the original cost
  SecureString passphrase; // held for the lifetime of the command, so a
                           // mutating command only has to ask once
};

OpenedVault unlock_vault(const fs::path& path, const char* prompt = "Vault passphrase: ") {
  const std::vector<uint8_t> file = vault::read_file(path);
  const vault::VaultHeader header = vault::parse_header(file.data(), file.size());

  OpenedVault result;
  result.passphrase = terminal::read_passphrase(prompt);
  std::cerr << "Deriving the vault key with Argon2id...\n";

  SecureBuffer plaintext;
  vault::unseal(file.data(), file.size(), result.passphrase, plaintext);

  result.store = store::parse(plaintext.data(), plaintext.size());
  result.params = vault::Params{header.argon2_time_cost, header.argon2_mem_cost_kb};
  return result;
}

void save_vault(const fs::path& path, const store::VaultStore& store,
                const vault::Params& params, const SecureString& passphrase) {
  const SecureBuffer plaintext = store::serialize(store);
  const std::vector<uint8_t> file = vault::seal(plaintext, passphrase, params);
  vault::write_file(path, file, /*overwrite=*/true);
}

std::string read_all_stdin() {
  std::ostringstream ss;
  ss << std::cin.rdbuf();
  return ss.str();
}

std::string read_text_arg_or_stdin(const std::optional<std::string>& arg,
                                   const char* prompt_if_tty) {
  if (arg) {
    return *arg;
  }
  if (terminal::stdin_is_tty()) {
    std::cerr << prompt_if_tty << std::flush;
  }
  return read_all_stdin();
}

std::string read_file_text(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw Error("cannot open " + path);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Rotates the signed prekey if it has aged past kSpkMaxAgeDays, and tops the
// one-time prekey pool back up once it drops below kReplenishThreshold. Runs
// on every `unlock` so both stay fresh without a manual `card` command.
// Returns whether the store was actually changed (and so needs saving).
bool maintain_prekeys(store::VaultStore& store,
                      const IdentitySigningSecretKey& identity_sk) {
  bool changed = false;
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));

  const bool spk_stale = store.signed_prekeys.empty() ||
      now - store.signed_prekeys.back().created_at > kSpkMaxAgeSeconds;
  if (spk_stale) {
    store.signed_prekeys.push_back(
        prekey::generate_signed_prekey(identity_sk, store.next_spk_id));
    store.next_spk_id += 1;
    // Keep only the newest two, same rule as the manual `--rotate-spk`: a
    // peer who grabbed the card just before rotation may still use the old one.
    while (store.signed_prekeys.size() > 2) {
      store.signed_prekeys.erase(store.signed_prekeys.begin());
    }
    std::cout << "Signed prekey was older than " << kSpkMaxAgeDays
              << " days; rotated it automatically.\n";
    changed = true;
  }

  if (store.one_time_prekeys.size() < kReplenishThreshold) {
    const std::size_t had = store.one_time_prekeys.size();
    std::vector<prekey::OneTimePrekey> fresh =
        prekey::generate_one_time_prekeys(store.next_otpk_id, kDefaultOtpkCount);
    store.next_otpk_id += static_cast<uint32_t>(kDefaultOtpkCount);
    for (auto& otpk : fresh) {
      store.one_time_prekeys.push_back(std::move(otpk));
    }
    std::cout << "Only " << had
              << " one-time prekey(s) were left; replenished "
              << kDefaultOtpkCount << " automatically.\n";
    changed = true;
  }

  return changed;
}

// --- commands ----------------------------------------------------------------

int cmd_init(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  warn_if_host_disk(usb);

  const fs::path path = vault::vault_path(usb);
  if (!opts.force && fs::exists(path)) {
    throw Error("a vault already exists at " + path.string() +
               " (pass --force to replace it)");
  }

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
    const std::string mnemonic = bip39::encode(entropy);
    print_mnemonic(mnemonic);
    terminal::wait_for_enter("Press ENTER once you have written them down...");
    terminal::clear_screen();
  }

  store::VaultStore store;
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
            << "Identity fingerprint:\n" << fingerprint(identity_pk) << "\n\n"
            << "Run `" << kProgram
            << " card --usb-path <dir>` to get the contact card to share.\n";
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

  const bool changed = maintain_prekeys(store, identity_sk);
  identity_sk.wipe();

  if (changed) {
    save_vault(path, store, opened.params, opened.passphrase);
  }

  std::cout << "Vault unlocked (" << store.contacts.size() << " contact(s), "
            << store.sessions.size() << " session(s)).\n"
            << "Identity fingerprint:\n" << fingerprint(identity_pk) << "\n";
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
    std::cout << fingerprint(identity_pk) << "\n";
    return 0;
  }

  bool changed = false;

  if (opts.rotate_spk) {
    store.signed_prekeys.push_back(
        prekey::generate_signed_prekey(identity_sk, store.next_spk_id));
    store.next_spk_id += 1;
    // Keep only the newest two: a peer whose card we handed out just before
    // rotating might still send an initial message against the old one.
    while (store.signed_prekeys.size() > 2) {
      store.signed_prekeys.erase(store.signed_prekeys.begin());
    }
    changed = true;
  }

  if (opts.replenish_otpk > 0) {
    std::vector<prekey::OneTimePrekey> fresh =
        prekey::generate_one_time_prekeys(store.next_otpk_id, opts.replenish_otpk);
    store.next_otpk_id += static_cast<uint32_t>(opts.replenish_otpk);
    for (auto& otpk : fresh) {
      store.one_time_prekeys.push_back(std::move(otpk));
    }
    changed = true;
  }

  identity_sk.wipe();

  if (store.signed_prekeys.empty()) {
    throw Error("internal: vault has no signed prekey");
  }
  const prekey::SignedPrekey& spk = store.signed_prekeys.back();

  std::cout << x3dh::export_card(identity_pk, spk, store.one_time_prekeys);

  if (store.one_time_prekeys.size() < kReplenishThreshold) {
    std::cerr << "warning: only " << store.one_time_prekeys.size()
              << " one-time prekey(s) left; consider `card --replenish-otpk "
              << kDefaultOtpkCount << "`.\n";
  }

  if (changed) {
    save_vault(path, store, opened.params, opened.passphrase);
  }
  return 0;
}

int cmd_add_contact(const Options& opts) {
  const std::string name =
      require_value(opts.name, "Contact alias: ", "an alias is required");
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  const std::string card_text =
      opts.card_file.empty() ? read_all_stdin() : read_file_text(opts.card_file);

  const x3dh::ImportedCard imported = x3dh::import_card(card_text);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  if (store.find_contact(name) >= 0) {
    throw Error("a contact named '" + name + "' already exists");
  }
  if (store.find_contact_by_identity(imported.identity_pub) >= 0) {
    throw Error("this identity is already saved under a different alias");
  }

  store::Contact contact;
  contact.alias = name;
  contact.identity_pub = imported.identity_pub;
  contact.card = imported.card;
  store.contacts.push_back(std::move(contact));

  save_vault(path, store, opened.params, opened.passphrase);

  std::cout << "Added '" << name << "'. Verify this fingerprint with them\n"
            << "over a separate channel (in person, a phone call) before "
               "trusting it:\n\n"
            << fingerprint(imported.identity_pub) << "\n\n"
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
    std::cout << c.alias << (c.verified ? " [verified]" : " [unverified]")
              << (session_idx >= 0 ? " [session established]" : " [no session yet]")
              << "\n"
              << fingerprint(c.identity_pub) << "\n\n";
  }
  return 0;
}

int cmd_trust(const Options& opts) {
  const std::string name =
      require_value(opts.name, "Contact alias: ", "an alias is required");
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  const int idx = store.find_contact(name);
  if (idx < 0) {
    throw Error("no contact named '" + name + "'");
  }
  store.contacts[static_cast<std::size_t>(idx)].verified = true;

  save_vault(path, store, opened.params, opened.passphrase);
  std::cout << "'" << name << "' marked as verified.\n";
  return 0;
}

int cmd_send(const Options& opts) {
  const std::string to =
      require_value(opts.to, "Send to (contact alias): ", "a recipient alias is required");
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  const std::string plaintext =
      read_text_arg_or_stdin(opts.message, "Message (end with Ctrl-D): ");
  if (plaintext.empty()) {
    throw Error("message must not be empty");
  }

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  const int idx = store.find_contact(to);
  if (idx < 0) {
    throw Error("no contact named '" + to + "' (see `contacts`)");
  }
  const std::size_t contact_index = static_cast<std::size_t>(idx);

  if (!store.contacts[contact_index].verified) {
    std::cerr << "warning: '" << to
              << "' has not been marked as trusted; run `trust` once you have "
                 "checked the fingerprint.\n";
  }

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  const std::string block =
      session::send(store, identity_sk, identity_pk, contact_index, plaintext);
  identity_sk.wipe();

  save_vault(path, store, opened.params, opened.passphrase);

  // stdout is only the block, so `send alice "hi" > msg.txt` yields a file that
  // can be pasted as-is; the blank separator is part of the terminal display.
  std::cerr << "\n";
  std::cout << block;
  return 0;
}

int cmd_recv(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  const std::string block =
      read_text_arg_or_stdin(opts.message, "Paste the message block, then Ctrl-D: ");

  OpenedVault opened = unlock_vault(path);
  store::VaultStore& store = opened.store;

  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(store.seed, identity_sk, identity_pk);

  const session::ReceiveResult result =
      session::receive(store, identity_sk, identity_pk, block);
  identity_sk.wipe();

  save_vault(path, store, opened.params, opened.passphrase);

  if (result.session_established) {
    std::cerr << "(new session established with '" << result.alias << "')\n";
  }
  if (!store.contacts[result.contact_index].verified) {
    std::cerr << "warning: '" << result.alias
              << "' has not been marked as trusted.\n";
  }
  std::cout << result.alias << ": " << result.plaintext << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    init_sodium();
    const Options opts = parse_args(argc, argv);

    if (opts.command == "help") {
      print_usage(std::cout);
      return 0;
    }
    if (opts.command == "version") {
      std::cout << kProgram << " " << kVersion << "\n";
      return 0;
    }
    if (opts.command == "init") {
      return cmd_init(opts);
    }
    if (opts.command == "unlock") {
      return cmd_unlock(opts);
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
    if (opts.command == "send") {
      return cmd_send(opts);
    }
    if (opts.command == "recv") {
      return cmd_recv(opts);
    }
    throw Error("unknown command: " + opts.command);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
