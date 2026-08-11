// Ratchet-USB -- phase 1: seed generation and vault.
//
// Everything sensitive lives on the removable drive passed as --usb-path;
// nothing is ever written to the host's filesystem.

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/bip39.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/terminal.hpp"
#include "ratchet/vault.hpp"

namespace fs = std::filesystem;
using namespace ratchet;

namespace {

constexpr const char* kProgram = "ratchet-usb";
constexpr const char* kVersion = "0.1.0";

void print_usage(std::ostream& os) {
  os << "Ratchet-USB " << kVersion << " -- encrypted seed vault\n"
     << "\n"
     << "Usage:\n"
     << "  " << kProgram << " init   --usb-path <dir> [options]\n"
     << "  " << kProgram << " unlock --usb-path <dir>\n"
     << "\n"
     << "Commands:\n"
     << "  init      Generate a 128-bit seed, show its 12-word BIP-39 backup,\n"
     << "            and store the encrypted vault at <dir>/vault.bin.\n"
     << "  unlock    Decrypt the vault and print the identity public key.\n"
     << "\n"
     << "Options:\n"
     << "  --usb-path <dir>     Directory on the removable drive (required).\n"
     << "  --force              Replace an existing vault (init only).\n"
     << "  --argon2-time <n>    Argon2id passes (default "
     << vault::kDefaultTimeCost << ").\n"
     << "  --argon2-mem-kb <n>  Argon2id memory in KiB (default "
     << vault::kDefaultMemCostKb << ").\n"
     << "  -h, --help           Show this help.\n"
     << "  -V, --version        Show the version.\n";
}

struct Options {
  std::string command;
  fs::path usb_path;
  bool force = false;
  vault::Params params;
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

Options parse_args(int argc, char** argv) {
  Options opts;
  std::vector<std::string_view> args(argv + 1, argv + argc);

  if (args.empty()) {
    throw Error("no command given (try `" + std::string(kProgram) + " --help`)");
  }

  std::size_t i = 0;
  if (!args[0].starts_with("-")) {
    opts.command = std::string(args[0]);
    i = 1;
  }

  for (; i < args.size(); ++i) {
    const std::string_view arg = args[i];
    auto next = [&](const char* flag) -> std::string_view {
      if (i + 1 >= args.size()) {
        throw Error(std::string(flag) + " needs a value");
      }
      return args[++i];
    };

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
    } else if (arg == "--argon2-time") {
      opts.params.time_cost = parse_u32(next("--argon2-time"), "--argon2-time");
    } else if (arg == "--argon2-mem-kb") {
      opts.params.mem_cost_kb =
          parse_u32(next("--argon2-mem-kb"), "--argon2-mem-kb");
    } else {
      throw Error("unknown argument: " + std::string(arg));
    }
  }

  if (opts.command.empty()) {
    throw Error("no command given (try `" + std::string(kProgram) + " --help`)");
  }
  return opts;
}

// The vault must live on the removable drive, so the path has to be an
// existing, writable directory. It is never created for the user: a typo would
// otherwise silently produce a vault in a directory on the host disk.
fs::path require_usb_path(const Options& opts) {
  if (opts.usb_path.empty()) {
    throw Error("--usb-path is required");
  }

  std::error_code ec;
  const fs::path resolved = fs::canonical(opts.usb_path, ec);
  if (ec) {
    throw Error("--usb-path does not exist: " + opts.usb_path.string());
  }
  if (!fs::is_directory(resolved, ec)) {
    throw Error("--usb-path is not a directory: " + resolved.string());
  }
  if (::access(resolved.c_str(), W_OK | X_OK) != 0) {
    throw Error("--usb-path is not writable: " + resolved.string());
  }
  return resolved;
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

  // Three rows of four, so it is easy to copy onto paper without losing the
  // position of a word.
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
               "way to recover the vault if the drive is lost, and anyone who\n"
               "reads them owns your identity.\n\n";
}

int cmd_init(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  warn_if_host_disk(usb);

  const fs::path path = vault::vault_path(usb);
  if (!opts.force && fs::exists(path)) {
    throw Error("a vault already exists at " + path.string() +
                " (pass --force to replace it)");
  }

  bip39::Entropy entropy;
  bip39::generate_entropy(entropy);

  const std::string mnemonic = bip39::encode(entropy);
  print_mnemonic(mnemonic);
  terminal::wait_for_enter("Press ENTER once you have written them down...");
  terminal::clear_screen();

  vault::Secrets secrets;
  derive_master_seed(entropy, secrets.seed);
  entropy.wipe();

  IdentityPublicKey pk{};
  derive_identity(secrets.seed, secrets.identity_sk, pk);

  SecureString passphrase = terminal::read_new_passphrase(
      "Vault passphrase: ", "Confirm passphrase: ");

  std::cout << "Deriving the vault key with Argon2id ("
            << opts.params.mem_cost_kb / 1024 << " MiB, "
            << opts.params.time_cost << " passes)...\n";

  const std::vector<uint8_t> file =
      vault::seal(secrets, passphrase, opts.params);
  passphrase.clear();

  vault::write_file(path, file, opts.force);

  std::cout << "\nVault written to " << path.string() << "\n"
            << "Identity public key: " << to_hex(pk.data(), pk.size()) << "\n";
  return 0;
}

int cmd_unlock(const Options& opts) {
  const fs::path usb = require_usb_path(opts);
  const fs::path path = vault::vault_path(usb);

  const std::vector<uint8_t> file = vault::read_file(path);

  SecureString passphrase = terminal::read_passphrase("Vault passphrase: ");
  std::cout << "Deriving the vault key with Argon2id...\n";

  vault::Secrets secrets;
  vault::unseal(file.data(), file.size(), passphrase, secrets);
  passphrase.clear();

  // Recomputed from the stored private key rather than read from the file:
  // if the two ever disagreed, the vault would be the thing that is wrong.
  IdentityPublicKey pk{};
  identity_public_from_secret(secrets.identity_sk, pk);

  // The private key and the seed stay in memory only, and only until `secrets`
  // goes out of scope.
  std::cout << "Vault unlocked.\n"
            << "Identity public key: " << to_hex(pk.data(), pk.size()) << "\n";
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
    throw Error("unknown command: " + opts.command);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
