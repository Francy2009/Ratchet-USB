#include "ratchet/cli.hpp"

#include <algorithm>
#include <charconv>

#include "ratchet/i18n.hpp"
#include "ratchet/secure.hpp"

namespace ratchet::cli {
namespace {

// What each command accepts. Keeping it as data rather than scattering the
// checks through the parser is what makes `send --force` an error instead of a
// flag that parses fine and then quietly does nothing.
struct CommandSpec {
  std::string_view name;
  std::vector<std::string_view> options;
  std::size_t max_positional;
};

const std::vector<CommandSpec>& specs() {
  // --usb-path is on every command, so it is listed once per spec rather than
  // special-cased in the lookup.
  static const std::vector<CommandSpec> table = {
      {"init",
       {"--usb-path", "--force", "--otpk-count", "--argon2-time",
        "--argon2-mem-kb", "--from-mnemonic"},
       0},
      {"unlock", {"--usb-path"}, 0},
      {"card",
       {"--usb-path", "--fingerprint", "--rotate-spk", "--replenish-otpk"},
       0},
      {"add", {"--usb-path", "--card"}, 1},
      {"contacts", {"--usb-path"}, 0},
      {"trust", {"--usb-path"}, 1},
      {"send", {"--usb-path"}, 2},
      {"recv", {"--usb-path"}, 1},
      {"ui", {"--usb-path", "--lang", "--idle-lock"}, 0},
  };
  return table;
}

const CommandSpec* find_spec(std::string_view command) {
  const auto& table = specs();
  const auto it = std::find_if(table.begin(), table.end(),
                               [&](const CommandSpec& s) { return s.name == command; });
  return it == table.end() ? nullptr : &*it;
}

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

// Commands read their subject (a contact alias, a message) as a positional
// argument rather than a --flag, so `send alice "hi"` replaces
// `send --to alice --message "hi"`.
void assign_positional(Options& opts, const std::vector<std::string>& positional) {
  std::size_t i = 0;
  auto take = [&]() -> const std::string* {
    return i < positional.size() ? &positional[i++] : nullptr;
  };

  if (opts.command == "add" || opts.command == "trust") {
    if (const std::string* v = take()) {
      opts.name = *v;
    }
  } else if (opts.command == "send") {
    if (const std::string* v = take()) {
      opts.to = *v;
    }
    if (const std::string* v = take()) {
      opts.message = *v;
    }
  } else if (opts.command == "recv") {
    if (const std::string* v = take()) {
      opts.message = *v;
    }
  }
}

}  // namespace

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
     << "  " << kProgram
     << " ui       [--usb-path <dir>] [--lang en|it] [--idle-lock <s>]\n"
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
     << "  ui        Open the full-screen terminal interface, which does all\n"
     << "            of the above without flags. This is what running the\n"
     << "            program with no arguments does, on a terminal; with the\n"
     << "            input or the output redirected, nothing changes and a\n"
     << "            command is still required.\n"
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
     << "  --card <file>        Read a contact card from a file (add only).\n"
     << "  --lang en|it         Language of the interface (ui only). Without\n"
     << "                       it, an Italian locale gets Italian and\n"
     << "                       anything else gets English.\n"
     << "  --idle-lock <s>      Close the vault after <s> seconds with no key\n"
     << "                       pressed (ui only, default "
     << kDefaultIdleLockSeconds << ", 0 to disable).\n"
     << "  -h, --help           Show this help.\n"
     << "  -V, --version        Show the version.\n";
}

Options parse_args(const std::vector<std::string_view>& args) {
  Options opts;
  std::vector<std::string> positional;
  std::vector<std::string_view> seen_options;

  if (args.empty()) {
    // Nothing on the command line means the interface, on a terminal. Off one
    // it is still the error it always was, reported by the caller, which is
    // the only place that can tell.
    opts.command = "ui";
    opts.no_arguments = true;
    return opts;
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
    auto note = [&](std::string_view flag) { seen_options.push_back(flag); };

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
      opts.usb_path = std::filesystem::path(next("--usb-path"));
      note("--usb-path");
    } else if (arg == "--force") {
      opts.force = true;
      note("--force");
    } else if (arg == "--otpk-count") {
      opts.otpk_count = parse_u32(next("--otpk-count"), "--otpk-count");
      note("--otpk-count");
    } else if (arg == "--argon2-time") {
      opts.params.time_cost = parse_u32(next("--argon2-time"), "--argon2-time");
      note("--argon2-time");
    } else if (arg == "--argon2-mem-kb") {
      opts.params.mem_cost_kb =
          parse_u32(next("--argon2-mem-kb"), "--argon2-mem-kb");
      note("--argon2-mem-kb");
    } else if (arg == "--rotate-spk") {
      opts.rotate_spk = true;
      note("--rotate-spk");
    } else if (arg == "--replenish-otpk") {
      opts.replenish_otpk =
          parse_u32(next("--replenish-otpk"), "--replenish-otpk");
      note("--replenish-otpk");
    } else if (arg == "--fingerprint") {
      opts.fingerprint_only = true;
      note("--fingerprint");
    } else if (arg == "--from-mnemonic") {
      opts.from_mnemonic = true;
      note("--from-mnemonic");
    } else if (arg == "--lang") {
      opts.lang = std::string(next("--lang"));
      if (!i18n::is_valid_choice(opts.lang)) {
        throw Error("--lang takes en or it");
      }
      note("--lang");
    } else if (arg == "--idle-lock") {
      const uint32_t seconds = parse_u32(next("--idle-lock"), "--idle-lock");
      if (seconds > static_cast<uint32_t>(kMaxIdleLockSeconds)) {
        throw Error("--idle-lock is at most " +
                    std::to_string(kMaxIdleLockSeconds) + " seconds");
      }
      opts.idle_lock_seconds = static_cast<int>(seconds);
      note("--idle-lock");
    } else if (arg == "--card") {
      opts.card_file = std::string(next("--card"));
      note("--card");
    } else if (arg.starts_with("-") && arg != "-") {
      throw Error("unknown argument: " + std::string(arg));
    } else {
      positional.emplace_back(arg);
    }
  }

  if (opts.command.empty()) {
    if (!positional.empty()) {
      throw Error("the command has to come first: `" + std::string(kProgram) +
                  " " + positional.front() + " ...`");
    }
    throw Error("no command given (try `" + std::string(kProgram) + " --help`)");
  }

  const CommandSpec* spec = find_spec(opts.command);
  if (spec == nullptr) {
    throw Error("unknown command: " + opts.command + " (try `" +
                std::string(kProgram) + " --help`)");
  }

  for (const std::string_view option : seen_options) {
    if (std::find(spec->options.begin(), spec->options.end(), option) ==
        spec->options.end()) {
      throw Error(std::string(option) + " is not an option of `" +
                  opts.command + "`");
    }
  }

  if (positional.size() > spec->max_positional) {
    throw Error("unexpected argument: " + positional[spec->max_positional]);
  }

  assign_positional(opts, positional);
  return opts;
}

}  // namespace ratchet::cli
