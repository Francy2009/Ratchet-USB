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
        "--argon2-mem-kb", "--from-mnemonic", "--passphrase-words",
        "--structured-output"},
       0},
      {"unlock", {"--usb-path"}, 0},
      {"passphrase",
       {"--usb-path", "--passphrase-words", "--structured-output"},
       0},
      {"anchor", {"--usb-path"}, 0},
      {"migrate", {"--usb-path", "--commit"}, 0},
      {"card",
       {"--usb-path", "--fingerprint", "--rotate-spk", "--replenish-otpk"},
       0},
      {"add", {"--usb-path", "--card"}, 1},
      {"contacts", {"--usb-path"}, 0},
      {"trust",
       {"--usb-path", "--confirmed", "--show-fingerprint",
        "--expect-fingerprint"},
       1},
      {"reset-session", {"--usb-path"}, 1},
      {"remove", {"--usb-path", "--yes"}, 1},
      {"send",
       {"--usb-path", "--file", "--stdin-payload", "--ttl", "--burn"},
       2},
      {"group-send",
       {"--usb-path", "--to", "--stdin-payload", "--ttl", "--burn"},
       1},
      {"outbox", {"--usb-path"}, 0},
      {"recv",
       {"--usb-path", "--stage-file", "--stdin-payload", "--structured-output"},
       1},
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

  if (opts.command == "add" || opts.command == "trust" ||
      opts.command == "reset-session" || opts.command == "remove") {
    if (const std::string* v = take()) {
      opts.name = *v;
    }
  } else if (opts.command == "group-send") {
    if (const std::string* v = take()) {
      opts.message = *v;
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
     << " -- encrypted vault and hybrid PQXDH messaging\n"
     << "\n"
     << "Usage:\n"
     << "  " << kProgram
     << " init     --usb-path <dir> [--from-mnemonic] [options]\n"
     << "  " << kProgram << " unlock   --usb-path <dir>\n"
     << "  " << kProgram
     << " passphrase --usb-path <dir> [--passphrase-words <n>]\n"
     << "  " << kProgram << " anchor   --usb-path <dir>\n"
     << "  " << kProgram << " migrate  --usb-path <dir> [--commit]\n"
     << "  " << kProgram
     << " card     --usb-path <dir> [--fingerprint] [--rotate-spk] "
        "[--replenish-otpk <n>]\n"
     << "  " << kProgram
     << " add      --usb-path <dir> <alias> [--card <file>]\n"
     << "  " << kProgram << " contacts --usb-path <dir>\n"
     << "  " << kProgram << " trust    --usb-path <dir> <alias>\n"
     << "  " << kProgram << " reset-session --usb-path <dir> <alias>\n"
     << "  " << kProgram << " remove   --usb-path <dir> [--yes] <alias>\n"
     << "  " << kProgram
     << " send     --usb-path <dir> <alias> [message|--file <file>] "
        "[--ttl 1h|24h|7d] [--burn]\n"
     << "  " << kProgram
     << " group-send --usb-path <dir> --to <alias> --to <alias> [message] "
        "[--ttl 1h|24h|7d] [--burn]\n"
     << "  " << kProgram << " outbox   --usb-path <dir>\n"
     << "  " << kProgram << " recv     --usb-path <dir> [message] [--stage-file]\n"
     << "  " << kProgram
     << " ui       [--usb-path <dir>] [--lang en|it] [--idle-lock <s>]\n"
     << "\n"
     << "Commands:\n"
     << "  init      Generate a 128-bit seed, show its 12-word BIP-39 backup,\n"
     << "            and create the vault (identity, a signed prekey, one-\n"
     << "            time prekeys) at <dir>/vault.bin. A random word passphrase\n"
     << "            is generated and shown once; write it down and enter it one\n"
     << "            word per line to unlock. With --from-mnemonic, rebuild the\n"
     << "            identity from an existing 12-word backup instead of\n"
     << "            generating a new one (no contacts or chat history come back\n"
     << "            with it; those only ever lived in the old vault.bin).\n"
     << "  unlock    Decrypt the vault and print the identity fingerprint.\n"
     << "  passphrase  Generate a new word passphrase and re-encrypt the vault\n"
     << "            with it, keeping the identity, contacts and sessions. The\n"
     << "            current passphrase is asked for first; the new one is shown\n"
     << "            once and cannot be recovered later.\n"
     << "  anchor    Explicitly enroll this authenticated vault state in the\n"
     << "            host Secret Service for rollback checks.\n"
     << "  migrate   Prepare and verify a v3 vault beside a legacy vault. Run\n"
     << "            it again with --commit to promote the new vault atomically.\n"
     << "  card      Print this identity's contact card, to paste to a\n"
     << "            contact so they can start a conversation. With\n"
     << "            --fingerprint, print only the fingerprint.\n"
     << "  add       Import a contact's card (read from --card, or from\n"
     << "            standard input) under <alias>.\n"
     << "  contacts  List known contacts, their fingerprint and trust state.\n"
     << "  trust     Mark <alias>'s fingerprint as verified out of band.\n"
     << "  reset-session  Explicitly discard session and skipped-key state;\n"
     << "            the next message requires a fresh authenticated opening.\n"
     << "  remove    Delete <alias>, its card and its session, including the\n"
     << "            ratchet keys. --yes skips the interactive confirmation.\n"
     << "  send      Encrypt a message for <alias> (running the initial\n"
     << "            handshake automatically if needed) and print the block\n"
     << "            to paste into the chat. [message] falls back to standard\n"
     << "            input, or a prompt, when omitted. With --file, encrypt any\n"
     << "            file (image, document, ...) through the same ratchet\n"
     << "            instead; the file itself is never modified or copied\n"
     << "            elsewhere. A message given as an argument is visible in\n"
     << "            the shell history; omit it or use --stdin-payload.\n"
     << "  group-send  Encrypt a message once and wrap its content key for\n"
     << "            each --to contact through the existing 1:1 session. The\n"
     << "            same block is handed to every member; recv finds the\n"
     << "            wrapper addressed to this vault. At least two --to flags\n"
     << "            are required. Plaintext on the command line is visible in\n"
     << "            argv; omit it or use --stdin-payload.\n"
     << "  outbox    Print a block left in vault.bin.outbox after stdout\n"
     << "            failed, then remove the file. It asks for the vault\n"
     << "            passphrase and refuses a block that does not match the\n"
     << "            saved vault generation. A new send is refused while a\n"
     << "            pending block exists.\n"
     << "  recv      Decrypt a pasted message block (establishing the\n"
     << "            session automatically if it is the first one). [message]\n"
     << "            falls back to standard input, or a prompt, when omitted.\n"
     << "            With --stage-file, a received file is staged in the private\n"
     << "            temporary folder and its path is printed, instead of asking\n"
     << "            on a terminal whether to open it.\n"
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
     << kDefaultOtpkCount << ", at most " << kMaxOtpkCount << ").\n"
     << "  --argon2-time <n>    Argon2id passes (default "
     << vault::kDefaultTimeCost << ").\n"
     << "  --argon2-mem-kb <n>  Argon2id memory in KiB (default "
     << vault::kDefaultMemCostKb << ").\n"
     << "  --from-mnemonic      Prompt for an existing 12-word backup instead\n"
     << "                       of generating a new one (init only).\n"
     << "  --passphrase-words <n>  Words in the generated vault passphrase,\n"
     << "                       " << passphrase::kMinWords << " to "
     << passphrase::kMaxWords << " (default " << passphrase::kDefaultWords
     << "; init and\n"
     << "                       passphrase only). More words means more entropy\n"
     << "                       to write down and type.\n"
     << "  --structured-output  Emit a machine-readable result block on stdout\n"
     << "                       for a GUI that already owns the terminal: init and\n"
     << "                       passphrase replace the human word grids with it\n"
     << "                       (it never puts a phrase in argv or a file), and\n"
     << "                       recv appends it after the body to say whether the\n"
     << "                       message was a file and, if staged, where. It never\n"
     << "                       carries the sender's alias.\n"
     << "  --fingerprint        Print only the identity fingerprint (card only).\n"
     << "  --card <file>        Read a contact card from a file (add only).\n"
     << "  --file <file>        Encrypt a file instead of text (send only).\n"
     << "  --ttl 1h|24h|7d      Mark the message ephemeral: a cooperating "
        "receiver\n"
     << "                       stops showing it after this long (send and "
        "group-send\n"
     << "                       only). Best-effort: it stops neither "
        "screenshots,\n"
     << "                       copies nor a modified client.\n"
     << "  --burn               Mark the message for a single reading "
        "(send and\n"
     << "                       group-send only). Same best-effort promise "
        "as --ttl.\n"
     << "  --to <alias>         Add a group recipient; repeat for each member\n"
     << "                       (group-send only, at least two).\n"
     << "  --stage-file         Stage a received file in the private temporary\n"
     << "                       folder and print its path, without asking on a\n"
     << "                       terminal whether to open it (recv only).\n"
     << "  --stdin-payload <n>  Read exactly <n> bytes from standard input as the\n"
     << "                       message (send, group-send) or block (recv),\n"
     << "                       before the\n"
     << "                       passphrase. For front ends that must not put the\n"
     << "                       plaintext in the child's argv; requires --usb-path\n"
     << "                       or RATCHET_USB_PATH.\n"
     << "  --yes                Skip the interactive confirmation (remove only).\n"
     << "  --confirmed          The fingerprint was shown and the user confirmed\n"
     << "                       intentional trust, not a comparison against\n"
     << "                       another channel. For a front end that showed its\n"
     << "                       own dialog (trust only).\n"
     << "  --show-fingerprint   Print the contact's fingerprint and what marking\n"
     << "                       it verified means, and change nothing in the\n"
     << "                       vault (trust only).\n"
     << "  --expect-fingerprint <fp>\n"
     << "                       With --confirmed: refuse to mark the contact\n"
     << "                       verified unless its fingerprint is still this\n"
     << "                       one, which is the value the front end showed\n"
     << "                       (trust only).\n"
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
      const uint32_t count = parse_u32(next("--otpk-count"), "--otpk-count");
      if (count > kMaxOtpkCount) {
        throw Error("--otpk-count is at most " +
                    std::to_string(kMaxOtpkCount));
      }
      opts.otpk_count = count;
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
      const uint32_t count =
          parse_u32(next("--replenish-otpk"), "--replenish-otpk");
      if (count > kMaxOtpkCount) {
        throw Error("--replenish-otpk is at most " +
                    std::to_string(kMaxOtpkCount));
      }
      opts.replenish_otpk = count;
      note("--replenish-otpk");
    } else if (arg == "--fingerprint") {
      opts.fingerprint_only = true;
      note("--fingerprint");
    } else if (arg == "--from-mnemonic") {
      opts.from_mnemonic = true;
      note("--from-mnemonic");
    } else if (arg == "--structured-output") {
      opts.structured_output = true;
      note("--structured-output");
    } else if (arg == "--passphrase-words") {
      const uint32_t words =
          parse_u32(next("--passphrase-words"), "--passphrase-words");
      if (words < passphrase::kMinWords || words > passphrase::kMaxWords) {
        throw Error("--passphrase-words is between " +
                    std::to_string(passphrase::kMinWords) + " and " +
                    std::to_string(passphrase::kMaxWords));
      }
      opts.passphrase_words = words;
      note("--passphrase-words");
    } else if (arg == "--commit") {
      opts.commit = true;
      note("--commit");
    } else if (arg == "--yes") {
      opts.assume_yes = true;
      note("--yes");
    } else if (arg == "--confirmed") {
      opts.confirmed = true;
      note("--confirmed");
    } else if (arg == "--show-fingerprint") {
      opts.show_fingerprint = true;
      note("--show-fingerprint");
    } else if (arg == "--expect-fingerprint") {
      opts.expect_fingerprint = std::string(next("--expect-fingerprint"));
      note("--expect-fingerprint");
    } else if (arg == "--stage-file") {
      opts.stage_received = true;
      note("--stage-file");
    } else if (arg == "--stdin-payload") {
      const uint32_t bytes =
          parse_u32(next("--stdin-payload"), "--stdin-payload");
      if (bytes == 0) {
        throw Error("--stdin-payload expects a positive byte count");
      }
      opts.stdin_payload_bytes = static_cast<std::size_t>(bytes);
      note("--stdin-payload");
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
    } else if (arg == "--to") {
      opts.group_members.emplace_back(next("--to"));
      note("--to");
    } else if (arg == "--card") {
      opts.card_file = std::string(next("--card"));
      note("--card");
    } else if (arg == "--file") {
      opts.file_path = std::string(next("--file"));
      note("--file");
    } else if (arg == "--ttl") {
      // Fixed buckets, not a duration: a free-form value would be a
      // per-message fingerprint and a clock to argue with. "off" is
      // accepted and means what omitting the flag means.
      const std::string value(next("--ttl"));
      ephemeral::Ttl ttl = ephemeral::Ttl::None;
      if (!ephemeral::parse_ttl(value, ttl)) {
        throw Error("--ttl takes 1h, 24h, 7d or off");
      }
      opts.ttl = ttl;
      note("--ttl");
    } else if (arg == "--burn") {
      opts.burn_after_reading = true;
      note("--burn");
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
