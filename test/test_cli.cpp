#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/cli.hpp"
#include "ratchet/command_io.hpp"
#include "test_support.hpp"

using namespace ratchet;
using ratchet::cli::Options;

namespace {

Options parse(std::vector<std::string_view> args) {
  return cli::parse_args(args);
}

}  // namespace

TEST("cli: no arguments asks for the interface, and says so") {
  // Whether the interface can actually run is a question about the terminal,
  // which this parser deliberately knows nothing about. It reports that there
  // were no arguments; main turns that back into the error it has always been
  // when the input or the output is redirected.
  const Options opts = parse({});
  CHECK_EQ(opts.command, std::string("ui"));
  CHECK(opts.no_arguments);
}

TEST("cli: an explicit ui is not the same as no arguments") {
  const Options opts = parse({"ui"});
  CHECK_EQ(opts.command, std::string("ui"));
  CHECK(!opts.no_arguments);
}

TEST("cli: ui takes a language and an idle timeout") {
  const Options opts = parse({"ui", "--lang", "it", "--idle-lock", "60"});
  CHECK_EQ(opts.lang, std::string("it"));
  CHECK_EQ(opts.idle_lock_seconds, 60);
  // Zero is a real answer: it turns the idle lock off.
  CHECK_EQ(parse({"ui", "--idle-lock", "0"}).idle_lock_seconds, 0);
  CHECK_EQ(parse({"ui"}).idle_lock_seconds, cli::kDefaultIdleLockSeconds);
}

TEST("cli: a language that is not one of the two is refused") {
  CHECK_THROWS(parse({"ui", "--lang", "fr"}));
  CHECK_THROWS(parse({"ui", "--lang"}));
  // An idle timeout longer than a day is a typo, not a preference.
  CHECK_THROWS(parse({"ui", "--idle-lock", "999999"}));
  CHECK_THROWS(parse({"ui", "--idle-lock", "-1"}));
}

TEST("cli: the interface flags belong to the interface alone") {
  CHECK_THROWS(parse({"send", "alice", "--lang", "it"}));
  CHECK_THROWS(parse({"recv", "--idle-lock", "10"}));
  // And ui takes none of the vault-shaping flags.
  CHECK_THROWS(parse({"ui", "--force"}));
  CHECK_THROWS(parse({"ui", "--argon2-time", "4"}));
}

TEST("cli: help and version short-circuit before command checks") {
  CHECK_EQ(parse({"--help"}).command, std::string("help"));
  CHECK_EQ(parse({"-h"}).command, std::string("help"));
  CHECK_EQ(parse({"--version"}).command, std::string("version"));
  CHECK_EQ(parse({"-V"}).command, std::string("version"));
  // A command in front does not change that.
  CHECK_EQ(parse({"send", "--help"}).command, std::string("help"));
}

TEST("cli: unknown command and unknown option are rejected") {
  CHECK_THROWS(parse({"frobnicate"}));
  CHECK_THROWS(parse({"contacts", "--bogus"}));
}

TEST("cli: the command has to come first") {
  CHECK_THROWS(parse({"--usb-path", "/media/usb", "contacts"}));
}

TEST("cli: usb-path is read as a value") {
  const Options opts = parse({"contacts", "--usb-path", "/media/usb"});
  CHECK_EQ(opts.command, std::string("contacts"));
  CHECK_EQ(opts.usb_path.string(), std::string("/media/usb"));
}

TEST("cli: an option that needs a value complains when it is missing") {
  CHECK_THROWS(parse({"contacts", "--usb-path"}));
  CHECK_THROWS(parse({"add", "alice", "--card"}));
  CHECK_THROWS(parse({"init", "--otpk-count"}));
}

TEST("cli: numeric options reject non-numbers") {
  CHECK_THROWS(parse({"init", "--otpk-count", "twelve"}));
  CHECK_THROWS(parse({"init", "--argon2-time", "3x"}));
  CHECK_THROWS(parse({"init", "--argon2-mem-kb", ""}));
}

TEST("cli: numeric options are parsed") {
  const Options opts =
      parse({"init", "--otpk-count", "7", "--argon2-time", "4",
             "--argon2-mem-kb", "65536"});
  CHECK_EQ(opts.otpk_count, static_cast<std::size_t>(7));
  CHECK_EQ(opts.params.time_cost, static_cast<uint32_t>(4));
  CHECK_EQ(opts.params.mem_cost_kb, static_cast<uint32_t>(65536));
}

// --- the generated passphrase ------------------------------------------------

TEST("cli: passphrase-words is parsed and bounded") {
  CHECK_EQ(parse({"init", "--passphrase-words", "8"}).passphrase_words,
           static_cast<std::size_t>(8));
  CHECK_EQ(parse({"passphrase", "--passphrase-words", "12"}).passphrase_words,
           static_cast<std::size_t>(12));
  // Five words is 55 bits, under the floor, so it is refused rather than
  // quietly accepted.
  CHECK_THROWS(parse({"init", "--passphrase-words", "5"}));
  CHECK_THROWS(parse({"init", "--passphrase-words", "0"}));
  CHECK_THROWS(parse({"init", "--passphrase-words", "13"}));
  CHECK_THROWS(parse({"init", "--passphrase-words", "eight"}));
  // Only the two commands that generate a passphrase take it.
  CHECK_THROWS(parse({"unlock", "--passphrase-words", "8"}));
}

TEST("cli: passphrase is a command with its own options") {
  CHECK_EQ(parse({"passphrase"}).command, std::string("passphrase"));
  CHECK_EQ(parse({"passphrase", "--usb-path", "/x"}).usb_path.string(),
           std::string("/x"));
  CHECK_THROWS(parse({"passphrase", "extra"}));
  CHECK_THROWS(parse({"passphrase", "--force"}));
}

// --- positional arguments ----------------------------------------------------

TEST("cli: add, trust and remove take the alias positionally") {
  CHECK_EQ(parse({"add", "alice"}).name, std::string("alice"));
  CHECK_EQ(parse({"trust", "alice"}).name, std::string("alice"));
  CHECK_EQ(parse({"remove", "alice"}).name, std::string("alice"));
}

TEST("cli: send takes an alias then a message") {
  const Options opts = parse({"send", "alice", "hi there"});
  CHECK_EQ(opts.to, std::string("alice"));
  CHECK(opts.message.has_value());
  CHECK_EQ(*opts.message, std::string("hi there"));
}

TEST("cli: a missing positional is left unset rather than defaulted") {
  const Options opts = parse({"send", "alice"});
  CHECK_EQ(opts.to, std::string("alice"));
  CHECK(!opts.message.has_value());
  CHECK(parse({"recv"}).message.has_value() == false);
  CHECK(parse({"trust"}).name.empty());
}

TEST("cli: recv takes the message positionally") {
  const Options opts = parse({"recv", "some text"});
  CHECK(opts.message.has_value());
  CHECK_EQ(*opts.message, std::string("some text"));
}

TEST("cli: surplus positionals are rejected per command") {
  CHECK_THROWS(parse({"trust", "alice", "bob"}));
  CHECK_THROWS(parse({"send", "alice", "hi", "extra"}));
  CHECK_THROWS(parse({"recv", "one", "two"}));
  CHECK_THROWS(parse({"contacts", "alice"}));
  CHECK_THROWS(parse({"init", "alice"}));
}

// An armored block opens with five dashes, which the parser used to mistake for
// an option; `recv "$(cat msg.txt)"` failed outright as a result.
TEST("cli: a pasted armored block is a value, not an option") {
  const std::string block =
      "-----BEGIN RATCHET MESSAGE-----\nAAAA\n-----END RATCHET MESSAGE-----\n";
  const Options opts = parse({"recv", block});
  CHECK(opts.message.has_value());
  CHECK_EQ(*opts.message, block);

  const std::string card =
      "-----BEGIN RATCHET CARD-----\nBBBB\n-----END RATCHET CARD-----\n";
  const Options sent = parse({"send", "alice", card});
  CHECK_EQ(sent.to, std::string("alice"));
  CHECK_EQ(*sent.message, card);
}

TEST("cli: a bare -- ends option parsing") {
  const Options opts = parse({"send", "alice", "--", "-not-an-option"});
  CHECK_EQ(opts.to, std::string("alice"));
  CHECK_EQ(*opts.message, std::string("-not-an-option"));

  // Without it, a leading dash is still an error rather than a silent value.
  CHECK_THROWS(parse({"send", "alice", "-not-an-option"}));
}

TEST("cli: -- does not swallow the surplus check") {
  CHECK_THROWS(parse({"trust", "--", "alice", "bob"}));
}

// --- per-command option validation ------------------------------------------
//
// Options used to be accepted for every command and quietly ignored, so
// `contacts --force --otpk-count 99` exited successfully having done nothing
// with either.

TEST("cli: options are rejected for commands that do not take them") {
  CHECK_THROWS(parse({"send", "alice", "hi", "--force"}));
  CHECK_THROWS(parse({"contacts", "--otpk-count", "99"}));
  CHECK_THROWS(parse({"unlock", "--fingerprint"}));
  CHECK_THROWS(parse({"recv", "--from-mnemonic"}));
  CHECK_THROWS(parse({"send", "alice", "hi", "--card", "f.txt"}));
  CHECK_THROWS(parse({"trust", "alice", "--rotate-spk"}));
  CHECK_THROWS(parse({"trust", "alice", "--yes"}));
  CHECK_THROWS(parse({"init", "--replenish-otpk", "5"}));
}

TEST("cli: each command still accepts its own options") {
  CHECK(parse({"init", "--force", "--from-mnemonic"}).from_mnemonic);
  CHECK(parse({"card", "--fingerprint"}).fingerprint_only);
  CHECK(parse({"card", "--rotate-spk"}).rotate_spk);
  CHECK(parse({"migrate", "--commit"}).commit);
  CHECK(parse({"remove", "alice", "--yes"}).assume_yes);
  CHECK_EQ(parse({"card", "--replenish-otpk", "10"}).replenish_otpk,
           static_cast<std::size_t>(10));
  CHECK_EQ(parse({"add", "alice", "--card", "a.txt"}).card_file,
           std::string("a.txt"));
  // --usb-path is common to all of them.
  for (const std::string_view command :
       {"init", "unlock", "anchor", "migrate", "card", "contacts"}) {
    CHECK_EQ(parse({command, "--usb-path", "/x"}).usb_path.string(),
             std::string("/x"));
  }
}

TEST("cli: structured output is opt-in for init and passphrase only") {
  CHECK(!parse({"init"}).structured_output);
  CHECK(parse({"init", "--structured-output"}).structured_output);
  CHECK(parse({"passphrase", "--structured-output"}).structured_output);
  CHECK_THROWS(parse({"init", "--structured-output=false"}));
  CHECK_THROWS(parse({"unlock", "--structured-output"}));
  CHECK_THROWS(parse({"send", "alice", "hi", "--structured-output"}));
  CHECK_THROWS(parse({"contacts", "--structured-output"}));
}

// --- the front-end payload channel -----------------------------------------

TEST("cli: --stdin-payload is parsed for send and recv only") {
  const Options sent = parse({"send", "--stdin-payload", "7", "alice"});
  CHECK(sent.stdin_payload_bytes.has_value());
  CHECK_EQ(*sent.stdin_payload_bytes, std::size_t{7});
  CHECK_EQ(sent.to, std::string("alice"));
  CHECK(!sent.message.has_value());

  const Options received = parse({"recv", "--stdin-payload", "9"});
  CHECK(received.stdin_payload_bytes.has_value());
  CHECK_EQ(*received.stdin_payload_bytes, std::size_t{9});

  // Zero is not a payload, and the option is not a general flag.
  CHECK_THROWS(parse({"send", "--stdin-payload", "0", "alice"}));
  CHECK_THROWS(parse({"send", "--stdin-payload", "x", "alice"}));
  CHECK_THROWS(parse({"send", "--stdin-payload"}));
  CHECK_THROWS(parse({"contacts", "--stdin-payload", "4"}));
  CHECK_THROWS(parse({"init", "--stdin-payload", "4"}));
}

TEST("command_io: read_exact stops exactly where the passphrase begins") {
  // A payload with a blank line inside it, followed by a word-passphrase
  // shaped stream. The count is what separates them; no delimiter could.
  // Exactly the GUI shape: payload bytes, then the passphrase with no
  // separator. The length is what makes the boundary unambiguous.
  const std::string input =
      std::string("line one\n\nline three") + "word one word two\n\n";
  std::istringstream in(input);
  const std::string payload = commands::read_exact(in, 20, "message");
  CHECK_EQ(payload, std::string("line one\n\nline three"));

  std::string rest;
  std::getline(in, rest);
  CHECK_EQ(rest, std::string("word one word two"));
}

TEST("command_io: read_exact preserves NUL and UTF-8 bytes") {
  std::string input;
  input.append("a\0b", 3);
  input += "città";  // UTF-8, not one byte per character
  input += "TAIL";
  std::istringstream in(input);
  const std::string payload = commands::read_exact(in, 9, "message");
  CHECK_EQ(payload.size(), std::size_t{9});
  CHECK_EQ(payload.substr(0, 3), std::string("a\0b", 3));
  CHECK_EQ(payload.substr(3, 6), std::string("città"));
}

TEST("command_io: read_exact refuses a stream that ends early") {
  std::istringstream in("short");
  CHECK_THROWS(commands::read_exact(in, 10, "message"));
}

TEST("cli: defaults are what the help text advertises") {
  const Options opts = parse({"init"});
  CHECK_EQ(opts.otpk_count, cli::kDefaultOtpkCount);
  CHECK_EQ(opts.params.time_cost, vault::kDefaultTimeCost);
  CHECK_EQ(opts.params.mem_cost_kb, vault::kDefaultMemCostKb);
  CHECK(!opts.force);
  CHECK(!opts.from_mnemonic);
  CHECK(!opts.fingerprint_only);
  CHECK(!opts.rotate_spk);
  CHECK_EQ(opts.replenish_otpk, static_cast<std::size_t>(0));
  CHECK_EQ(opts.passphrase_words, passphrase::kDefaultWords);
  CHECK(opts.usb_path.empty());
}
