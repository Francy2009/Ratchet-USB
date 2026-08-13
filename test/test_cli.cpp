#include <string>
#include <string_view>
#include <vector>

#include "ratchet/cli.hpp"
#include "test_support.hpp"

using namespace ratchet;
using ratchet::cli::Options;

namespace {

Options parse(std::vector<std::string_view> args) {
  return cli::parse_args(args);
}

}  // namespace

TEST("cli: no arguments is an error") {
  CHECK_THROWS(parse({}));
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

// --- positional arguments ----------------------------------------------------

TEST("cli: add and trust take the alias positionally") {
  CHECK_EQ(parse({"add", "alice"}).name, std::string("alice"));
  CHECK_EQ(parse({"trust", "alice"}).name, std::string("alice"));
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
  CHECK_THROWS(parse({"init", "--replenish-otpk", "5"}));
}

TEST("cli: each command still accepts its own options") {
  CHECK(parse({"init", "--force", "--from-mnemonic"}).from_mnemonic);
  CHECK(parse({"card", "--fingerprint"}).fingerprint_only);
  CHECK(parse({"card", "--rotate-spk"}).rotate_spk);
  CHECK_EQ(parse({"card", "--replenish-otpk", "10"}).replenish_otpk,
           static_cast<std::size_t>(10));
  CHECK_EQ(parse({"add", "alice", "--card", "a.txt"}).card_file,
           std::string("a.txt"));
  // --usb-path is common to all of them.
  for (const std::string_view command :
       {"init", "unlock", "card", "contacts"}) {
    CHECK_EQ(parse({command, "--usb-path", "/x"}).usb_path.string(),
             std::string("/x"));
  }
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
  CHECK(opts.usb_path.empty());
}
