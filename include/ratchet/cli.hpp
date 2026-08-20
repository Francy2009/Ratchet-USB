#ifndef RATCHET_CLI_HPP
#define RATCHET_CLI_HPP

#include <cstddef>
#include <filesystem>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/vault.hpp"

// Command-line parsing, kept out of main.cpp so it can be tested directly:
// the argument grammar is where a mistake silently changes what a command does,
// which is exactly the sort of thing a test should pin down.
namespace ratchet::cli {

inline constexpr const char* kProgram = "ratchet-usb";
inline constexpr const char* kVersion = "0.2.0";
inline constexpr std::size_t kDefaultOtpkCount = 10;
// How long the terminal interface waits before closing the vault on its own.
inline constexpr int kDefaultIdleLockSeconds = 180;
inline constexpr int kMaxIdleLockSeconds = 24 * 60 * 60;

struct Options {
  std::string command;
  std::filesystem::path usb_path;
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
  // Terminal interface only.
  std::string lang;  // empty means "work it out from the locale"
  int idle_lock_seconds = kDefaultIdleLockSeconds;
  // True when the program was run with nothing after its name. The interface
  // is what that means on a terminal; off a terminal it has to stay the error
  // it has always been, and only the caller can tell the difference.
  bool no_arguments = false;
};

// Parses the command line with argv[0] already stripped. Throws Error on an
// unknown command, an option the named command does not take, a missing option
// value, or a surplus positional argument.
//
// An empty command line is the one case that does not throw: it yields the
// `ui` command with no_arguments set. Whether that can actually run is a
// question about the terminal, and this parser deliberately knows nothing
// about terminals -- it stays a pure function of its arguments, which is what
// makes the grammar testable.
Options parse_args(const std::vector<std::string_view>& args);

void print_usage(std::ostream& os);

}  // namespace ratchet::cli

#endif  // RATCHET_CLI_HPP
