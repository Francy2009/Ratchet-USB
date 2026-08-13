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
};

// Parses the command line with argv[0] already stripped. Throws Error on an
// unknown command, an option the named command does not take, a missing option
// value, or a surplus positional argument.
Options parse_args(const std::vector<std::string_view>& args);

void print_usage(std::ostream& os);

}  // namespace ratchet::cli

#endif  // RATCHET_CLI_HPP
