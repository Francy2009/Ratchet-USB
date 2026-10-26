#ifndef RATCHET_CLI_HPP
#define RATCHET_CLI_HPP

#include <cstddef>
#include <filesystem>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/passphrase.hpp"
#include "ratchet/vault.hpp"

// Command-line parsing, kept out of main.cpp so it can be tested directly:
// the argument grammar is where a mistake silently changes what a command does,
// which is exactly the sort of thing a test should pin down.
namespace ratchet::cli {

inline constexpr const char* kProgram = "ratchet-usb";
inline constexpr const char* kVersion = "0.5.0-dev";
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
  // init/passphrase --structured-output: replace the human word grids with the
  // machine-readable block in ratchet/gui_format.hpp. The default output is
  // untouched. The block is on stdout; it is not put in argv, a file or a log.
  bool structured_output = false;
  bool commit = false;
  // remove --yes: skip the interactive confirmation. The GUI asks with its own
  // dialog first and has no terminal to type the confirmation into.
  bool assume_yes = false;
  // recv --stage-file: stage a received file in the private temporary folder and
  // print its path, instead of asking on a terminal whether to open it. For a
  // front end with no terminal (the GUI) to hand the file to the user.
  bool stage_received = false;
  // Words in the generated vault passphrase (init and passphrase). Six by
  // default; see ratchet/passphrase.hpp for the entropy this buys.
  std::size_t passphrase_words = passphrase::kDefaultWords;
  std::string name;
  std::string to;
  std::string card_file;
  std::string file_path;  // send --file: encrypt a file instead of text
  std::optional<std::string> message;
  // send/recv --stdin-payload: the exact number of bytes to read from standard
  // input as the message or block *before* the vault passphrase.
  //
  // This exists for front ends that must not put plaintext in the child's argv
  // (the desktop GUI): argv is visible in /proc to every process of the same
  // user, while a pipe is not. A length is needed because a message can contain
  // newlines and blank lines, so no delimiter would be unambiguous. The option
  // is rejected for every other command; it is not a second way to type a
  // message.
  std::optional<std::size_t> stdin_payload_bytes;
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
