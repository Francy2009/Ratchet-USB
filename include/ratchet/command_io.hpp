#ifndef RATCHET_COMMAND_IO_HPP
#define RATCHET_COMMAND_IO_HPP

#include <cstddef>
#include <filesystem>
#include <istream>
#include <optional>
#include <string>

#include "ratchet/app.hpp"
#include "ratchet/cli.hpp"
#include "ratchet/store.hpp"

// The pieces of the command-line front end that are not a command: resolving
// the drive, reading a value or a secret, opening the vault, and the small
// pieces of maintenance output `unlock` has always printed.
//
// These used to live in the anonymous namespace of main.cpp. Splitting them out
// leaves main.cpp as the process entry point and `commands` as the handlers,
// and keeps the helpers -- the code that decides where the vault is and how a
// passphrase is read -- in one place both can be read against.
namespace ratchet::commands {

// Where the vault lives. Resolved in this order: --usb-path, the
// RATCHET_USB_PATH environment variable, an auto-detected removable drive, and
// finally a prompt.
//
// `for_init` splits the two questions being asked. Every other command wants a
// drive that already holds a vault, so a single match can be offered straight
// away. `init` is about to write, so it looks at removable drives generally and
// always asks before touching one -- guessing would be the one mistake this
// tool cannot afford.
std::filesystem::path require_usb_path(const cli::Options& opts,
                                       bool for_init = false);

// Best-effort warning when the given path sits on the same filesystem as the
// user's home directory, which usually means it is the host disk rather than a
// removable drive. It stays a warning: a mount layout cannot be told apart
// from a removable one with certainty.
void warn_if_host_disk(const std::filesystem::path& usb_path);

// Falls back to an interactive prompt for a required, non-secret value (an
// alias, a contact name) when it was not passed as a flag and stdin is a
// terminal; throws Error otherwise.
std::string require_value(const std::string& value, const std::string& prompt,
                          const char* flag_error);

// Reads and validates the vault container, prompts for the passphrase and
// opens it. Which prompt is shown follows the vault itself: a v4 vault was
// sealed with a generated word phrase and asks for it one word per line, while
// a v3 vault keeps the classic single-line password prompt. `label` names what
// is being asked for ("Vault passphrase", "Current vault passphrase").
// Throws before the prompt if the path holds no vault, so a mistyped path does
// not ask for a secret first.
app::OpenedVault unlock_vault(const std::filesystem::path& path,
                              const std::string& label = "Vault passphrase");

std::string read_bounded(std::istream& input, std::size_t max_bytes,
                         const char* what);

std::string read_text_arg_or_stdin(const std::optional<std::string>& arg,
                                   const char* prompt_if_tty,
                                   std::size_t max_bytes);

std::string read_file_text(const std::string& path, std::size_t max_bytes);

// Runs the automatic maintenance and prints what it did, in the wording
// `unlock` has always used. The decisions themselves live in app.cpp, so the
// terminal interface applies exactly the same rules.
bool maintain_prekeys(store::VaultStore& store,
                      const IdentitySigningPublicKey& identity_pk,
                      const IdentitySigningSecretKey& identity_sk);

// Throws away skipped message keys nobody claimed in time and reports how many
// were dropped. Returns whether anything was dropped (and so whether the store
// needs saving).
bool expire_skipped_keys(store::VaultStore& store);

}  // namespace ratchet::commands

#endif  // RATCHET_COMMAND_IO_HPP
