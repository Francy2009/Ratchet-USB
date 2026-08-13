#ifndef RATCHET_TERMINAL_HPP
#define RATCHET_TERMINAL_HPP

#include <string>

#include "ratchet/secure.hpp"

namespace ratchet::terminal {

// Reads a line from the terminal with echo disabled, and restores the terminal
// state even if the read fails. When stdin is not a tty (a pipe, a test
// harness) the line is read as-is, since there is no echo to switch off.
SecureString read_passphrase(const std::string& prompt);

// Reads a passphrase twice and checks the two match, to catch typos before
// anything is encrypted with them.
SecureString read_new_passphrase(const std::string& prompt,
                                 const std::string& confirm_prompt);

// Waits for ENTER. No-op when stdin is not a tty.
void wait_for_enter(const std::string& prompt);

// Prints prompt and reads one line with normal echo, for values that are not
// secret (a path, an alias). Returns an empty string on EOF or when stdin is
// not a tty, so callers can fall back to treating the value as missing.
std::string read_line(const std::string& prompt);

// Clears the screen and the scrollback buffer, so the mnemonic does not stay
// visible behind the session. Only emitted when stdout is a tty.
void clear_screen();

bool stdin_is_tty();

}  // namespace ratchet::terminal

#endif  // RATCHET_TERMINAL_HPP
