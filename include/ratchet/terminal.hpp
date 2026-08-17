#ifndef RATCHET_TERMINAL_HPP
#define RATCHET_TERMINAL_HPP

#include <string>
#include <string_view>

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
bool stdout_is_tty();

// Rewrites the C0 control characters and DEL as visible \xNN escapes, leaving
// newline and tab alone.
//
// A decrypted message comes from a sender who is authenticated but not
// trusted, and a terminal treats what it is handed as instructions, not text.
// An unescaped ESC lets the sender move the cursor, erase lines that are
// already on screen -- including the "has not been marked as trusted" warning
// printed moments earlier -- repaint them with something else, set the window
// title, or on terminals that allow it write the system clipboard with OSC 52.
//
// Bytes 0x80-0x9F are deliberately left alone. They are the C1 controls only
// in a non-UTF-8 terminal; in UTF-8, which is what anything current uses, they
// are continuation bytes, and escaping them would mangle every message that is
// not pure ASCII.
std::string escape_control_chars(std::string_view text);

// escape_control_chars, but only when stdout is a terminal. A redirect to a
// file or a pipe gets the bytes exactly as the sender wrote them, because
// there is no terminal to drive and mangling the text would be the bug.
std::string escape_if_tty(std::string_view text);

}  // namespace ratchet::terminal

#endif  // RATCHET_TERMINAL_HPP
