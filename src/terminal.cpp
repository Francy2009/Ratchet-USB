#include "ratchet/terminal.hpp"

#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <iostream>
#include <string>

namespace ratchet::terminal {
namespace {

// Turns echo off for the lifetime of the object and puts it back afterwards,
// including when read_passphrase throws.
class EchoOff {
 public:
  EchoOff() {
    if (!isatty(STDIN_FILENO)) {
      return;
    }
    if (tcgetattr(STDIN_FILENO, &saved_) != 0) {
      return;
    }
    struct termios quiet = saved_;
    quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
    quiet.c_lflag |= ECHONL;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0) {
      active_ = true;
    }
  }

  ~EchoOff() {
    if (active_) {
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_);
    }
  }

  EchoOff(const EchoOff&) = delete;
  EchoOff& operator=(const EchoOff&) = delete;

 private:
  struct termios saved_{};
  bool active_ = false;
};

// A command that reads a message from stdin first (`send` with no message
// argument) leaves stdin's end-of-file indicator latched by the Ctrl-D that
// ended it. Every later fgetc would then return EOF without waiting, so the
// passphrase prompt failed outright on a terminal where the user is perfectly
// able to keep typing. Clearing it costs nothing on a pipe: the read simply
// hits EOF again and the caller reports the missing value as before.
void clear_stale_eof() {
  if (std::feof(stdin) != 0) {
    std::clearerr(stdin);
  }
}

// Puts the terminal into cbreak mode for the lifetime of the object: canonical
// mode and echo off, so a single key is delivered without a newline and does
// not appear on screen. Restores the previous settings on the way out, including
// when the read throws. A no-op when stdin is not a tty.
class Cbreak {
 public:
  Cbreak() {
    if (!isatty(STDIN_FILENO)) {
      return;
    }
    if (tcgetattr(STDIN_FILENO, &saved_) != 0) {
      return;
    }
    struct termios mode = saved_;
    mode.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
    mode.c_cc[VMIN] = 1;
    mode.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &mode) == 0) {
      active_ = true;
    }
  }

  ~Cbreak() {
    if (active_) {
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_);
    }
  }

  Cbreak(const Cbreak&) = delete;
  Cbreak& operator=(const Cbreak&) = delete;

 private:
  struct termios saved_{};
  bool active_ = false;
};

}  // namespace

bool stdin_is_tty() { return isatty(STDIN_FILENO) != 0; }

bool stdout_is_tty() { return isatty(STDOUT_FILENO) != 0; }

std::string escape_control_chars(std::string_view text) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    const auto c = static_cast<unsigned char>(ch);
    // Newline and tab are the two controls a message legitimately contains.
    const bool is_control =
        (c < 0x20 || c == 0x7F) && c != '\n' && c != '\t';
    if (is_control) {
      out += "\\x";
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 0x0F]);
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

std::string escape_if_tty(std::string_view text) {
  return stdout_is_tty() ? escape_control_chars(text) : std::string(text);
}

SecureString read_passphrase(const std::string& prompt) {
  clear_stale_eof();

  // Prompts go to stderr, not stdout: stdout carries the payload a command is
  // there to produce (a contact card, a message block), so `card > file` has to
  // stay free of anything but the block itself.
  std::cerr << prompt << std::flush;

  EchoOff guard;
  SecureString out;
  int c;
  // Read a character at a time: std::getline would leave a copy of the
  // passphrase in a std::string whose buffer we cannot reliably wipe.
  while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
    if (c == '\r') {
      continue;
    }
    out.push_back(static_cast<char>(c));
  }
  if (c == EOF && out.empty()) {
    std::cerr << "\n";
    throw Error("no passphrase on standard input");
  }
  if (!stdin_is_tty()) {
    // No ECHONL to print the newline for us.
    std::cerr << "\n";
  }
  return out;
}

SecureString read_word_phrase(const std::string& prompt) {
  clear_stale_eof();

  std::cerr << prompt << std::flush;

  EchoOff guard;
  SecureString out;
  bool any = false;
  for (;;) {
    // One line at a time, into a SecureString: std::getline would leave a copy
    // of the passphrase in a std::string whose buffer we cannot reliably wipe.
    SecureString line;
    int c;
    while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
      if (c == '\r') {
        continue;
      }
      line.push_back(static_cast<char>(c));
    }
    const bool at_eof = (c == EOF);
    // A blank line ends the passphrase, as does end of input. Requiring only
    // end of input made a legacy single-line passphrase impossible to enter
    // with Enter alone -- the prompt simply sat there waiting for a Ctrl-D the
    // user had no reason to know about. With the blank line, a legacy
    // passphrase is typed and confirmed with Enter, Enter, and a word phrase
    // is one word per line followed by an empty line (or Ctrl-D).
    if (line.empty()) {
      break;
    }
    if (any) {
      out.push_back(' ');
    }
    for (std::size_t i = 0; i < line.size(); ++i) {
      out.push_back(line.data()[i]);
    }
    any = true;
    if (at_eof) {
      break;
    }
  }

  if (!any) {
    std::cerr << "\n";
    throw Error("no passphrase on standard input");
  }
  if (!stdin_is_tty()) {
    // No ECHONL to print the final newline for us.
    std::cerr << "\n";
  }
  return out;
}

void wait_for_enter(const std::string& prompt) {
  if (!stdin_is_tty()) {
    return;
  }
  std::cerr << prompt << std::flush;
  int c;
  while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
  }
}

bool confirm_enter_or_escape(const std::string& prompt) {
  clear_stale_eof();
  std::cerr << prompt << std::flush;

  Cbreak guard;
  bool confirmed = false;
  int c;
  while ((c = std::fgetc(stdin)) != EOF) {
    if (c == '\n' || c == '\r') {
      confirmed = true;
      break;
    }
    if (c == 0x1B) {
      confirmed = false;
      break;
    }
  }
  // Echo is off, so nothing printed the newline the user expects after a key.
  std::cerr << "\n";
  return confirmed;
}

std::string read_line(const std::string& prompt) {
  if (!stdin_is_tty()) {
    return {};
  }
  clear_stale_eof();
  std::cerr << prompt << std::flush;

  std::string out;
  int c;
  while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
    if (c == '\r') {
      continue;
    }
    out.push_back(static_cast<char>(c));
  }
  return out;
}

void clear_screen() {
  if (isatty(STDOUT_FILENO) == 0) {
    return;
  }
  // Clear screen, clear scrollback, cursor home.
  std::cout << "\033[2J\033[3J\033[H" << std::flush;
}

}  // namespace ratchet::terminal
