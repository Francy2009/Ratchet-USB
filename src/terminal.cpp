#include "ratchet/terminal.hpp"

#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <iostream>

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

}  // namespace

bool stdin_is_tty() { return isatty(STDIN_FILENO) != 0; }

SecureString read_passphrase(const std::string& prompt) {
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

SecureString read_new_passphrase(const std::string& prompt,
                                 const std::string& confirm_prompt) {
  SecureString first = read_passphrase(prompt);
  if (first.empty()) {
    throw Error("passphrase must not be empty");
  }
  SecureString second = read_passphrase(confirm_prompt);
  if (!first.equals(second)) {
    throw Error("the two passphrases do not match");
  }
  return first;
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

std::string read_line(const std::string& prompt) {
  if (!stdin_is_tty()) {
    return {};
  }
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
