#ifndef RATCHET_COMMANDS_HPP
#define RATCHET_COMMANDS_HPP

#include "ratchet/cli.hpp"

// The command handlers, one per `ratchet-usb` command, and the dispatcher that
// picks between them. main.cpp is only the process entry point around this.
namespace ratchet::commands {

// Runs the command named by `opts` and returns the process exit code. Throws
// Error for anything the user did wrong (an unknown command, a missing value);
// main.cpp turns that into the one-line message and exit status 1 it has always
// used.
int run(const cli::Options& opts);

}  // namespace ratchet::commands

#endif  // RATCHET_COMMANDS_HPP
