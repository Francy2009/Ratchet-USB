// Ratchet-USB -- hybrid PQXDH identity/handshake migration in progress.
//
// Everything sensitive lives on the removable drive passed as --usb-path;
// nothing is ever written to the host's filesystem.
//
// This file is only the process entry point: it hardens the process before any
// secret exists, parses the command line, and hands the parsed command to
// ratchet::commands::run. The command handlers live in src/commands.cpp and the
// shared helpers they use in src/command_io.cpp.

#include <exception>
#include <iostream>
#include <string_view>
#include <vector>

#include "ratchet/cli.hpp"
#include "ratchet/commands.hpp"
#include "ratchet/secure.hpp"

int main(int argc, char** argv) {
  try {
    // Before anything else, and before any secret exists to protect: from here
    // on a crash cannot write a core dump and a sibling process cannot attach.
    ratchet::harden_process();
    ratchet::init_sodium();
    const ratchet::cli::Options opts = ratchet::cli::parse_args(
        std::vector<std::string_view>(argv + 1, argv + argc));
    return ratchet::commands::run(opts);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
