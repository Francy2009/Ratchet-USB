// The argument parser is the first thing a hostile or simply mistyped command
// line reaches, and it decides what every other command is allowed to do. It
// must reject anything it likes, but it must not crash, over-read, or hang.
//
// The first part of an input is argv-like: NUL separates arguments, so one
// input can describe a whole command line.

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "ratchet/cli.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::vector<std::string_view> args;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= size && args.size() < 64; ++i) {
    if (i == size || data[i] == 0) {
      args.emplace_back(reinterpret_cast<const char*>(data + start), i - start);
      start = i + 1;
    }
  }
  try {
    (void)ratchet::cli::parse_args(args);
  } catch (...) {
    // Rejecting input is the expected outcome for most of it.
  }
  return 0;
}
