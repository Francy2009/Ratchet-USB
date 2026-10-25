#include <iostream>
#include <string>
#include <string_view>

#include "ratchet/secure.hpp"
#include "test_support.hpp"

int main(int argc, char** argv) {
  ratchet::init_sodium();
  std::string filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--list") {
      list_only = true;
    } else if (arg == "--filter") {
      if (i + 1 >= argc) {
        std::cerr << "--filter needs a value\n";
        return 2;
      }
      filter = argv[++i];
    } else if (arg.rfind("--filter=", 0) == 0) {
      filter = std::string(arg.substr(std::string_view("--filter=").size()));
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "usage: ratchet_tests [--list] [--filter <substring>]\n";
      return 0;
    } else {
      std::cerr << "unknown argument: " << arg << "\n";
      return 2;
    }
  }
  std::cout << "Ratchet-USB test suite\n\n";
  return ratchet::test::run_all(filter, list_only);
}
