#include <iostream>

#include "ratchet/secure.hpp"
#include "test_support.hpp"

int main() {
  ratchet::init_sodium();
  std::cout << "Ratchet-USB test suite\n\n";
  return ratchet::test::run_all();
}
