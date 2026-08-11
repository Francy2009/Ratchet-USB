#include "ratchet/secure.hpp"

namespace ratchet {

void init_sodium() {
  static const bool ok = [] {
    // sodium_init() returns 1 if another caller already initialised it, which
    // is not an error.
    return sodium_init() >= 0;
  }();
  if (!ok) {
    throw Error("libsodium initialisation failed");
  }
}

}  // namespace ratchet
