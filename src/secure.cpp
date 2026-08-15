#include "ratchet/secure.hpp"

#include <sys/resource.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

namespace ratchet {

bool harden_process() noexcept {
  bool all_applied = true;

  // Core dumps: refuse to produce one at all, however the process dies.
  const struct rlimit no_core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
    all_applied = false;
  }

#if defined(__linux__)
  // Clearing the dumpable flag also stops a same-user process from attaching
  // with ptrace, which is the other way memory leaves this process uninvited.
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    all_applied = false;
  }
#else
  // On macOS the equivalent is PT_DENY_ATTACH, which is not portable and which
  // this project has no way to test today. RLIMIT_CORE above still applies.
  all_applied = false;
#endif

  return all_applied;
}

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
