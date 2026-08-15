#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#include "ratchet/secure.hpp"
#include "test_support.hpp"

namespace ratchet::test {
namespace {

// harden_process() is checked in a forked child rather than here, for two
// reasons: it is process-global and irreversible, so calling it in the test
// runner would silently apply to every test after this one, and clearing the
// dumpable flag on the runner itself is a poor thing to do to whoever is
// debugging a failure.
//
// The child reports through its exit status: 0 for both limits applied, and a
// distinct code per failure so a broken assertion says which one broke.
TEST("harden_process disables core dumps and ptrace attachment") {
  const pid_t pid = fork();
  CHECK(pid >= 0);

  if (pid == 0) {
    if (!harden_process()) {
      _exit(10);  // reported failure on a platform where both should work
    }

    struct rlimit core {};
    if (getrlimit(RLIMIT_CORE, &core) != 0) {
      _exit(11);
    }
    // A dump of size zero is never written, which is the property that keeps
    // key material off the host's disk when the process dies badly.
    if (core.rlim_cur != 0 || core.rlim_max != 0) {
      _exit(12);
    }

#if defined(__linux__)
    if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
      _exit(13);
    }
#endif

    _exit(0);
  }

  int status = 0;
  CHECK(waitpid(pid, &status, 0) == pid);
  CHECK(WIFEXITED(status));
  CHECK_EQ(WEXITSTATUS(status), 0);
}

// The negative control for the test above: without harden_process, a fresh
// process is dumpable and its core limit is whatever it inherited. If this ever
// starts matching the hardened state on its own, the test above stops proving
// anything and would keep passing regardless.
TEST("a process that has not been hardened is still dumpable") {
#if defined(__linux__)
  const pid_t pid = fork();
  CHECK(pid >= 0);

  if (pid == 0) {
    _exit(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1 ? 0 : 1);
  }

  int status = 0;
  CHECK(waitpid(pid, &status, 0) == pid);
  CHECK(WIFEXITED(status));
  CHECK_EQ(WEXITSTATUS(status), 0);
#endif
}

}  // namespace
}  // namespace ratchet::test
