#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#include <cstdint>
#include <cstdlib>
#include <new>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "ratchet/secure.hpp"
#include "test_support.hpp"

namespace ratchet::test {
namespace {

// Locked bytes reported for the mapping that contains `addr`, straight out of
// /proc/self/smaps. Returns -1 when the figure cannot be read, which is how
// every non-Linux platform answers.
long locked_kb_for(const void* addr) {
#if defined(__linux__)
  std::ifstream in("/proc/self/smaps");
  if (!in) {
    return -1;
  }
  const auto target = reinterpret_cast<uintptr_t>(addr);
  std::string line;
  bool in_range = false;
  while (std::getline(in, line)) {
    unsigned long lo = 0;
    unsigned long hi = 0;
    if (std::sscanf(line.c_str(), "%lx-%lx", &lo, &hi) == 2) {
      in_range = target >= lo && target < hi;
    }
    if (in_range && line.rfind("Locked:", 0) == 0) {
      long kb = 0;
      if (std::sscanf(line.c_str(), "Locked: %ld", &kb) == 1) {
        return kb;
      }
    }
  }
#else
  (void)addr;
#endif
  return -1;
}

uintptr_t page_of(const void* p) {
  static const auto mask = ~(static_cast<uintptr_t>(::sysconf(_SC_PAGESIZE)) - 1);
  return reinterpret_cast<uintptr_t>(p) & mask;
}

// One page of scratch memory, aligned to a page boundary, so a test can put
// several secrets on the same page on purpose instead of hoping the allocator
// happens to.
class PageBlock {
 public:
  PageBlock() {
    const std::size_t size = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
    if (::posix_memalign(&block_, size, size) != 0) {
      throw Failure("could not allocate a page-aligned block");
    }
  }
  ~PageBlock() { ::free(block_); }

  PageBlock(const PageBlock&) = delete;
  PageBlock& operator=(const PageBlock&) = delete;

  void* at(std::size_t offset) { return static_cast<char*>(block_) + offset; }

 private:
  void* block_ = nullptr;
};

// Whether mlock actually does anything here.
//
// Often it does not, for entirely legitimate reasons: AddressSanitizer
// intercepts mlock and munlock and makes them no-ops (locking its shadow
// mappings would blow through RLIMIT_MEMLOCK), a container may set that limit
// to zero, and /proc/self/smaps does not exist away from Linux. The tests
// below still drive the locking code in every one of those environments --
// what they cannot do there is assert on a figure the platform declines to
// produce, so they say so out loud rather than passing quietly.
bool mlock_is_effective() {
  static const bool effective = [] {
    PageBlock probe;
    bool ok = false;
    if (sodium_mlock(probe.at(0), 32) == 0) {
      ok = locked_kb_for(probe.at(0)) > 0;
      sodium_munlock(probe.at(0), 32);
    }
    if (!ok) {
      std::cout << "  note: mlock has no observable effect in this "
                   "environment (sanitizer, container limit, or no smaps);\n"
                   "  note: the page-locking assertions below are skipped, "
                   "the code paths are still exercised.\n";
    }
    return ok;
  }();
  return effective;
}

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
    const bool fully_hardened = harden_process();

    // The return value says whether *everything* was applied, and on a platform
    // without the ptrace half it is honestly false -- so it is only an
    // assertion where both halves exist. Asserting it everywhere is what broke
    // this test on macOS: the code was right and the test was wrong about what
    // the platform promises. What follows checks the effects themselves, which
    // is the property that actually matters.
#if defined(__linux__)
    if (!fully_hardened) {
      _exit(10);
    }
#else
    (void)fully_hardened;
#endif

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

// --- Page-granular locking ---------------------------------------------------

TEST("destroying one secret does not unlock a page another still lives on") {
  // mlock and munlock work on whole pages; SecureBytes works on 32-byte
  // objects. Up to 128 of them share a 4 KiB page, and this project allocates
  // them in exactly that pattern -- intermediate DH results side by side, a
  // thousand skipped-key records in one vector. munlock() called for any one
  // of them used to release the page out from under all the others, which put
  // live key material back in reach of the swap file.
  //
  // The two secrets are placed on one page deliberately rather than by hoping
  // the allocator puts them there: an earlier version of this test left it to
  // chance, and in the test runner the two landed on different pages, so it
  // passed against the very bug it was written for.
  PageBlock block;
  auto* first = new (block.at(0)) SecureBytes<32>();
  auto* second = new (block.at(64)) SecureBytes<32>();
  CHECK_EQ(page_of(first->data()), page_of(second->data()));

  const long before = locked_kb_for(second->data());
  first->~SecureBytes();
  const long after = locked_kb_for(second->data());

  if (mlock_is_effective()) {
    CHECK(before > 0);
    CHECK_EQ(after, before);
  }

  second->~SecureBytes();
}

TEST("a page is released once the last secret on it is gone") {
  // The other half of the contract: reference counting must not leak locks,
  // or a long-running process ends up pinning every page a secret ever
  // touched.
  PageBlock block;
  long while_alive = -1;
  long after = -1;
  {
    auto* only = new (block.at(0)) SecureBytes<32>();
    while_alive = locked_kb_for(only->data());
    only->~SecureBytes();
  }
  after = locked_kb_for(block.at(0));

  if (mlock_is_effective()) {
    CHECK(while_alive > 0);
    CHECK(after < while_alive);
  }
}

TEST("nested secrets on one page keep it locked until the last one goes") {
  PageBlock block;
  auto* a = new (block.at(0)) SecureBytes<32>();
  auto* b = new (block.at(64)) SecureBytes<32>();
  auto* c = new (block.at(128)) SecureBytes<32>();

  const long all_three = locked_kb_for(a->data());
  c->~SecureBytes();
  b->~SecureBytes();
  const long one_left = locked_kb_for(a->data());
  a->~SecureBytes();
  const long none_left = locked_kb_for(block.at(0));

  if (mlock_is_effective()) {
    CHECK(all_three > 0);
    CHECK_EQ(one_left, all_three);
    CHECK(none_left < all_three);
  }
}

TEST("SecureString locks its buffer and moves the lock when it grows") {
  SecureString s;
  // Past the initial 64-byte reservation, so the growth path runs at least
  // once and the lock has to follow the reallocation.
  for (int i = 0; i < 300; ++i) {
    s.push_back(static_cast<char>('a' + (i % 26)));
  }
  CHECK_EQ(s.size(), std::size_t{300});

  if (mlock_is_effective()) {
    CHECK(locked_kb_for(s.data()) > 0);
  }

  s.clear();
  CHECK(s.empty());
}

TEST("SecureBuffer locks its buffer across repeated growth") {
  SecureBuffer buf;
  const std::vector<uint8_t> chunk(64, 0xAB);
  for (int i = 0; i < 200; ++i) {
    buf.append(chunk.data(), chunk.size());
  }
  CHECK_EQ(buf.size(), std::size_t{200 * 64});

  if (mlock_is_effective()) {
    CHECK(locked_kb_for(buf.data()) > 0);
  }

  buf.clear();
  CHECK(buf.empty());
}

TEST("a cleared SecureBuffer re-locks the storage it allocates next") {
  // clear() releases the block rather than merely emptying it. Keeping the
  // capacity would leave an unlocked allocation that the next append writes a
  // secret into, because the growth path only runs when size reaches capacity.
  SecureBuffer buf;
  const std::vector<uint8_t> chunk(256, 0x5A);
  buf.append(chunk.data(), chunk.size());
  buf.clear();
  buf.append(chunk.data(), chunk.size());

  CHECK_EQ(buf.size(), chunk.size());
  if (mlock_is_effective()) {
    CHECK(locked_kb_for(buf.data()) > 0);
  }
}

TEST("SecureBytes still zeroes its bytes on destruction") {
  // The lock accounting changed; the wipe is the part that must not have.
  alignas(SecureBytes<32>) unsigned char storage[sizeof(SecureBytes<32>)];
  auto* secret = new (storage) SecureBytes<32>();
  for (std::size_t i = 0; i < secret->size(); ++i) {
    (*secret)[i] = 0xC5;
  }
  secret->~SecureBytes();

  bool all_zero = true;
  for (const unsigned char byte : storage) {
    if (byte != 0) {
      all_zero = false;
    }
  }
  CHECK(all_zero);
}

}  // namespace
}  // namespace ratchet::test
