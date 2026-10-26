#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <limits>
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

    // The return value says whether both protections were applied. That is
    // true on Linux. What follows checks the effects themselves.
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

TEST("SecureString moves its buffer instead of copying it") {
  SecureString source;
  for (int i = 0; i < 200; ++i) {
    source.push_back(static_cast<char>('A' + (i % 26)));
  }
  const std::string expected(source.data(), source.size());

  SecureString moved(std::move(source));
  // The moved-from buffer is documented as empty; checking it is the point of
  // the test, not an accidental use.
  CHECK(source.empty());  // NOLINT(bugprone-use-after-move)
  CHECK_EQ(moved.size(), expected.size());
  CHECK_EQ(std::string(moved.data(), moved.size()), expected);

  SecureString assigned;
  assigned.push_back('x');
  assigned = std::move(moved);
  CHECK(moved.empty());  // NOLINT(bugprone-use-after-move)
  CHECK_EQ(std::string(assigned.data(), assigned.size()), expected);
}

TEST("SecureBuffer moves its buffer instead of copying it") {
  SecureBuffer source;
  const std::vector<uint8_t> chunk(128, 0x3C);
  source.append(chunk.data(), chunk.size());
  const std::vector<uint8_t> expected(source.data(), source.data() + source.size());

  SecureBuffer moved(std::move(source));
  CHECK(source.empty());  // NOLINT(bugprone-use-after-move)
  CHECK(moved.size() == expected.size());
  CHECK(std::equal(moved.data(), moved.data() + moved.size(), expected.begin()));

  SecureBuffer assigned;
  assigned = std::move(moved);
  CHECK(moved.empty());  // NOLINT(bugprone-use-after-move)
  CHECK(assigned.size() == expected.size());
  CHECK(std::equal(assigned.data(), assigned.data() + assigned.size(),
                   expected.begin()));
}

TEST("SecureBuffer resize down and back up keeps one locked allocation") {
  SecureBuffer buf;
  const std::vector<uint8_t> chunk(256, 0x7E);
  buf.append(chunk.data(), chunk.size());
  const long before = locked_kb_for(buf.data());

  buf.resize(17);
  CHECK_EQ(buf.size(), std::size_t{17});
  if (mlock_is_effective()) {
    CHECK_EQ(locked_kb_for(buf.data()), before);
  }

  // Growing again inside the old capacity must not allocate an unlocked block.
  buf.resize(200);
  CHECK_EQ(buf.size(), std::size_t{200});
  if (mlock_is_effective()) {
    CHECK_EQ(locked_kb_for(buf.data()), before);
  }
  // The byte after the shrunk region was re-initialised by resize(), so the
  // old 0x7E is not what comes back.
  CHECK_EQ(static_cast<unsigned>(buf[17]), 0u);
}

TEST("SecureBuffer append refuses a length that would wrap size_t") {
  SecureBuffer buf;
  const uint8_t byte = 1;
  buf.append(&byte, 1);
  CHECK_THROWS(buf.append(&byte, std::numeric_limits<std::size_t>::max()));
  // The failed call must not have changed the value.
  CHECK_EQ(buf.size(), std::size_t{1});
  CHECK_EQ(static_cast<unsigned>(buf[0]), 1u);
}

TEST("SecureBytes rejects an assignment of the wrong length") {
  SecureBytes<32> secret;
  const uint8_t src[31] = {};
  CHECK_THROWS(secret.assign(src, sizeof src));
}

TEST("StringWipe zeroes on scope exit and on an exception") {
  std::string text = "synthetic plaintext 0123456789";
  const std::size_t n = text.size();
  const char* const p = text.data();
  {
    StringWipe guard(text);
  }
  CHECK(text.empty());
  for (std::size_t i = 0; i < n; ++i) {
    CHECK_EQ(p[i], '\0');
  }

  std::string thrown = "synthetic secret on an error path";
  const std::size_t m = thrown.size();
  const char* const q = thrown.data();
  bool caught = false;
  try {
    StringWipe guard(thrown);
    throw Failure("simulated failure");
  } catch (const Failure&) {
    caught = true;
  }
  CHECK(caught);
  CHECK(thrown.empty());
  for (std::size_t i = 0; i < m; ++i) {
    CHECK_EQ(q[i], '\0');
  }

  std::string kept = "keep me";
  {
    StringWipe guard(kept);
    guard.dismiss();
  }
  CHECK_EQ(kept, std::string("keep me"));
}

TEST("append_string_wiped grows without losing the text") {
  std::string text;
  for (int i = 0; i < 200; ++i) {
    append_string_wiped(text, "piece/");
  }
  CHECK_EQ(text.size(), std::size_t{200} * 6);
  CHECK_EQ(text.substr(0, 12), std::string("piece/piece/"));
  CHECK_EQ(text.substr(text.size() - 6), std::string("piece/"));
  wipe_string(text);
}

TEST("wipe_vector releases the bytes it zeroed") {
  std::vector<uint8_t> bytes(64, 0xA5);
  wipe_vector(bytes);
  CHECK(bytes.empty());
  CHECK_EQ(bytes.capacity(), std::size_t{0});
}

// A lock that the OS refuses is a lock failure, not bookkeeping degradation,
// and must not leave a page reference that later unlocks somebody else's page.
// Simulated in a child so the lowered RLIMIT_MEMLOCK does not affect the test
// runner. When the environment grants CAP_IPC_LOCK (or mlock is otherwise
// still permitted) the test cannot force a failure and says so.
TEST("a refused lock is not reported as degraded bookkeeping") {
#if defined(__linux__)
  const pid_t pid = fork();
  CHECK(pid >= 0);
  if (pid == 0) {
    const struct rlimit no_memlock = {0, 0};
    if (setrlimit(RLIMIT_MEMLOCK, &no_memlock) != 0) {
      _exit(0);  // cannot simulate here; the runner itself may be restricted
    }
    PageBlock block;
    if (lock_region(block.at(0), 32)) {
      _exit(0);  // mlock still succeeded; nothing was simulated
    }
    // The same page now has two references that both failed to lock. Releasing
    // both must not underflow the count or crash; a second release of a page
    // with no reference is the dangerous case.
    (void)lock_region(block.at(32), 32);
    unlock_region(block.at(32), 32);
    unlock_region(block.at(0), 32);
    _exit(memory_locking_degraded() ? 3 : 0);
  }
  int status = 0;
  CHECK(waitpid(pid, &status, 0) == pid);
  CHECK(WIFEXITED(status));
  CHECK_EQ(WEXITSTATUS(status), 0);
#endif
}

TEST("SecureBytes still zeroes its bytes on destruction") {
  // The lock accounting changed; the wipe is the part that must not have.
  alignas(SecureBytes<32>) unsigned char storage[sizeof(SecureBytes<32>)]{};
  auto* secret = new (storage) SecureBytes<32>();
  for (std::size_t i = 0; i < secret->size(); ++i) {
    (*secret)[i] = 0xC5;
  }
  secret->~SecureBytes();

  bool all_zero = true;
  const volatile unsigned char* p = storage;
  for (std::size_t i = 0; i < sizeof(storage); ++i) {
    if (p[i] != 0) {
      all_zero = false;
    }
  }
  CHECK(all_zero);
}

}  // namespace
}  // namespace ratchet::test
