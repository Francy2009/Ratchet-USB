#include "ratchet/secure.hpp"

#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cstdio>
#include <mutex>
#include <unordered_map>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

namespace ratchet {
namespace {

// How many live secrets sit on each locked page.
//
// mlock() and munlock() work on whole pages; SecureBytes works on objects of
// 32 or 64 bytes. On a 4 KiB page that is up to 128 secrets sharing one lock,
// and this project allocates them in exactly that pattern -- intermediate DH
// results next to each other on the stack, a thousand SkippedKey records in
// one vector. Calling munlock() when any single one of them is destroyed
// unlocks the page out from under all the others, which is how a buffer that
// is still holding a live key ends up eligible for the swap file again.
//
// Counting per page fixes the mismatch: the page is locked when the first
// secret lands on it and released when the last one leaves.
std::mutex& locker_mutex() {
  static std::mutex m;
  return m;
}

// Keyed by the page's address as an integer, but every page is *reached* by
// pointer arithmetic from the caller's own pointer -- see first_page below.
// Rebuilding a pointer out of an integer would be both a lint violation and a
// genuine aliasing hazard.
std::unordered_map<const void*, std::size_t>& page_refs() {
  static std::unordered_map<const void*, std::size_t> refs;
  return refs;
}

std::size_t page_size() {
  static const std::size_t n = [] {
    const long v = ::sysconf(_SC_PAGESIZE);
    return v > 0 ? static_cast<std::size_t>(v) : std::size_t{4096};
  }();
  return n;
}

// The start of the page `p` sits in, as a pointer derived from `p` itself.
char* first_page(void* p, std::size_t ps) {
  auto* const bytes = static_cast<char*>(p);
  const auto offset =
      static_cast<std::size_t>(reinterpret_cast<uintptr_t>(bytes) & (ps - 1));
  return bytes - offset;
}

// Set when an exception stopped the bookkeeping from completing. From that
// point the page accounting is approximate, and the only safe direction to be
// approximate in is "still locked", which is what both handlers below do.
bool g_accounting_degraded = false;

// Reported once per process. A lock that could not be taken is not a reason to
// refuse to run -- a container with a small RLIMIT_MEMLOCK is a normal place
// to be -- but silently believing the memory is protected when it is not is
// worse than knowing it is not.
void warn_lock_failed_once() {
  static const bool warned = [] {
    (void)std::fputs(
        "warning: could not lock key material into RAM (RLIMIT_MEMLOCK?);\n"
        "warning: secrets in this process may be written to swap.\n",
        stderr);
    return true;
  }();
  (void)warned;
}

}  // namespace

bool lock_region(void* p, std::size_t n) noexcept {
  if (p == nullptr || n == 0) {
    return true;
  }
  const std::size_t ps = page_size();
  char* const start = first_page(p, ps);
  const char* const end = static_cast<const char*>(p) + n;
  bool ok = true;

  // noexcept because SecureBytes' move constructor is, and std::vector relies
  // on that to move its elements rather than copy them. The bookkeeping below
  // can allocate, so a failure to do so is reported as a lock that did not
  // happen rather than propagated -- under memory exhaustion the page
  // accounting for this one call may end up incomplete, which is not the
  // process's largest problem at that point.
  try {
    const std::lock_guard<std::mutex> guard(locker_mutex());
    for (char* page = start; page < end; page += ps) {
      if (page_refs()[page]++ == 0) {
        if (sodium_mlock(page, ps) != 0) {
          ok = false;
        }
      }
    }
  } catch (...) {
    g_accounting_degraded = true;
    ok = false;
  }

  if (!ok) {
    warn_lock_failed_once();
  }
  return ok;
}

void unlock_region(void* p, std::size_t n) noexcept {
  if (p == nullptr || n == 0) {
    return;
  }
  const std::size_t ps = page_size();
  char* const start = first_page(p, ps);
  const char* const end = static_cast<const char*>(p) + n;

  // This object's own bytes go regardless of what happens to the page lock.
  sodium_memzero(p, n);

  // find/erase on an existing key allocate nothing, so the only thing that can
  // throw here is the mutex itself; catching keeps the destructors that call
  // this noexcept in fact as well as in signature.
  try {
    const std::lock_guard<std::mutex> guard(locker_mutex());
    for (char* page = start; page < end; page += ps) {
      const auto it = page_refs().find(page);
      if (it == page_refs().end()) {
        continue;
      }
      if (--it->second == 0) {
        // Nothing else is living on this page any more, so it is finally safe
        // to hand it back. sodium_munlock would zero the whole page here,
        // which is not ours to do: the page may hold unrelated data.
        ::munlock(page, ps);
        page_refs().erase(it);
      }
    }
  } catch (...) {
    // The bytes are already zeroed. Leaving the page locked is the safe way to
    // fail, so nothing is retried -- only recorded.
    g_accounting_degraded = true;
  }
}

bool memory_locking_degraded() noexcept {
  const std::lock_guard<std::mutex> guard(locker_mutex());
  return g_accounting_degraded;
}

void wipe_string(std::string& text) {
  if (!text.empty()) {
    sodium_memzero(text.data(), text.size());
  }
  text.clear();
}

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
