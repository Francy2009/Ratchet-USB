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

// One page's bookkeeping.
//
// `refs` counts live secret regions on the page. `locked` records whether our
// own sodium_mlock() call succeeded -- munlock() is only called when it did,
// so a failed lock can never release a page somebody else locked.
//
// `dump_excluded` records that we asked libsodium to take the page out of a
// core dump. It is an attempt, not a confirmation: libsodium 1.0.22 does
// `madvise(MADV_DONTDUMP)` before `mlock()` and ignores the madvise result, so
// there is no portable way to observe whether the flag stuck. On Linux the
// call is unconditional, which is why the restore path below is attempted even
// when `locked` is false.
struct PageState {
  std::size_t refs = 0;
  bool locked = false;
  bool dump_excluded = false;
};

// Keyed by the page's address as an integer, but every page is *reached* by
// pointer arithmetic from the caller's own pointer -- see first_page below.
// Rebuilding a pointer out of an integer would be both a lint violation and a
// genuine aliasing hazard.
std::unordered_map<const void*, PageState>& page_refs() {
  static std::unordered_map<const void*, PageState> refs;
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

// Undoes the dump exclusion that sodium_mlock() attempts on Linux.
//
// The page is passed to madvise() whole and page-aligned, never as an
// arbitrary data() pointer: madvise() rejects a range whose start is not
// page-aligned, so handing it the address of a 32-byte SecureBytes would fail
// with EINVAL (and, if it had been accepted, would affect the other secrets on
// the page). This only runs from unlock_region when the last reference to the
// page is gone, so dump exclusion is never lifted while another secret is
// still living there.
//
// Best-effort on purpose. A page can be shared with unrelated allocations that
// called sodium_mlock() outside this bookkeeping; there is no way to know
// whether the exclusion flag was already set before our first lock. The
// restore is therefore deliberately *after* the last of our own secrets is
// gone, and a failure is not treated as fatal.
void restore_dump_exclusion(void* page, std::size_t ps) noexcept {
#if defined(MADV_DODUMP)
  (void)::madvise(page, ps, MADV_DODUMP);
#else
  (void)page;
  (void)ps;
#endif
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
      PageState& state = page_refs()[page];
      if (state.refs++ == 0) {
        // libsodium 1.0.22's sodium_mlock() first asks the kernel to exclude
        // the page from core dumps and only then calls mlock(). The madvise
        // result is ignored there, so `dump_excluded` records an attempt; the
        // restore path in unlock_region() is what undoes it. The failure of
        // mlock() itself is separate and is what makes the lock advisory.
        state.dump_excluded = true;
        state.locked = sodium_mlock(page, ps) == 0;
        if (!state.locked) {
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
      PageState& state = it->second;
      if (state.refs == 0) {
        // Defensive: a page with no live owner should not be in the table.
        // Leave it alone rather than underflowing the count.
        continue;
      }
      if (--state.refs == 0) {
        // Nothing else we track is living on this page any more, so it is
        // finally safe to undo both effects of the lock. sodium_munlock would
        // zero the whole page here, which is not ours to do: the page may hold
        // unrelated data. The bytes we do own were already zeroed above.
        //
        // Dump exclusion is lifted only here, at the last reference, never
        // while another secret on the page is alive. This is attempted even
        // when `locked` is false because sodium_mlock() asks for DONTDUMP
        // before it tries mlock() and can therefore leave the flag set even
        // when the lock itself failed.
        if (state.dump_excluded) {
          restore_dump_exclusion(page, ps);
        }
        if (state.locked) {
          ::munlock(page, ps);
        }
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
  try {
    const std::lock_guard<std::mutex> guard(locker_mutex());
    return g_accounting_degraded;
  } catch (...) {
    // If even the mutex cannot be taken, the bookkeeping is by definition not
    // trustworthy. Reporting degradation is the safe answer.
    return true;
  }
}

void wipe_string(std::string& text) {
  if (!text.empty()) {
    sodium_memzero(text.data(), text.size());
  }
  text.clear();
}

void wipe_vector(std::vector<uint8_t>& bytes) noexcept {
  if (!bytes.empty()) {
    sodium_memzero(bytes.data(), bytes.size());
  }
  std::vector<uint8_t>().swap(bytes);
}

void append_string_wiped(std::string& out, std::string_view text) {
  if (text.empty()) {
    return;
  }
  if (text.size() > out.max_size() - out.size()) {
    throw Error("internal: string size overflow");
  }
  const std::size_t needed = out.size() + text.size();
  if (needed > out.capacity()) {
    const std::size_t doubled =
        out.capacity() > out.max_size() / 2 ? out.max_size()
                                            : out.capacity() * 2;
    std::string bigger;
    bigger.reserve(doubled > needed ? doubled : needed);
    bigger.append(out);
    if (!out.empty()) {
      sodium_memzero(out.data(), out.size());
    }
    out.swap(bigger);
    // `bigger` now owns the old allocation, whose used bytes are zeroed. The
    // unused tail of that allocation is not ours to write through the string
    // interface; it is released with the allocation.
  }
  out.append(text);
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
