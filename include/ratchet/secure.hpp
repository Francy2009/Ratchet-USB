#ifndef RATCHET_SECURE_HPP
#define RATCHET_SECURE_HPP

#include <sodium.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ratchet {

// Every failure in this project is reported as an Error. Nothing sensitive is
// ever put in the message: error strings end up on the terminal and in shell
// history, so they only ever describe *what* failed, never with which value.
class Error : public std::runtime_error {
 public:
  explicit Error(const std::string& what) : std::runtime_error(what) {}
};

// Initialises libsodium. Safe to call more than once; every entry point calls
// it before touching any crypto primitive.
void init_sodium();

// Stops the process from handing its own memory to anyone, in the two ways it
// otherwise would while a vault is open.
//
// The first is a core dump. sodium_mlock keeps key material out of the swap
// file, but it does nothing about a crash: the kernel writes locked pages into
// the dump like any other, so a segfault at the wrong moment puts the seed, the
// identity key and every session key on the host's disk -- which is the one
// place this whole project exists to keep them away from. RLIMIT_CORE of zero
// is what actually prevents that.
//
// The second is ptrace. Without PR_SET_DUMPABLE cleared, any other process
// running as the same user can attach and read the vault straight out of
// memory, no crash required.
//
// Best-effort by design: a hardening step that cannot be applied is not a
// reason to refuse to run, so failures are silent.
//
// Returns true only when *both* protections are in place. Outside Linux that
// is false by construction: the core-dump limit still applies, but clearing
// the dumpable flag is Linux-specific.
// Callers that only want the process hardened as far as it goes can ignore the
// result; it is there so a test can tell the two cases apart.
bool harden_process() noexcept;

// Locks the pages holding [p, p+n) into RAM, keeping a reference count per
// page so that a page shared by several secrets stays locked until the last of
// them is gone. Returns false if any page could not be locked, having already
// warned on stderr once per process.
//
// This exists because mlock/munlock are page-granular while the secrets here
// are 32 and 64 bytes: without the counting, destroying one secret unlocks
// every other secret that happens to share its page. Every secret-holding type
// below goes through this pair rather than calling sodium_mlock directly.
bool lock_region(void* p, std::size_t n) noexcept;

// Zeroes [p, p+n) and drops this region's claim on the pages behind it,
// unlocking a page only once nothing else holds it.
void unlock_region(void* p, std::size_t n) noexcept;

// True once an exception has prevented the page accounting from completing --
// under memory exhaustion, essentially. From that point pages may stay locked
// longer than they need to, which is the safe direction to be wrong in.
bool memory_locking_degraded() noexcept;

// Zeroes a std::string's buffer, then empties it.
//
// For plaintext that cannot live in SecureString because it did not start
// there: a decrypted message arrives from session::receive as an ordinary
// string, and a message being typed has to be edited before it is a secret
// worth sealing. Neither is protected the way a key is -- the pages are not
// locked, so they can reach swap -- but wiping them the moment the screen
// stops showing them is a great deal better than leaving them on the heap
// until the allocator happens to reuse the block.
void wipe_string(std::string& text);

// Zeroes a byte vector's contents, then releases its storage.
//
// The file path uses this for the raw bytes of an attached file: once they have
// been framed into the plaintext that goes to the ratchet there is no reason
// for the copy on the heap to survive, including when framing throws.
void wipe_vector(std::vector<uint8_t>& bytes) noexcept;

// Appends to an ordinary std::string, wiping the old allocation before it is
// released when growth is needed.
//
// This is not SecureString: the current buffer is still ordinary, unlocked
// heap memory, so the value can reach swap. It only stops a reallocation from
// leaving the previous copy of a message body on the heap for the allocator to
// hand to somebody else. Used for the TUI's editable buffer and for input read
// from a pipe, where the final length is not known up front.
void append_string_wiped(std::string& out, std::string_view text);

// Wipes a std::string when it goes out of scope, including on an exception or
// an early return. `dismiss()` releases the value from the guard when ownership
// is intentionally handed off.
class StringWipe {
 public:
  explicit StringWipe(std::string& text) noexcept : text_(text) {}
  ~StringWipe() {
    if (armed_) {
      wipe_string(text_);
    }
  }

  StringWipe(const StringWipe&) = delete;
  StringWipe& operator=(const StringWipe&) = delete;

  void dismiss() noexcept { armed_ = false; }

 private:
  std::string& text_;
  bool armed_ = true;
};

// Fixed-size buffer for key material.
//
// The buffer is locked into RAM when the OS allows it (so it is not written to
// a swap file on the host) and wiped with sodium_memzero on destruction, which
// the compiler is not allowed to optimise away. Copying is disabled on
// purpose: a copy would be a second plaintext copy of a secret with a lifetime
// nobody is tracking. Use assign() when a copy is genuinely intended.
template <std::size_t N>
class SecureBytes {
 public:
  static constexpr std::size_t size_value = N;

  SecureBytes() { lock(); }

  // Moving relocates the one copy of the secret rather than duplicating it, so
  // it stays safe under the same "one lifetime" rule that rules out copying:
  // the source is wiped as part of the move. This is what lets a struct that
  // embeds a SecureBytes (a session record, a prekey) live in a std::vector.
  SecureBytes(SecureBytes&& other) noexcept {
    lock();
    std::memcpy(data_, other.data_, N);
    other.wipe();
  }

  SecureBytes& operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
      std::memcpy(data_, other.data_, N);
      other.wipe();
    }
    return *this;
  }

  ~SecureBytes() { unlock_region(data_, N); }

  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;

  uint8_t* data() noexcept { return data_; }
  const uint8_t* data() const noexcept { return data_; }
  constexpr std::size_t size() const noexcept { return N; }

  uint8_t& operator[](std::size_t i) noexcept { return data_[i]; }
  const uint8_t& operator[](std::size_t i) const noexcept { return data_[i]; }

  void assign(const uint8_t* src, std::size_t len) {
    if (len != N) {
      throw Error("internal: secure buffer assignment with wrong length");
    }
    std::memcpy(data_, src, N);
  }

  void assign(const SecureBytes<N>& other) { assign(other.data(), N); }

  void wipe() noexcept { sodium_memzero(data_, N); }

  // Constant-time comparison; a byte-by-byte loop would leak the position of
  // the first difference through timing.
  bool equals(const SecureBytes<N>& other) const noexcept {
    return sodium_memcmp(data_, other.data_, N) == 0;
  }

 private:
  void lock() { lock_region(data_, N); }

  uint8_t data_[N]{};
};

// Variable-length secret, used for the passphrase and the BIP-39 mnemonic,
// whose length is not known at compile time. Same guarantees as SecureBytes:
// locked, wiped, non-copyable.
//
// The lock has to follow the buffer. std::vector's storage moves when it
// grows, so growing means locking the new block before anything is copied into
// it and releasing the old one on the way out -- which is why growth is done
// by hand here rather than left to push_back.
class SecureString {
 public:
  SecureString() = default;
  ~SecureString() { clear(); }

  SecureString(const SecureString&) = delete;
  SecureString& operator=(const SecureString&) = delete;
  SecureString(SecureString&& other) noexcept { *this = std::move(other); }

  SecureString& operator=(SecureString&& other) noexcept {
    if (this != &other) {
      clear();
      buf_ = std::move(other.buf_);
      other.buf_.clear();
    }
    return *this;
  }

  void push_back(char c) {
    // Growing the vector may reallocate, leaving the old bytes on the heap.
    // Reserving in chunks, locking the new block and wiping the previous one
    // keeps that from scattering copies of the passphrase around.
    grow(1);
    buf_.push_back(c);
  }

  const char* data() const noexcept { return buf_.data(); }
  std::size_t size() const noexcept { return buf_.size(); }
  bool empty() const noexcept { return buf_.empty(); }

  bool equals(const SecureString& other) const noexcept {
    if (buf_.size() != other.buf_.size()) {
      return false;
    }
    if (buf_.empty()) {
      return true;
    }
    return sodium_memcmp(buf_.data(), other.buf_.data(), buf_.size()) == 0;
  }

  void clear() noexcept {
    unlock_region(buf_.data(), buf_.capacity());
    // The storage is released rather than merely emptied. std::vector::clear
    // keeps the capacity, and that block is now unlocked -- the next
    // push_back would write a secret into it without ever taking the lock
    // again, because the growth path only runs when size reaches capacity.
    std::vector<char>().swap(buf_);
  }

 private:
  // Makes room for `extra` more bytes without ever leaving an unwiped copy of
  // the old contents behind. Full reserve()+insert() is used rather than
  // vector::resize() because the old block has to be zeroed before it is
  // released, and the new block has to be locked before the secret is copied
  // into it.
  //
  // If the copy throws (memory exhaustion), the new block is unlocked, wiped
  // and freed by the handler below and the old buffer is left untouched. The
  // previous version leaked the page reference in exactly that case: the page
  // stayed locked with no owner left to unlock it, and
  // memory_locking_degraded() never learned about it.
  void grow(std::size_t extra) {
    const std::size_t old_size = buf_.size();
    if (extra > buf_.max_size() - old_size) {
      throw Error("internal: secure string size overflow");
    }
    const std::size_t needed = old_size + extra;
    if (needed <= buf_.capacity()) {
      return;
    }
    const std::size_t doubled =
        buf_.capacity() > buf_.max_size() / 2 ? buf_.max_size()
                                              : buf_.capacity() * 2;
    const std::size_t new_capacity = doubled > needed ? doubled : needed;
    std::vector<char> bigger;
    bigger.reserve(new_capacity);
    (void)lock_region(bigger.data(), bigger.capacity());
    try {
      bigger.insert(bigger.end(), buf_.begin(), buf_.end());
    } catch (...) {
      unlock_region(bigger.data(), bigger.capacity());
      throw;
    }
    unlock_region(buf_.data(), buf_.capacity());
    buf_.swap(bigger);
  }

  std::vector<char> buf_;
};

// Growable byte buffer for secrets whose total length is not known up front:
// the serialised vault store (seed, prekeys, sessions), which is decrypted
// into one of these before being parsed, and the X3DH input keying material.
// Same lock-on-grow, wipe-on-destroy behaviour as SecureString; move-only for
// the same reason as SecureBytes.
//
// This is the single most sensitive buffer in the program -- everything the
// vault holds passes through it in the clear -- so it going unlocked was the
// worst of the three.
class SecureBuffer {
 public:
  SecureBuffer() = default;
  ~SecureBuffer() { clear(); }

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& other) noexcept { *this = std::move(other); }

  SecureBuffer& operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
      clear();
      buf_ = std::move(other.buf_);
      other.buf_.clear();
    }
    return *this;
  }

  uint8_t* data() noexcept { return buf_.data(); }
  const uint8_t* data() const noexcept { return buf_.data(); }
  std::size_t size() const noexcept { return buf_.size(); }
  bool empty() const noexcept { return buf_.empty(); }

  uint8_t& operator[](std::size_t i) noexcept { return buf_[i]; }
  const uint8_t& operator[](std::size_t i) const noexcept { return buf_[i]; }

  // Resize while preserving the lock-on-grow guarantee. AEAD decryptors use
  // this so plaintext is written directly into locked memory.
  //
  // Shrinking zeroes the bytes being dropped first. vector::resize() on the way
  // down only changes the size, so a plaintext tail used to stay readable in
  // the locked allocation until something happened to overwrite it.
  void resize(std::size_t n) {
    if (n < buf_.size()) {
      sodium_memzero(buf_.data() + n, buf_.size() - n);
    }
    reserve(n);
    buf_.resize(n);
  }

  void append(const uint8_t* p, std::size_t n) {
    if (n == 0) {
      return;
    }
    const std::size_t old_size = buf_.size();
    if (n > buf_.max_size() - old_size) {
      throw Error("internal: secure buffer size overflow");
    }
    reserve(old_size + n);
    buf_.resize(old_size + n);
    std::memcpy(buf_.data() + old_size, p, n);
  }

  // Makes room for `n` bytes, preserving the lock-on-grow and wipe-on-release
  // guarantees. Growth is exception-safe: if copying the old contents throws,
  // the new block is unlocked, wiped and released; the old block stays intact.
  void reserve(std::size_t n) {
    if (n <= buf_.capacity()) {
      return;
    }
    std::vector<uint8_t> bigger;
    bigger.reserve(n);
    (void)lock_region(bigger.data(), bigger.capacity());
    try {
      bigger.insert(bigger.end(), buf_.begin(), buf_.end());
    } catch (...) {
      unlock_region(bigger.data(), bigger.capacity());
      throw;
    }
    unlock_region(buf_.data(), buf_.capacity());
    buf_.swap(bigger);
  }

  void clear() noexcept {
    unlock_region(buf_.data(), buf_.capacity());
    // Released rather than emptied, for the reason given in SecureString.
    std::vector<uint8_t>().swap(buf_);
  }

 private:
  std::vector<uint8_t> buf_;
};

}  // namespace ratchet

#endif  // RATCHET_SECURE_HPP
