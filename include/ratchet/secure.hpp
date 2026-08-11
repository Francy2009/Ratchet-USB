#ifndef RATCHET_SECURE_HPP
#define RATCHET_SECURE_HPP

#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <string>
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

  SecureBytes() { sodium_mlock(data_, N); }

  ~SecureBytes() {
    sodium_memzero(data_, N);
    sodium_munlock(data_, N);
  }

  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;
  SecureBytes(SecureBytes&&) = delete;
  SecureBytes& operator=(SecureBytes&&) = delete;

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
  uint8_t data_[N]{};
};

// Variable-length secret, used for the passphrase, whose length is not known
// at compile time. Same guarantees as SecureBytes: locked, wiped, non-copyable.
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
    // Reserving in chunks and wiping the previous block keeps that from
    // scattering copies of the passphrase around.
    if (buf_.size() == buf_.capacity()) {
      std::vector<char> bigger;
      bigger.reserve(buf_.capacity() == 0 ? 64 : buf_.capacity() * 2);
      bigger.insert(bigger.end(), buf_.begin(), buf_.end());
      wipe_vector(buf_);
      buf_.swap(bigger);
    }
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
    wipe_vector(buf_);
    buf_.clear();
  }

 private:
  static void wipe_vector(std::vector<char>& v) noexcept {
    if (!v.empty()) {
      sodium_memzero(v.data(), v.size());
    }
  }

  std::vector<char> buf_;
};

}  // namespace ratchet

#endif  // RATCHET_SECURE_HPP
