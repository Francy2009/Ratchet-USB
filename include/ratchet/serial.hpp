#ifndef RATCHET_SERIAL_HPP
#define RATCHET_SERIAL_HPP

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/secure.hpp"

// A small binary reader/writer shared by every on-disk and on-the-wire format
// in the project (the vault store, contact cards, message envelopes): fixed
// fields as raw bytes, variable fields as a little-endian uint32 length
// followed by the bytes. Nothing here is format-specific; each format just
// picks a field order and wraps the result with its own magic/version bytes.
namespace ratchet::serial {

// Sinks a Writer can append to. Defined for the two buffer types the project
// uses: SecureBuffer for anything holding key material, plain std::vector for
// public data (contact cards, message envelopes) that never needs wiping.
inline void buffer_append(SecureBuffer& out, const uint8_t* p, std::size_t n) {
  out.append(p, n);
}

inline void buffer_append(std::vector<uint8_t>& out, const uint8_t* p,
                          std::size_t n) {
  out.insert(out.end(), p, p + n);
}

template <typename Sink>
class Writer {
 public:
  explicit Writer(Sink& out) : out_(out) {}

  void u8(uint8_t v) { buffer_append(out_, &v, 1); }

  void u32(uint32_t v) {
    const uint8_t b[4] = {
        static_cast<uint8_t>(v & 0xFFu), static_cast<uint8_t>((v >> 8) & 0xFFu),
        static_cast<uint8_t>((v >> 16) & 0xFFu),
        static_cast<uint8_t>((v >> 24) & 0xFFu)};
    buffer_append(out_, b, 4);
  }

  void bytes(const uint8_t* p, std::size_t n) { buffer_append(out_, p, n); }

  // Length-prefixed field, for anything whose size is not fixed by the format.
  void blob(const uint8_t* p, std::size_t n) {
    u32(static_cast<uint32_t>(n));
    bytes(p, n);
  }

  void str(std::string_view s) {
    blob(reinterpret_cast<const uint8_t*>(s.data()), s.size());
  }

 private:
  Sink& out_;
};

// Reads back from a flat buffer regardless of what produced it. Every read is
// bounds-checked: the data may come from a file or a pasted message, neither
// of which is trusted merely for having the right magic bytes.
class Reader {
 public:
  Reader(const uint8_t* data, std::size_t len) : data_(data), len_(len) {}

  uint8_t u8() {
    need(1);
    return data_[pos_++];
  }

  uint32_t u32() {
    need(4);
    const uint32_t v = static_cast<uint32_t>(data_[pos_]) |
                       (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                       (static_cast<uint32_t>(data_[pos_ + 2]) << 16) |
                       (static_cast<uint32_t>(data_[pos_ + 3]) << 24);
    pos_ += 4;
    return v;
  }

  void bytes(uint8_t* out, std::size_t n) {
    need(n);
    std::memcpy(out, data_ + pos_, n);
    pos_ += n;
  }

  std::vector<uint8_t> blob() {
    const uint32_t n = u32();
    need(n);
    std::vector<uint8_t> v(data_ + pos_, data_ + pos_ + n);
    pos_ += n;
    return v;
  }

  std::string str() {
    const std::vector<uint8_t> v = blob();
    return std::string(v.begin(), v.end());
  }

  bool at_end() const noexcept { return pos_ == len_; }

 private:
  void need(std::size_t n) const {
    // pos_ + n cannot overflow in practice (every caller passes a length that
    // came from this same buffer), but check anyway rather than trust that.
    if (n > len_ - pos_) {
      throw Error("truncated or malformed data");
    }
  }

  const uint8_t* data_;
  std::size_t len_;
  std::size_t pos_ = 0;
};

}  // namespace ratchet::serial

#endif  // RATCHET_SERIAL_HPP
