#include "ratchet/spqr.hpp"

#include <cstddef>
#include <cstring>

namespace {

struct RustBuffer {
  uint8_t* ptr;
  std::size_t len;
};

extern "C" {
int ratchet_spqr_init(bool initiator, const uint8_t* secret, std::size_t secret_len,
                      RustBuffer* state);
int ratchet_spqr_send(const uint8_t* state, std::size_t state_len,
                      RustBuffer* next_state, RustBuffer* message,
                      RustBuffer* key);
int ratchet_spqr_recv(const uint8_t* state, std::size_t state_len,
                      const uint8_t* message, std::size_t message_len,
                      RustBuffer* next_state, RustBuffer* key);
void ratchet_spqr_free(RustBuffer buffer);
}

class OwnedRustBuffer {
 public:
  ~OwnedRustBuffer() { ratchet_spqr_free(value); }
  RustBuffer value{};
};

void copy_state(ratchet::SecureBuffer& out, const RustBuffer& in) {
  out.resize(in.len);
  if (in.len > 0) std::memcpy(out.data(), in.ptr, in.len);
}

void copy_key(ratchet::SecureBytes<32>& out, const RustBuffer& in) {
  if (in.len != out.size()) throw ratchet::Error("SPQR returned an invalid key");
  out.assign(in.ptr, in.len);
}

}  // namespace

namespace ratchet::spqr {

SecureBuffer initialize(bool initiator, const SecureBytes<32>& secret) {
  OwnedRustBuffer state;
  if (ratchet_spqr_init(initiator, secret.data(), secret.size(), &state.value) != 0) {
    throw Error("SPQR initialization failed");
  }
  SecureBuffer out;
  copy_state(out, state.value);
  return out;
}

Sent send(const SecureBuffer& state) {
  OwnedRustBuffer next, message, key;
  if (ratchet_spqr_send(state.data(), state.size(), &next.value,
                        &message.value, &key.value) != 0) {
    throw Error("SPQR send step failed");
  }
  Sent out;
  copy_state(out.state, next.value);
  out.message.assign(message.value.ptr, message.value.ptr + message.value.len);
  copy_key(out.key, key.value);
  return out;
}

Received receive(const SecureBuffer& state, const std::vector<uint8_t>& message) {
  OwnedRustBuffer next, key;
  if (ratchet_spqr_recv(state.data(), state.size(), message.data(),
                        message.size(), &next.value, &key.value) != 0) {
    throw Error("SPQR receive step failed");
  }
  Received out;
  copy_state(out.state, next.value);
  copy_key(out.key, key.value);
  return out;
}

}  // namespace ratchet::spqr
