#ifndef RATCHET_SPQR_HPP
#define RATCHET_SPQR_HPP

#include <cstdint>
#include <vector>

#include "ratchet/secure.hpp"

namespace ratchet::spqr {

struct Sent {
  SecureBuffer state;
  std::vector<uint8_t> message;
  SecureBytes<32> key;
};

struct Received {
  SecureBuffer state;
  SecureBytes<32> key;
};

SecureBuffer initialize(bool initiator, const SecureBytes<32>& secret);
Sent send(const SecureBuffer& state);
Received receive(const SecureBuffer& state, const std::vector<uint8_t>& message);

}  // namespace ratchet::spqr

#endif
