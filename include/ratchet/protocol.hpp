#ifndef RATCHET_PROTOCOL_HPP
#define RATCHET_PROTOCOL_HPP

#include <cstdint>

namespace ratchet {

enum class ProtocolSuite : uint8_t {
  ClassicV2 = 1,
  HybridPqxdhV1 = 2,
  TripleRatchetV1 = 3,
};

constexpr bool suite_at_least(ProtocolSuite value, ProtocolSuite minimum) {
  return static_cast<uint8_t>(value) >= static_cast<uint8_t>(minimum);
}

}  // namespace ratchet

#endif
