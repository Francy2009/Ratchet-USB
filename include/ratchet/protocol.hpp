#ifndef RATCHET_PROTOCOL_HPP
#define RATCHET_PROTOCOL_HPP

#include <cstdint>

namespace ratchet {

enum class ProtocolSuite : uint8_t {
  ClassicV2 = 1,
  HybridPqxdhV1 = 2,
  TripleRatchetV1 = 3,
  // New cards only. The handshake uses the X-Wing combiner; messages still
  // use the Triple Ratchet. Suite 2 and 3 sessions keep the combiner they
  // already agreed.
  XWingTripleRatchetV1 = 4,
};

constexpr bool suite_at_least(ProtocolSuite value, ProtocolSuite minimum) {
  return static_cast<uint8_t>(value) >= static_cast<uint8_t>(minimum);
}

constexpr bool known_suite(uint8_t suite) {
  return suite >= static_cast<uint8_t>(ProtocolSuite::ClassicV2) &&
         suite <= static_cast<uint8_t>(ProtocolSuite::XWingTripleRatchetV1);
}

// Suites whose messages carry an SPQR ciphertext and split the handshake
// secret into an EC chain and an SPQR chain.
constexpr bool uses_triple_ratchet(ProtocolSuite suite) {
  return suite == ProtocolSuite::TripleRatchetV1 ||
         suite == ProtocolSuite::XWingTripleRatchetV1;
}

// The published X-Wing combiner. Only the opening handshake of a new suite 4
// session uses it. Established sessions never re-run the combiner.
constexpr bool uses_xwing_combiner(ProtocolSuite suite) {
  return suite == ProtocolSuite::XWingTripleRatchetV1;
}

}  // namespace ratchet

#endif
