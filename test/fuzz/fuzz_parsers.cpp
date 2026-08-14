// Coverage-guided fuzzing over every parser that consumes input the tool did
// not produce itself.
//
// The unit tests check that well-formed input round-trips. This checks the
// other half: that malformed input is rejected rather than mishandled. The
// distinction matters here because three of these parsers run *before* any
// authentication has happened -- a contact card and a message envelope are
// whatever someone pasted into the terminal, and a vault header is read and
// acted on before the AEAD tag over it has been checked. Anything reachable
// from these entry points is reachable by an attacker who can get the user to
// paste a block or hand them a doctored vault.bin.
//
// Build and run:
//
//   cmake -S . -B build-fuzz -DRATCHET_BUILD_FUZZERS=ON \
//         -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
//   cmake --build build-fuzz
//   mkdir -p .fuzz-out
//   ./build-fuzz/test/fuzz/fuzz_parsers .fuzz-out test/fuzz/corpus \
//       -max_total_time=60
//
// Two directories, and the order matters: libFuzzer writes what it discovers
// into the first one. Keeping that separate from test/fuzz/corpus is what stops
// a single run from leaving a few hundred mutated blobs in the tree. The
// committed corpus grows by hand, when an input is worth keeping.
//
// The contract every one of these parsers is being held to: on any input at
// all, either return a value or throw ratchet::Error. Anything else -- a
// crash, a read out of bounds, an allocation sized from an unvalidated length
// field -- is a finding.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

#include "ratchet/message.hpp"
#include "ratchet/store.hpp"
#include "ratchet/vault.hpp"
#include "ratchet/wire.hpp"
#include "ratchet/x3dh.hpp"

using namespace ratchet;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) {
    return 0;
  }

  // The first byte picks the parser, so one corpus drives all of them and
  // libFuzzer can mutate its way between formats.
  const uint8_t selector = data[0];
  const uint8_t* body = data + 1;
  const size_t body_len = size - 1;
  const std::string text(reinterpret_cast<const char*>(body), body_len);

  try {
    switch (selector % 5) {
      case 0:
        // Pasted by the user, straight from an untrusted channel.
        (void)x3dh::import_card(text);
        break;
      case 1:
        // Same: whatever arrived over WhatsApp, email, a forum.
        (void)message::decode(text);
        break;
      case 2:
        // Read from vault.bin before the tag over it is verified.
        (void)vault::parse_header(body, body_len);
        break;
      case 3:
        // Post-decryption, so authenticated -- but a bug here is still a bug
        // reachable by anyone who can write to the drive and knows the
        // passphrase, and it shares its Reader with the two formats above.
        (void)store::parse(body, body_len);
        break;
      case 4:
        // The armour layer underneath both pasted formats.
        (void)wire::decode_block("MESSAGE", text);
        break;
      default:
        break;
    }
  } catch (const std::exception&) {
    // Rejecting malformed input by throwing is the contract, not a failure.
  }

  return 0;
}
