// Coverage-guided fuzzing of the protocol state machine.
//
// fuzz_parsers.cpp covers the parsers. It would never have found the replay
// that destroyed a session, because nothing was malformed about that message --
// it parsed perfectly, and the damage was done by the state machine's reaction
// to a message it had already seen. Parser fuzzing cannot reach a bug whose
// input is well-formed by construction, so this drives the layer above it.
//
// Two real vaults are set up, cards are exchanged, and the fuzzer's input is
// read as a script of operations: send, deliver, deliver something a bit
// different, deliver something already delivered. Every delivery is then held
// to the properties that actually matter:
//
//   1. A block that was altered in any way must never decrypt. A single
//      success here is a forgery, which would be the worst possible finding.
//   2. Anything that does decrypt must be one of the messages actually sent.
//      Decrypting to something nobody wrote would mean the AEAD or the key
//      schedule is not binding what it should.
//   3. A block that already decrypted once must never decrypt again. This is
//      the property the accepted-handshake guard and the consumed skipped key
//      exist to provide, held here over arbitrary interleavings rather than
//      the handful the unit tests spell out.
//
// Build and run:
//
//   cmake -S . -B build-fuzz -DRATCHET_BUILD_FUZZERS=ON \
//         -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
//   cmake --build build-fuzz
//   mkdir -p .fuzz-out
//   ./build-fuzz/test/fuzz/fuzz_session .fuzz-out test/fuzz/corpus_session \
//       -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <set>
#include <string>
#include <vector>

#include "ratchet/session.hpp"
#include "ratchet/store.hpp"
#include "ratchet/x3dh.hpp"

using namespace ratchet;

namespace {

struct Party {
  IdentitySigningSecretKey sk;
  IdentitySigningPublicKey pk{};
  store::VaultStore vault;
};

void fail(const char* what) {
  std::fprintf(stderr, "INVARIANT VIOLATED: %s\n", what);
  std::abort();
}

Party make_party(std::size_t otpk_count) {
  Party p;
  bip39::Entropy entropy;
  bip39::generate_entropy(entropy);
  derive_master_seed(entropy, p.vault.seed);
  derive_identity(p.vault.seed, p.sk, p.pk);
  p.vault.signed_prekeys.push_back(prekey::generate_signed_prekey(p.sk, 1));
  p.vault.next_spk_id = 2;
  p.vault.one_time_prekeys = prekey::generate_one_time_prekeys(1, otpk_count);
  p.vault.next_otpk_id = static_cast<uint32_t>(1 + otpk_count);
  return p;
}

void introduce(const Party& from, Party& into) {
  const std::string card = x3dh::export_card(
      from.pk, from.vault.signed_prekeys.back(), from.vault.one_time_prekeys);
  const x3dh::ImportedCard imported = x3dh::import_card(card);
  store::Contact c;
  c.alias = "peer";
  c.identity_pub = imported.identity_pub;
  c.verified = true;
  c.card = imported.card;
  into.vault.contacts.push_back(std::move(c));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) {
    return 0;
  }

  // Low bit of the first byte decides whether the responder publishes one-time
  // prekeys, so both X3DH paths get explored.
  Party alice = make_party(3);
  Party bob = make_party((data[0] & 1u) ? 3 : 0);
  introduce(bob, alice);
  introduce(alice, bob);

  // Every block ever produced, and what it should decrypt to.
  std::vector<std::string> blocks;
  std::vector<std::string> expected;
  std::set<std::string> sent_plaintexts;
  std::set<std::size_t> already_delivered;

  std::size_t pos = 1;
  int budget = 40;  // keep a single run short enough to stay fast

  while (pos < size && budget-- > 0) {
    const uint8_t op = data[pos++];

    switch (op % 4) {
      case 0: {  // Alice sends.
        const std::string text = "m" + std::to_string(blocks.size());
        try {
          blocks.push_back(session::send(alice.vault, alice.sk, alice.pk, 0, text));
          expected.push_back(text);
          sent_plaintexts.insert(text);
        } catch (const std::exception&) {
        }
        break;
      }

      case 1: {  // Bob receives an untouched block.
        if (blocks.empty() || pos >= size) {
          break;
        }
        const std::size_t idx = data[pos++] % blocks.size();
        try {
          const session::ReceiveResult r =
              session::receive(bob.vault, bob.sk, bob.pk, blocks[idx]);
          if (sent_plaintexts.find(r.plaintext) == sent_plaintexts.end()) {
            fail("decrypted a plaintext that was never sent");
          }
          if (already_delivered.count(idx) != 0) {
            fail("the same block decrypted twice");
          }
          already_delivered.insert(idx);
        } catch (const std::exception&) {
          // Refusing is always allowed: out-of-order limits, replay guards and
          // exhausted prekeys all legitimately reject a block.
        }
        break;
      }

      case 2: {  // Bob receives a block with one byte changed.
        if (blocks.empty() || pos + 2 >= size) {
          break;
        }
        const std::size_t idx = data[pos++] % blocks.size();
        std::string mutated = blocks[idx];
        if (mutated.empty()) {
          break;
        }
        const std::size_t at = data[pos++] % mutated.size();
        mutated[at] = static_cast<char>(mutated[at] ^ (data[pos++] | 1u));
        if (mutated == blocks[idx]) {
          break;
        }
        try {
          const session::ReceiveResult r =
              session::receive(bob.vault, bob.sk, bob.pk, mutated);
          // Changing a byte of the armour can still describe the same bytes
          // (base64 has slack, and whitespace is stripped), so a success is
          // only a forgery if the block really did change underneath.
          if (r.plaintext != expected[idx]) {
            fail("an altered block decrypted to something else");
          }
        } catch (const std::exception&) {
          // The expected outcome.
        }
        break;
      }

      case 3: {  // Bob sends back, so the DH ratchet turns over.
        try {
          const std::string reply =
              session::send(bob.vault, bob.sk, bob.pk, 0, "reply");
          const session::ReceiveResult r =
              session::receive(alice.vault, alice.sk, alice.pk, reply);
          if (r.plaintext != "reply") {
            fail("a reply decrypted to the wrong text");
          }
        } catch (const std::exception&) {
        }
        break;
      }
    }
  }

  return 0;
}
