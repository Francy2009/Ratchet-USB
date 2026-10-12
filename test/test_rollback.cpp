#include <algorithm>

#include "ratchet/rollback.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

store::VaultStore state(uint64_t generation) {
  store::VaultStore s;
  s.generation = generation;
  for (std::size_t i = 0; i < s.vault_id.size(); ++i) {
    s.vault_id[i] = static_cast<uint8_t>(i + 1);
  }
  return s;
}

rollback::Digest bytes(uint8_t value) {
  rollback::Digest d{};
  d.fill(value);
  return d;
}

}  // namespace

TEST("rollback anchor accepts the exact authenticated generation") {
  const store::VaultStore usb = state(7);
  const rollback::AnchorRecord anchor{usb.vault_id, 7, bytes(0x31)};
  CHECK(rollback::validate(anchor, usb, bytes(0x31)) ==
        rollback::Status::Protected);
}

TEST("rollback anchor rejects rollback and same-generation replacement") {
  store::VaultStore usb = state(6);
  const rollback::AnchorRecord anchor{usb.vault_id, 7, bytes(0x31)};
  CHECK_THROWS(rollback::validate(anchor, usb, bytes(0x31)));

  usb.generation = 7;
  CHECK_THROWS(rollback::validate(anchor, usb, bytes(0x32)));
}

TEST("rollback anchor recovers exactly one durable-save gap") {
  store::VaultStore usb = state(8);
  usb.previous_digest = bytes(0x31);
  const rollback::AnchorRecord anchor{usb.vault_id, 7, bytes(0x31)};
  CHECK(rollback::validate(anchor, usb, bytes(0x32)) ==
        rollback::Status::AdvancedAfterCrash);

  usb.generation = 9;
  CHECK_THROWS(rollback::validate(anchor, usb, bytes(0x33)));
  usb.generation = 8;
  usb.previous_digest = bytes(0x30);
  CHECK_THROWS(rollback::validate(anchor, usb, bytes(0x32)));
}

TEST("rollback anchor cannot be substituted between vault identities") {
  store::VaultStore usb = state(7);
  rollback::AnchorRecord anchor{usb.vault_id, 7, bytes(0x31)};
  anchor.vault_id[0] ^= 1;
  CHECK_THROWS(rollback::validate(anchor, usb, bytes(0x31)));
}
