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

MasterSeed mac_seed(uint8_t fill) {
  MasterSeed seed;
  uint8_t raw[32];
  raw[0] = fill;
  for (std::size_t i = 1; i < sizeof raw; ++i) {
    raw[i] = static_cast<uint8_t>(fill + i);
  }
  seed.assign(raw, sizeof raw);
  sodium_memzero(raw, sizeof raw);
  return seed;
}

TEST("a legacy unsigned rollback anchor still validates") {
  store::VaultStore usb = state(4);
  usb.seed = mac_seed(0x10);
  const rollback::AnchorRecord anchor{usb.vault_id, 4, bytes(0x44)};
  CHECK(!anchor.authenticated);
  CHECK(rollback::validate(anchor, usb, bytes(0x44)) ==
        rollback::Status::Protected);
  const rollback::AnchorRecord decoded = rollback::decode(rollback::encode(anchor));
  CHECK(!decoded.authenticated);
  CHECK(decoded.generation == 4);
  CHECK(decoded.vault_digest == bytes(0x44));
}

TEST("a signed rollback anchor rejects a flipped tag and a different seed") {
  store::VaultStore usb = state(4);
  usb.seed = mac_seed(0x10);
  rollback::AnchorRecord anchor{usb.vault_id, 4, bytes(0x44)};
  rollback::authenticate(anchor, usb.seed);
  CHECK(anchor.authenticated);
  const rollback::AnchorRecord decoded = rollback::decode(rollback::encode(anchor));
  CHECK(decoded.authenticated);
  CHECK(decoded.mac == anchor.mac);
  CHECK(rollback::validate(decoded, usb, bytes(0x44)) ==
        rollback::Status::Protected);

  rollback::AnchorRecord flipped = decoded;
  flipped.mac[0] ^= 1;
  CHECK_THROWS(rollback::validate(flipped, usb, bytes(0x44)));

  store::VaultStore other = state(4);
  other.seed = mac_seed(0x20);
  rollback::AnchorRecord resigned{usb.vault_id, 4, bytes(0x44)};
  rollback::authenticate(resigned, other.seed);
  CHECK_THROWS(rollback::validate(resigned, usb, bytes(0x44)));
}

TEST("rollback anchor cannot be substituted between vault identities") {
  store::VaultStore usb = state(7);
  rollback::AnchorRecord anchor{usb.vault_id, 7, bytes(0x31)};
  anchor.vault_id[0] ^= 1;
  CHECK_THROWS(rollback::validate(anchor, usb, bytes(0x31)));
}
