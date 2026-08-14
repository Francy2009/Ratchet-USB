#ifndef RATCHET_STORE_HPP
#define RATCHET_STORE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/identity.hpp"
#include "ratchet/prekey.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/x25519.hpp"

// The vault's contents: everything that used to be the fixed "seed + identity
// key" pair in phase 1, now grown into a small database. All of it is kept in
// (and only ever exists in) the AEAD-sealed vault.bin -- see vault.hpp for the
// container format this is serialised into.
namespace ratchet::store {

// One of a contact's published one-time prekeys, as seen from our side: only
// the public half, since the private half never leaves their vault.
struct PeerOtpk {
  uint32_t id = 0;
  x25519::PublicKey pub{};
};

// A snapshot of a contact's card: everything needed to run X3DH as the
// initiator. Kept around after import so `send` can perform the handshake
// lazily, the first time there is something to say to them.
struct PeerCard {
  uint32_t spk_id = 0;
  x25519::PublicKey spk_pub{};
  Signature spk_signature{};
  std::vector<PeerOtpk> one_time_prekeys;
};

struct Contact {
  std::string alias;
  IdentitySigningPublicKey identity_pub{};
  // Set explicitly by the `trust` command once the fingerprint has been
  // checked over a channel other than the one the card arrived on. X3DH
  // authenticates that both sides used the identity keys they claim to, but
  // not that those keys belong to the person the user thinks they are
  // talking to -- that link only exists once a human has checked it.
  bool verified = false;
  std::optional<PeerCard> card;
};

struct SkippedKey {
  x25519::PublicKey dh_pub{};
  uint32_t n = 0;
  SecureBytes<32> message_key;
  // Unix timestamp (seconds) of the moment the key was stashed, used to
  // expire it once the message it belongs to is too late to still be coming.
  // See ratchet::kSkippedKeyMaxAgeSeconds.
  uint64_t created_at = 0;
};

// Double Ratchet state for one contact. Field names follow the Signal Double
// Ratchet specification's pseudocode (RK, DHs, DHr, CKs, CKr, Ns, Nr, PN) so
// the two can be read side by side.
struct Session {
  std::size_t contact_index = 0;

  SecureBytes<32> root_key;

  bool has_dhs = false;
  x25519::SecretKey dhs_sk;
  x25519::PublicKey dhs_pub{};

  bool has_dhr = false;
  x25519::PublicKey dhr_pub{};

  bool has_cks = false;
  SecureBytes<32> chain_key_send;

  bool has_ckr = false;
  SecureBytes<32> chain_key_recv;

  uint32_t ns = 0;
  uint32_t nr = 0;
  uint32_t pn = 0;

  std::vector<SkippedKey> skipped;
};

struct VaultStore {
  MasterSeed seed;

  uint32_t next_spk_id = 1;
  std::vector<prekey::SignedPrekey> signed_prekeys;

  uint32_t next_otpk_id = 1;
  std::vector<prekey::OneTimePrekey> one_time_prekeys;

  std::vector<Contact> contacts;
  std::vector<Session> sessions;

  // Returns the index into `contacts`, or -1 if there is no match.
  int find_contact(std::string_view alias) const;
  int find_contact_by_identity(const IdentitySigningPublicKey& id) const;
  int find_session(std::size_t contact_index) const;
};

// Serialises into a freshly allocated SecureBuffer, ready to be handed to
// vault::seal.
SecureBuffer serialize(const VaultStore& store);

// Reverses serialize(). Throws Error on any structural problem; there is
// nothing to defend against here beyond bugs, since the bytes only ever come
// from a successful vault::unseal, but the reader is bounds-checked anyway.
VaultStore parse(const uint8_t* data, std::size_t len);

}  // namespace ratchet::store

#endif  // RATCHET_STORE_HPP
