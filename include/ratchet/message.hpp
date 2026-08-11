#ifndef RATCHET_MESSAGE_HPP
#define RATCHET_MESSAGE_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/identity.hpp"
#include "ratchet/x25519.hpp"

// The wire format of one pasteable message: a "-----BEGIN RATCHET
// MESSAGE-----" block carrying a Double Ratchet header, an optional set of
// X3DH fields (present only on the message that opens a session), and the
// AEAD ciphertext.
namespace ratchet::message {

inline constexpr std::size_t kSenderIdBytes = 8;
using SenderId = std::array<uint8_t, kSenderIdBytes>;

// Truncated SHA-256 of an identity public key, carried in every envelope so
// the recipient can tell which contact (and which session) a message belongs
// to without the user having to say so on every `recv`.
SenderId sender_id_for(const IdentitySigningPublicKey& identity_pub);

struct InitialFields {
  IdentitySigningPublicKey initiator_identity_pub{};
  uint32_t spk_id = 0;
  std::optional<uint32_t> otpk_id;
};

struct RatchetHeader {
  x25519::PublicKey dh_pub{};
  uint32_t pn = 0;
  uint32_t n = 0;
};

struct Envelope {
  SenderId sender_id{};
  std::optional<InitialFields> initial;
  RatchetHeader header;
  std::vector<uint8_t> ciphertext;  // nonce || AEAD ciphertext || tag
};

std::string encode(const Envelope& env);
Envelope decode(std::string_view text);

// The bytes authenticated as AEAD associated data for a message: the ratchet
// header alone, so tampering with it is caught even though it travels in the
// clear (it has to, the recipient needs it to derive the message key).
std::vector<uint8_t> header_aad(const RatchetHeader& header);

}  // namespace ratchet::message

#endif  // RATCHET_MESSAGE_HPP
