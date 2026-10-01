#ifndef RATCHET_MESSAGE_HPP
#define RATCHET_MESSAGE_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/identity.hpp"
#include "ratchet/protocol.hpp"
#include "ratchet/x25519.hpp"

// The wire format of one pasteable message: a "-----BEGIN RATCHET
// MESSAGE-----" block carrying a Double Ratchet header, an optional set of
// X3DH fields (present only on the message that opens a session), and the
// AEAD ciphertext.
namespace ratchet::message {

inline constexpr std::size_t kMaxEnvelopeBytes = 8u * 1024u * 1024u;
inline constexpr std::size_t kMaxPlaintextBytes = 4u * 1024u * 1024u;

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
  std::optional<uint32_t> pq_spk_id;
  std::optional<pq::MlKemCiphertext> pq_spk_ciphertext;
  std::optional<uint32_t> pq_otpk_id;
  std::optional<pq::MlKemCiphertext> pq_otpk_ciphertext;
};

struct RatchetHeader {
  x25519::PublicKey dh_pub{};
  uint32_t pn = 0;
  uint32_t n = 0;
};

struct Envelope {
  uint8_t version = 2;
  ProtocolSuite suite = ProtocolSuite::HybridPqxdhV1;
  SenderId sender_id{};
  std::optional<InitialFields> initial;
  RatchetHeader header;
  std::vector<uint8_t> ciphertext;  // nonce || AEAD ciphertext || tag
};

std::string encode(const Envelope& env);
Envelope decode(std::string_view text);

// The ratchet header is authenticated together with the envelope prefix
// (version, suite, sender and opening fields). It travels in the clear because
// the recipient needs it to derive the message key.
std::vector<uint8_t> header_aad(const RatchetHeader& header);
std::vector<uint8_t> envelope_aad_prefix(const Envelope& env);

}  // namespace ratchet::message

#endif  // RATCHET_MESSAGE_HPP
