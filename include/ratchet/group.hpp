#ifndef RATCHET_GROUP_HPP
#define RATCHET_GROUP_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/store.hpp"

// Multi-user messages: the content is encrypted once under a random key, and
// that key is wrapped once per member through the 1:1 Double Ratchet session
// that already exists with them. A member unwraps its own copy with its
// existing session and uses it to decrypt the shared content.
//
// This is deliberately not a group protocol with server-side membership or a
// group ratchet. Each recipient's copy of the content key travels through the
// same authenticated 1:1 channel as any other message, so a member learns the
// key and the content but not the other wrappers' keys. The member list is not
// in the block: the wrappers are opaque, and a recipient only has to find the
// one its own session can open.
namespace ratchet::group {

// A bundle that has to be handed to every member. It carries one wrapper per
// member plus the shared ciphertext.
inline constexpr std::size_t kMaxMembers = 64;

// The whole base64 block, including every wrapper. Kept below the message
// envelope limit so a group block cannot make a front end allocate without
// bound.
inline constexpr std::size_t kMaxGroupBlockBytes = std::size_t{16} * 1024u * 1024u;

// True when `text` carries a "GROUP" armored block rather than a single
// recipient message. The CLI uses this to route `recv` without asking the user
// which command to run.
bool looks_like_group(std::string_view text);

// The group id as lowercase hex, for the one line the CLI prints so a user can
// tell two group messages apart.
std::string group_id_hex(const std::array<uint8_t, 16>& group_id);

// Encrypts `plaintext` once, wraps the content key for every contact in
// `contact_indices`, and returns one pasteable GROUP block. Every contact must
// already be verified and have a usable card; the 1:1 sessions are advanced
// exactly as `session::send` would advance them.
//
// The vault is not modified unless every wrapper was produced: the operation
// runs on a serialized copy and commits it at the end, so a failure midway
// cannot leave half the members with an advanced session.
std::string send(store::VaultStore& vault,
                 const IdentitySigningSecretKey& my_identity_sk,
                 const IdentitySigningPublicKey& my_identity_pk,
                 const std::vector<std::size_t>& contact_indices,
                 const std::string& plaintext);

struct ReceiveResult {
  std::size_t contact_index = 0;
  std::string alias;
  std::array<uint8_t, 16> group_id{};
  std::string plaintext;
};

// Finds the wrapper this vault can open, unwraps the content key, and decrypts
// the shared content. Throws Error when the block is malformed, when no wrapper
// belongs to this vault, or when the content does not authenticate.
ReceiveResult receive(store::VaultStore& vault,
                      const IdentitySigningSecretKey& my_identity_sk,
                      const IdentitySigningPublicKey& my_identity_pk,
                      const std::string& block);

}  // namespace ratchet::group

#endif  // RATCHET_GROUP_HPP
