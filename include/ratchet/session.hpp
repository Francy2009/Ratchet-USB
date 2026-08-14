#ifndef RATCHET_SESSION_HPP
#define RATCHET_SESSION_HPP

#include <cstddef>
#include <string>

#include "ratchet/store.hpp"

// Ties together a contact, X3DH and the Double Ratchet: the two entry points
// the CLI actually calls, `send` and `receive`, decide on their own whether a
// handshake is needed before the ratchet can do its job.
namespace ratchet::session {

// Encrypts `plaintext` for the given contact, running X3DH first if no
// session exists yet, and returns the pasteable message block.
std::string send(store::VaultStore& vault, const IdentitySigningSecretKey& my_identity_sk,
                 const IdentitySigningPublicKey& my_identity_pk,
                 std::size_t contact_index, const std::string& plaintext);

struct ReceiveResult {
  std::size_t contact_index = 0;
  std::string alias;
  std::string plaintext;
  bool session_established = false;  // true if this message opened a fresh session
};

// Decrypts an incoming message block. If it carries X3DH fields, establishes
// (or replaces) the session for the sending contact before decrypting.
ReceiveResult receive(store::VaultStore& vault,
                      const IdentitySigningSecretKey& my_identity_sk,
                      const IdentitySigningPublicKey& my_identity_pk,
                      const std::string& block);

// Throws away every skipped message key in the vault that nobody claimed
// within ratchet::kSkippedKeyMaxAgeSeconds, and returns how many were
// dropped. `receive` already expires the keys of the session it touches; this
// is the sweep `unlock` runs, so a vault that is opened but never received
// into does not keep them forever either.
std::size_t expire_skipped_keys(store::VaultStore& vault);

}  // namespace ratchet::session

#endif  // RATCHET_SESSION_HPP
