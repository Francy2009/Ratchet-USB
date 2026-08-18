#ifndef RATCHET_RATCHET_HPP
#define RATCHET_RATCHET_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/message.hpp"
#include "ratchet/store.hpp"
#include "ratchet/x25519.hpp"

// The Double Ratchet: a symmetric-key ratchet inside each direction's message
// chain, plus a Diffie-Hellman ratchet every time the conversation changes
// direction. Function and field names follow the Signal Double Ratchet
// specification's pseudocode.
//
// One deliberate deviation: a message key is used directly as a
// ChaCha20-Poly1305 key rather than expanded (as the spec does) into separate
// AES-CBC, HMAC and IV material -- there is no need for that split once the
// cipher itself is an AEAD. The nonce for each message's AEAD call is drawn
// fresh and carried in the envelope rather than derived, which trades twelve
// bytes per message for one less place a counter could be mishandled.
namespace ratchet::ratchet {

// A cap on how many message keys a single DH ratchet step will generate to
// catch up on missed messages. Without it, a header claiming an enormous `n`
// would make decryption allocate and hash without bound.
inline constexpr std::size_t kMaxSkip = 1000;

// How long a cached skipped message key is kept before it is thrown away. A
// skipped key is the one piece of ratchet state that does not move on by
// itself: the chain keys either side of it have already been ratcheted
// forward, but the key sits in the vault waiting for a message that may never
// arrive. Without an expiry it would wait forever, so a vault stolen months
// later still decrypts those old messages, and a chain the conversation left
// behind long ago keeps eating room from the kMaxSkip budget until no further
// gap can be tolerated at all. A week is long enough for any delivery this is
// meant to survive -- a message handed over on a USB stick, not one waiting on
// a server.
inline constexpr uint64_t kSkippedKeyMaxAgeDays = 7;
inline constexpr uint64_t kSkippedKeyMaxAgeSeconds =
    kSkippedKeyMaxAgeDays * 24 * 60 * 60;

// The two key-derivation steps the ratchet is built from. They are exposed
// here, rather than kept private to the .cpp, so the test suite can check them
// against known-answer vectors produced by an independent implementation of
// the same construction -- a round-trip test cannot tell a correct ratchet
// from one that is wrong in a self-consistent way.
namespace detail {

// The info string bound into every root-key derivation. Part of the wire
// contract: changing it makes this build unable to talk to any other.
inline constexpr std::string_view kRootInfo = "Ratchet-USB/v1/ratchet-root";

// KDF_RK: advances the root key across one DH ratchet step, producing a new
// root key and a fresh chain key. `rk` and `new_rk` (or `ck`) may be the same
// object -- every read of `rk` happens before the first write to an aliased
// output, so that is safe.
void kdf_rk(const SecureBytes<32>& rk, const SecureBytes<32>& dh_out,
            SecureBytes<32>& new_rk, SecureBytes<32>& ck);

// KDF_CK: advances a chain key by one message, producing a message key and
// the next chain key. Same aliasing safety as kdf_rk.
void kdf_ck(const SecureBytes<32>& ck, SecureBytes<32>& new_ck,
            SecureBytes<32>& mk);

}  // namespace detail

// Alice: turns an X3DH shared secret into a session's sending half. Her
// first ratchet key pair is the ephemeral she used for X3DH; `bob_dh_pub` is
// the public key of the ratchet step she is about to perform against (Bob's
// signed prekey, from his card).
void init_sender(store::Session& session, const SecureBytes<32>& shared_secret,
                 const x25519::SecretKey& ephemeral_sk,
                 const x25519::PublicKey& ephemeral_pk,
                 const x25519::PublicKey& bob_dh_pub);

// Bob: turns the same shared secret into a session's receiving half. His
// first ratchet key pair is the signed prekey he already published.
void init_receiver(store::Session& session, const SecureBytes<32>& shared_secret,
                   const x25519::SecretKey& spk_sk, const x25519::PublicKey& spk_pk);

// Encrypts `plaintext`, advancing the sending chain by one message, and fills
// in the envelope's ratchet header.
void encrypt(store::Session& session, const std::string& plaintext,
            message::RatchetHeader& header, std::vector<uint8_t>& ciphertext);

// Drops every cached skipped key stashed more than kSkippedKeyMaxAgeSeconds
// before `now` (a Unix timestamp in seconds), and returns how many were
// dropped. `decrypt` runs this against the system clock before it does
// anything else; it is exposed so `unlock` can expire keys on a vault that is
// opened but never received into, and so tests can drive it from a fixed
// clock.
std::size_t expire_skipped_keys(store::Session& session, uint64_t now);

// Decrypts an incoming envelope, performing a DH ratchet step first if its
// header carries a new ratchet public key, and caching any message keys
// skipped along the way so a message that arrives out of order can still be
// decrypted later. Throws Error on a bad authentication tag, or if the
// message is further ahead than kMaxSkip lets it catch up to.
//
// Atomic: `session` is advanced only if the AEAD tag checks out. On any
// failure it is left exactly as it was, down to the skipped-key cache, so a
// forged header cannot leave a half-ratcheted session behind and a message
// delivered twice cannot burn the key belonging to the next one.
std::string decrypt(store::Session& session, const message::RatchetHeader& header,
                    const std::vector<uint8_t>& ciphertext);

}  // namespace ratchet::ratchet

#endif  // RATCHET_RATCHET_HPP
