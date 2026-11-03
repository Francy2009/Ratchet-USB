#include "ratchet/group.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <unordered_set>

#include "ratchet/identity.hpp"
#include "ratchet/kdf.hpp"
#include "ratchet/message.hpp"
#include "ratchet/ratchet.hpp"
#include "ratchet/serial.hpp"
#include "ratchet/session.hpp"
#include "ratchet/wire.hpp"

namespace ratchet::group {
namespace {

constexpr std::array<uint8_t, 4> kGroupMagic = {'R', 'G', 'R', 'P'};
constexpr std::array<uint8_t, 4> kKeyMagic = {'R', 'G', 'K', '1'};
constexpr uint8_t kGroupVersion = 1;
constexpr std::size_t kNonceBytes = 12;
constexpr std::size_t kKeyBytes = 32;
constexpr std::size_t kGroupIdBytes = 16;
constexpr std::size_t kKeyPayloadBytes =
    kKeyMagic.size() + kGroupIdBytes + kKeyBytes;
constexpr std::string_view kSignDomain = "Ratchet-USB/v1/group-sender";

std::string make_key_payload(const std::array<uint8_t, kGroupIdBytes>& group_id,
                             const SecureBytes<kKeyBytes>& content_key) {
  SecureBuffer payload;
  serial::Writer<SecureBuffer> w(payload);
  w.bytes(kKeyMagic.data(), kKeyMagic.size());
  w.bytes(group_id.data(), group_id.size());
  w.bytes(content_key.data(), content_key.size());
  return std::string(reinterpret_cast<const char*>(payload.data()),
                     payload.size());
}

// Extracts the content key from a decrypted wrapper. Returns false (rather than
// throwing) for a wrapper that decrypted to something else, so a caller can
// keep looking; the wrapper itself was authenticated by the 1:1 session, so
// this is a format check, not a trust boundary.
bool parse_key_payload(std::string_view payload,
                       std::array<uint8_t, kGroupIdBytes>& group_id,
                       SecureBytes<kKeyBytes>& content_key) {
  if (payload.size() != kKeyPayloadBytes) {
    return false;
  }
  if (std::memcmp(payload.data(), kKeyMagic.data(), kKeyMagic.size()) != 0) {
    return false;
  }
  std::memcpy(group_id.data(), payload.data() + kKeyMagic.size(),
              group_id.size());
  std::memcpy(content_key.data(),
              payload.data() + kKeyMagic.size() + group_id.size(),
              content_key.size());
  return true;
}

std::vector<uint8_t> content_aad(
    const std::array<uint8_t, kGroupIdBytes>& group_id,
    const IdentitySigningPublicKey& sender,
    const std::vector<std::string>& wrappers) {
  init_sodium();
  // Hash the exact wrapper bytes so the content cannot be recombined with a
  // different set: adding, removing or editing a wrapper invalidates it.
  std::vector<uint8_t> wrapper_bytes;
  serial::Writer<std::vector<uint8_t>> ww(wrapper_bytes);
  for (const std::string& wrapper : wrappers) {
    ww.str(wrapper);
  }
  std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
  crypto_hash_sha256(digest.data(), wrapper_bytes.data(), wrapper_bytes.size());

  std::vector<uint8_t> aad;
  // Reserve the exact size: GCC 13's vector-growth analysis is unhappy about
  // the small first append into an empty vector, and the size is known here.
  aad.reserve(kGroupMagic.size() + 1 + group_id.size() + sender.size() + 4 +
              digest.size());
  serial::Writer<std::vector<uint8_t>> w(aad);
  w.bytes(kGroupMagic.data(), kGroupMagic.size());
  w.u8(kGroupVersion);
  w.bytes(group_id.data(), group_id.size());
  w.bytes(sender.data(), sender.size());
  w.u32(static_cast<uint32_t>(wrappers.size()));
  w.bytes(digest.data(), digest.size());

  sodium_memzero(digest.data(), digest.size());
  sodium_memzero(wrapper_bytes.data(), wrapper_bytes.size());
  return aad;
}

void derive_wrapper_key(const SecureBytes<32>& shared, SecureBytes<32>& key) {
  constexpr std::string_view kSalt = "Ratchet-USB/v1/group-wrapper";
  constexpr std::string_view kInfo = "Ratchet-USB/v1/group-wrapper-key";
  kdf::Prk prk;
  kdf::extract(prk, reinterpret_cast<const uint8_t*>(kSalt.data()),
               kSalt.size(), shared.data(), shared.size());
  kdf::expand(key.data(), key.size(), kInfo, prk);
}

// The inner wrapper is an ordinary 1:1 MESSAGE block, whose header carries a
// ratchet public key. Put it inside a sealed box to the recipient's identity
// key so that header never reaches the wire: a fresh ephemeral key per wrapper
// is unlinkable to any earlier 1:1 envelope, while the key itself is still
// wrapped by the existing Double Ratchet session inside.
std::string seal_wrapper(const IdentitySigningPublicKey& recipient_identity,
                         const std::string& inner_block) {
  init_sodium();
  IdentityDHPublicKey recipient_dh;
  identity_dh_public(recipient_identity, recipient_dh);

  x25519::SecretKey ephemeral_sk;
  x25519::PublicKey ephemeral_pub;
  x25519::generate_keypair(ephemeral_sk, ephemeral_pub);

  SecureBytes<32> shared;
  x25519::dh(ephemeral_sk, recipient_dh, shared);
  SecureBytes<32> key;
  derive_wrapper_key(shared, key);

  std::array<uint8_t, kNonceBytes> nonce{};
  randombytes_buf(nonce.data(), nonce.size());
  std::vector<uint8_t> ciphertext(
      inner_block.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long ciphertext_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          ciphertext.data(), &ciphertext_len,
          reinterpret_cast<const uint8_t*>(inner_block.data()),
          inner_block.size(), nullptr, 0, nullptr, nonce.data(),
          key.data()) != 0) {
    throw Error("group wrapper encryption failed");
  }
  ciphertext.resize(ciphertext_len);

  std::vector<uint8_t> out;
  serial::Writer<std::vector<uint8_t>> w(out);
  w.bytes(ephemeral_pub.data(), ephemeral_pub.size());
  w.bytes(nonce.data(), nonce.size());
  w.blob(ciphertext.data(), ciphertext.size());
  return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

std::string unseal_wrapper(const IdentitySigningSecretKey& my_identity_sk,
                           const IdentitySigningPublicKey& my_identity_pk,
                           std::string_view wrapper) {
  init_sodium();
  serial::Reader r(reinterpret_cast<const uint8_t*>(wrapper.data()),
                   wrapper.size());
  x25519::PublicKey ephemeral_pub{};
  r.bytes(ephemeral_pub.data(), ephemeral_pub.size());
  std::array<uint8_t, kNonceBytes> nonce{};
  r.bytes(nonce.data(), nonce.size());
  const std::vector<uint8_t> ciphertext = r.blob();
  if (!r.at_end()) {
    throw Error("group wrapper has trailing data");
  }
  if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
    throw Error("group wrapper ciphertext is too short");
  }

  IdentityDHSecretKey my_dh_sk;
  IdentityDHPublicKey my_dh_pk;
  identity_dh_keypair(my_identity_sk, my_identity_pk, my_dh_sk, my_dh_pk);
  SecureBytes<32> shared;
  x25519::dh(my_dh_sk, ephemeral_pub, shared);
  SecureBytes<32> key;
  derive_wrapper_key(shared, key);

  SecureBuffer plaintext;
  plaintext.resize(ciphertext.size());
  unsigned long long plaintext_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
          ciphertext.size(), nullptr, 0, nonce.data(), key.data()) != 0) {
    throw Error("group wrapper authentication failed");
  }
  return std::string(reinterpret_cast<const char*>(plaintext.data()),
                     plaintext_len);
}

std::array<uint8_t, crypto_hash_sha256_BYTES> transcript_digest(
    const std::vector<uint8_t>& aad, const std::vector<uint8_t>& ciphertext) {
  init_sodium();
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(
      &state, reinterpret_cast<const uint8_t*>(kSignDomain.data()),
      kSignDomain.size());
  crypto_hash_sha256_update(&state, aad.data(), aad.size());
  crypto_hash_sha256_update(&state, ciphertext.data(), ciphertext.size());
  std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
  crypto_hash_sha256_final(&state, digest.data());
  return digest;
}

std::vector<uint8_t> encrypt_content(
    const SecureBytes<kKeyBytes>& content_key, const std::string& plaintext,
    const std::array<uint8_t, kNonceBytes>& nonce,
    const std::vector<uint8_t>& aad) {
  init_sodium();
  const std::size_t target_len = ratchet::detail::padded_payload_size(plaintext.size());
  SecureBuffer padded;
  padded.resize(target_len);
  std::memcpy(padded.data(), plaintext.data(), plaintext.size());
  padded[plaintext.size()] = 0x80;

  std::vector<uint8_t> ct(target_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long ct_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          ct.data(), &ct_len, padded.data(), padded.size(), aad.data(),
          aad.size(), nullptr, nonce.data(), content_key.data()) != 0) {
    throw Error("group content encryption failed");
  }
  ct.resize(ct_len);
  return ct;
}

std::string decrypt_content(const SecureBytes<kKeyBytes>& content_key,
                            const std::vector<uint8_t>& ciphertext,
                            const std::array<uint8_t, kNonceBytes>& nonce,
                            const std::vector<uint8_t>& aad) {
  init_sodium();
  if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
    throw Error("group ciphertext is too short");
  }
  SecureBuffer pt;
  pt.resize(ciphertext.size());
  unsigned long long pt_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          pt.data(), &pt_len, nullptr, ciphertext.data(), ciphertext.size(),
          aad.data(), aad.size(), nonce.data(), content_key.data()) != 0) {
    throw Error("group message authentication failed (wrong key or a tampered "
                "message)");
  }

  // Same bucketed ISO/IEC 7816-4 padding the 1:1 messages use, so a group
  // body does not leak its exact length either.
  if (pt_len == 0 || (pt[pt_len - 1] != 0x00 && pt[pt_len - 1] != 0x80)) {
    throw Error("group message padding is invalid (tampered message)");
  }
  std::size_t i = pt_len;
  while (i > 0 && pt[i - 1] == 0x00) {
    --i;
  }
  if (i == 0 || pt[i - 1] != 0x80) {
    throw Error("group message padding is invalid (tampered message)");
  }
  return std::string(reinterpret_cast<const char*>(pt.data()), i - 1);
}

}  // namespace

bool looks_like_group(std::string_view text) {
  if (text.find("-----BEGIN RATCHET GROUP-----") != std::string_view::npos) {
    return true;
  }
  // A normal message block wins if both markers are present, so quoted text
  // around a pasted message cannot change which command handles it.
  if (text.find("-----BEGIN RATCHET MESSAGE-----") != std::string_view::npos) {
    return false;
  }
  // A block whose dashes an editor changed still routes to the group decoder,
  // which gives the useful "altered dashes" error instead of claiming the
  // user pasted the wrong kind of block.
  return text.find("BEGIN RATCHET GROUP") != std::string_view::npos;
}

std::string group_id_hex(const std::array<uint8_t, kGroupIdBytes>& group_id) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(group_id.size() * 2, '\0');
  for (std::size_t i = 0; i < group_id.size(); ++i) {
    out[i * 2] = kHex[group_id[i] >> 4];
    out[i * 2 + 1] = kHex[group_id[i] & 0x0F];
  }
  return out;
}

std::string send(store::VaultStore& vault,
                 const IdentitySigningSecretKey& my_identity_sk,
                 const IdentitySigningPublicKey& my_identity_pk,
                 const std::vector<std::size_t>& contact_indices,
                 const std::string& plaintext) {
  if (contact_indices.size() < 2) {
    throw Error("a group message needs at least two recipients");
  }
  if (contact_indices.size() > kMaxMembers) {
    throw Error("a group message has at most " + std::to_string(kMaxMembers) +
                " recipients");
  }
  if (plaintext.size() > message::kMaxPlaintextBytes) {
    throw Error("message exceeds the 4 MiB plaintext limit");
  }
  std::unordered_set<std::size_t> unique;
  for (const std::size_t index : contact_indices) {
    if (index >= vault.contacts.size()) {
      throw Error("group recipient does not exist");
    }
    if (!unique.insert(index).second) {
      throw Error("a group recipient is listed more than once");
    }
  }

  // Work on a serialized copy. Every wrapper advances a 1:1 session (and may
  // consume a one-time prekey from a contact card), so a failure halfway
  // through must not leave the vault with some sessions moved on and others
  // not. The copy is committed only once all wrappers exist.
  const SecureBuffer snapshot = store::serialize(vault);
  store::VaultStore working = store::parse(snapshot.data(), snapshot.size());

  std::array<uint8_t, kGroupIdBytes> group_id{};
  randombytes_buf(group_id.data(), group_id.size());
  SecureBytes<kKeyBytes> content_key;
  randombytes_buf(content_key.data(), content_key.size());
  std::array<uint8_t, kNonceBytes> nonce{};
  randombytes_buf(nonce.data(), nonce.size());

  std::string key_payload = make_key_payload(group_id, content_key);
  StringWipe wipe_key_payload(key_payload);

  std::vector<std::string> wrappers;
  wrappers.reserve(contact_indices.size());
  for (const std::size_t index : contact_indices) {
    const std::string inner = session::send(
        working, my_identity_sk, my_identity_pk, index, key_payload);
    wrappers.push_back(
        seal_wrapper(working.contacts[index].identity_pub, inner));
  }

  const std::vector<uint8_t> aad =
      content_aad(group_id, my_identity_pk, wrappers);
  const std::vector<uint8_t> ciphertext =
      encrypt_content(content_key, plaintext, nonce, aad);

  // The content key is shared with every member, so the AEAD alone proves only
  // that *a member* produced the ciphertext. The sender's Ed25519 identity key
  // signs the transcript, binding the content, the wrappers and the header to
  // the one identity the recipient already verified. Without this, any member
  // could re-encrypt the body under the shared key and attribute it to the
  // sender before the original reached the others.
  std::array<uint8_t, crypto_hash_sha256_BYTES> digest =
      transcript_digest(aad, ciphertext);
  Signature signature{};
  sign(my_identity_sk, digest.data(), digest.size(), signature);
  sodium_memzero(digest.data(), digest.size());

  std::vector<uint8_t> body;
  serial::Writer<std::vector<uint8_t>> w(body);
  w.bytes(kGroupMagic.data(), kGroupMagic.size());
  w.u8(kGroupVersion);
  w.bytes(group_id.data(), group_id.size());
  w.bytes(my_identity_pk.data(), my_identity_pk.size());
  w.bytes(nonce.data(), nonce.size());
  w.u32(static_cast<uint32_t>(wrappers.size()));
  for (const std::string& wrapper : wrappers) {
    w.str(wrapper);
  }
  w.blob(ciphertext.data(), ciphertext.size());
  w.bytes(signature.data(), signature.size());
  if (body.size() > kMaxGroupBlockBytes) {
    throw Error("group block exceeds the size limit");
  }

  std::string block = wire::encode_block("GROUP", body.data(), body.size());
  vault = std::move(working);
  return block;
}

ReceiveResult receive(store::VaultStore& vault,
                      const IdentitySigningSecretKey& my_identity_sk,
                      const IdentitySigningPublicKey& my_identity_pk,
                      const std::string& block) {
  const std::vector<uint8_t> body =
      wire::decode_block("GROUP", block, kMaxGroupBlockBytes);
  serial::Reader r(body.data(), body.size());

  std::array<uint8_t, kGroupMagic.size()> magic{};
  r.bytes(magic.data(), magic.size());
  if (magic != kGroupMagic) {
    throw Error("unsupported group message format");
  }
  if (r.u8() != kGroupVersion) {
    throw Error("unsupported group message version");
  }
  std::array<uint8_t, kGroupIdBytes> group_id{};
  r.bytes(group_id.data(), group_id.size());
  IdentitySigningPublicKey sender{};
  r.bytes(sender.data(), sender.size());
  std::array<uint8_t, kNonceBytes> nonce{};
  r.bytes(nonce.data(), nonce.size());
  const uint32_t count = r.u32();
  if (count < 2 || count > kMaxMembers) {
    throw Error("group message has an invalid member count");
  }
  std::vector<std::string> wrappers;
  wrappers.reserve(r.bounded_count(count, 4));
  for (uint32_t i = 0; i < count; ++i) {
    std::string wrapper = r.str();
    if (wrapper.size() > message::kMaxEnvelopeBytes) {
      throw Error("group wrapper exceeds the message size limit");
    }
    wrappers.push_back(std::move(wrapper));
  }
  const std::vector<uint8_t> ciphertext = r.blob();
  Signature signature{};
  r.bytes(signature.data(), signature.size());
  if (!r.at_end()) {
    throw Error("group message has trailing data");
  }

  // Check the claimed sender before trying wrappers, so an unknown or
  // unverified sender gives the same clear error a 1:1 message would.
  const int sender_index = vault.find_contact_by_identity(sender);
  if (sender_index < 0) {
    throw Error(
        "group message from an unknown contact; import their card first "
        "(`add-contact`)");
  }
  if (!vault.contacts[static_cast<std::size_t>(sender_index)].verified) {
    throw Error("contact fingerprint must be verified before receiving messages");
  }

  const std::vector<uint8_t> aad = content_aad(group_id, sender, wrappers);
  std::array<uint8_t, crypto_hash_sha256_BYTES> digest =
      transcript_digest(aad, ciphertext);
  const bool sender_ok =
      verify(sender, digest.data(), digest.size(), signature);
  sodium_memzero(digest.data(), digest.size());
  if (!sender_ok) {
    throw Error(
        "group message sender signature is invalid; the content was not "
        "produced by the identity it names");
  }

  // The wrapper is authenticated by the 1:1 session, but the shared content is
  // not authenticated until the end. Run the whole receive on a serialized
  // copy and commit only after the content has also authenticated, so a block
  // that fails later cannot consume a wrapper, a message key or a prekey in
  // the caller's vault.
  const SecureBuffer snapshot = store::serialize(vault);
  store::VaultStore working = store::parse(snapshot.data(), snapshot.size());

  SecureBytes<kKeyBytes> content_key;
  bool found = false;
  ReceiveResult result;
  for (const std::string& wrapper : wrappers) {
    // Try each wrapper on its own copy. A valid 1:1 envelope that is not a
    // group-key payload must not advance the session that a later, genuine
    // wrapper will commit: otherwise the direct message would be consumed
    // without ever being returned to the user.
    std::string inner;
    try {
      inner = unseal_wrapper(my_identity_sk, my_identity_pk, wrapper);
    } catch (const Error&) {
      // Not sealed to this vault (or tampered), so it is not ours.
      continue;
    }

    const SecureBuffer attempt_snapshot = store::serialize(working);
    store::VaultStore attempt =
        store::parse(attempt_snapshot.data(), attempt_snapshot.size());
    session::ReceiveResult wrapped;
    try {
      wrapped = session::receive(attempt, my_identity_sk, my_identity_pk,
                                 inner);
    } catch (const Error&) {
      // A wrapper addressed to another member normally fails here: it names a
      // prekey this vault does not have, or its ratchet tag does not verify.
      // None of those failures changed the vault, so continue to the next one.
      continue;
    }
    StringWipe wipe_wrapped(wrapped.plaintext);
    std::array<uint8_t, kGroupIdBytes> wrapped_group{};
    if (!parse_key_payload(wrapped.plaintext, wrapped_group, content_key)) {
      continue;
    }
    if (wrapped_group != group_id) {
      throw Error("group message header does not match its wrapper");
    }
    if (wrapped.contact_index != static_cast<std::size_t>(sender_index)) {
      throw Error("group wrapper sender does not match the message header");
    }
    working = std::move(attempt);
    result.contact_index = wrapped.contact_index;
    result.alias = wrapped.alias;
    found = true;
    break;
  }
  if (!found) {
    throw Error(
        "this group message has no wrapper for this vault; it was not "
        "addressed to you, or no session with the sender exists yet");
  }

  result.group_id = group_id;
  result.plaintext = decrypt_content(content_key, ciphertext, nonce, aad);
  vault = std::move(working);
  return result;
}

}  // namespace ratchet::group
