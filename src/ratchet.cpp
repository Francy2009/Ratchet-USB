#include "ratchet/ratchet.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iterator>

#include "ratchet/kdf.hpp"

namespace ratchet::ratchet {
namespace detail {

void kdf_rk(const SecureBytes<32>& rk, const SecureBytes<32>& dh_out,
           SecureBytes<32>& new_rk, SecureBytes<32>& ck) {
  init_sodium();
  kdf::Prk prk;
  kdf::extract(prk, rk.data(), rk.size(), dh_out.data(), dh_out.size());
  uint8_t okm[64];
  kdf::expand(okm, sizeof okm, kRootInfo, prk);
  std::memcpy(new_rk.data(), okm, 32);
  std::memcpy(ck.data(), okm + 32, 32);
  sodium_memzero(okm, sizeof okm);
}

void kdf_ck(const SecureBytes<32>& ck, SecureBytes<32>& new_ck, SecureBytes<32>& mk) {
  init_sodium();
  const uint8_t byte1 = 0x01;
  const uint8_t byte2 = 0x02;
  uint8_t mk_tmp[32];
  uint8_t ck_tmp[32];
  crypto_auth_hmacsha256(mk_tmp, &byte1, 1, ck.data());
  crypto_auth_hmacsha256(ck_tmp, &byte2, 1, ck.data());
  std::memcpy(mk.data(), mk_tmp, 32);
  std::memcpy(new_ck.data(), ck_tmp, 32);
  sodium_memzero(mk_tmp, sizeof mk_tmp);
  sodium_memzero(ck_tmp, sizeof ck_tmp);
}

}  // namespace detail

namespace {

using detail::kdf_ck;
using detail::kdf_rk;

std::vector<uint8_t> aead_encrypt(const SecureBytes<32>& mk, const std::string& plaintext,
                                  const std::vector<uint8_t>& aad) {
  init_sodium();
  uint8_t nonce[12];
  randombytes_buf(nonce, sizeof nonce);

  std::vector<uint8_t> ct(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long ct_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          ct.data(), &ct_len, reinterpret_cast<const uint8_t*>(plaintext.data()),
          plaintext.size(), aad.data(), aad.size(), nullptr, nonce, mk.data()) != 0) {
    throw Error("message encryption failed");
  }
  ct.resize(ct_len);

  std::vector<uint8_t> out;
  out.reserve(sizeof nonce + ct.size());
  out.insert(out.end(), nonce, nonce + sizeof nonce);
  out.insert(out.end(), ct.begin(), ct.end());
  return out;
}

std::string aead_decrypt(const SecureBytes<32>& mk, const std::vector<uint8_t>& envelope,
                         const std::vector<uint8_t>& aad) {
  init_sodium();
  constexpr std::size_t kNonceBytes = 12;
  if (envelope.size() < kNonceBytes + crypto_aead_chacha20poly1305_ietf_ABYTES) {
    throw Error("message ciphertext is too short");
  }
  const uint8_t* nonce = envelope.data();
  const uint8_t* ct = envelope.data() + kNonceBytes;
  const std::size_t ct_len = envelope.size() - kNonceBytes;

  std::vector<uint8_t> pt(ct_len);
  unsigned long long pt_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(pt.data(), &pt_len, nullptr, ct, ct_len,
                                                aad.data(), aad.size(), nonce,
                                                mk.data()) != 0) {
    throw Error("message authentication failed (wrong key or a tampered message)");
  }
  std::string out(reinterpret_cast<const char*>(pt.data()), pt_len);
  sodium_memzero(pt.data(), pt.size());
  return out;
}

void dh_ratchet(store::Session& s, const x25519::PublicKey& new_dhr_pub) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr_pub = new_dhr_pub;
  s.has_dhr = true;

  SecureBytes<32> dh_out;
  x25519::dh(s.dhs_sk, s.dhr_pub, dh_out);
  kdf_rk(s.root_key, dh_out, s.root_key, s.chain_key_recv);
  s.has_ckr = true;

  x25519::generate_keypair(s.dhs_sk, s.dhs_pub);

  x25519::dh(s.dhs_sk, s.dhr_pub, dh_out);
  kdf_rk(s.root_key, dh_out, s.root_key, s.chain_key_send);
  s.has_cks = true;
}

// SkipMessageKeys: advances the receiving chain key up to (but not
// including) `until`, stashing a message key for every message skipped along
// the way.
void skip_message_keys(store::Session& s, uint32_t until) {
  if (!s.has_ckr) {
    return;
  }
  if (until < s.nr) {
    return;  // nothing to skip; the caller will report the real problem
  }
  const uint64_t to_skip = static_cast<uint64_t>(until) - s.nr;
  if (s.skipped.size() + to_skip > kMaxSkip) {
    throw Error(
        "too many skipped messages in this chain (possible attack, or a very "
        "large gap in delivery)");
  }
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  while (s.nr < until) {
    store::SkippedKey sk;
    sk.dh_pub = s.dhr_pub;
    sk.n = s.nr;
    sk.created_at = now;
    SecureBytes<32> new_ckr;
    kdf_ck(s.chain_key_recv, new_ckr, sk.message_key);
    s.chain_key_recv = std::move(new_ckr);
    s.skipped.push_back(std::move(sk));
    s.nr += 1;
  }
}

}  // namespace

void init_sender(store::Session& s, const SecureBytes<32>& shared_secret,
                 const x25519::SecretKey& ephemeral_sk,
                 const x25519::PublicKey& ephemeral_pk,
                 const x25519::PublicKey& bob_dh_pub) {
  s.dhs_sk.assign(ephemeral_sk.data(), ephemeral_sk.size());
  s.dhs_pub = ephemeral_pk;
  s.has_dhs = true;

  s.dhr_pub = bob_dh_pub;
  s.has_dhr = true;

  SecureBytes<32> dh_out;
  x25519::dh(s.dhs_sk, s.dhr_pub, dh_out);
  kdf_rk(shared_secret, dh_out, s.root_key, s.chain_key_send);
  s.has_cks = true;
  s.has_ckr = false;

  s.ns = s.nr = s.pn = 0;
  s.skipped.clear();
}

void init_receiver(store::Session& s, const SecureBytes<32>& shared_secret,
                   const x25519::SecretKey& spk_sk, const x25519::PublicKey& spk_pk) {
  s.dhs_sk.assign(spk_sk.data(), spk_sk.size());
  s.dhs_pub = spk_pk;
  s.has_dhs = true;

  s.has_dhr = false;
  s.root_key.assign(shared_secret.data(), shared_secret.size());
  s.has_cks = false;
  s.has_ckr = false;

  s.ns = s.nr = s.pn = 0;
  s.skipped.clear();
}

void encrypt(store::Session& s, const std::string& plaintext,
            message::RatchetHeader& header, std::vector<uint8_t>& ciphertext) {
  if (!s.has_cks) {
    throw Error("internal: session has no sending chain yet");
  }

  SecureBytes<32> mk;
  SecureBytes<32> new_cks;
  kdf_ck(s.chain_key_send, new_cks, mk);
  s.chain_key_send = std::move(new_cks);

  header.dh_pub = s.dhs_pub;
  header.pn = s.pn;
  header.n = s.ns;
  s.ns += 1;

  const std::vector<uint8_t> aad = message::header_aad(header);
  ciphertext = aead_encrypt(mk, plaintext, aad);
}

std::size_t expire_skipped_keys(store::Session& s, uint64_t now) {
  const auto stale = [now](const store::SkippedKey& sk) {
    // A key stamped in the future is left alone: that is a clock that went
    // backwards, not an old key, and expiring it would lose a live message.
    return now > sk.created_at && now - sk.created_at > kSkippedKeyMaxAgeSeconds;
  };
  const auto first = std::remove_if(s.skipped.begin(), s.skipped.end(), stale);
  const std::size_t dropped =
      static_cast<std::size_t>(std::distance(first, s.skipped.end()));
  // Erasing runs SecureBytes' destructor over the tail, which zeroes the key
  // material rather than just releasing it.
  s.skipped.erase(first, s.skipped.end());
  return dropped;
}

namespace {

// The decryption proper, which advances `s` as it goes and leaves it partly
// advanced if it throws. Never called on a session anyone still wants: the
// public `decrypt` below runs it against a copy.
std::string decrypt_in_place(store::Session& s,
                             const message::RatchetHeader& header,
                             const std::vector<uint8_t>& ciphertext) {
  // Before anything else, so an expired key can neither decrypt a message nor
  // keep occupying a slot in the kMaxSkip budget.
  expire_skipped_keys(s, static_cast<uint64_t>(std::time(nullptr)));

  const std::vector<uint8_t> aad = message::header_aad(header);

  // Try a cached key from an earlier out-of-order gap first.
  for (auto it = s.skipped.begin(); it != s.skipped.end(); ++it) {
    if (it->dh_pub == header.dh_pub && it->n == header.n) {
      // Decrypt first, erase second. A message key is the one piece of state
      // here that cannot be rebuilt: the chain keys either side of it have
      // already ratcheted past. Erasing before the tag was checked meant one
      // flipped ciphertext byte destroyed it for good -- and (dh_pub, n)
      // travel in the clear, so anyone who saw the block could build the
      // message that did it. Passing the cached key straight to the AEAD
      // rather than copying it out also keeps one fewer copy of key material
      // alive.
      std::string plaintext = aead_decrypt(it->message_key, ciphertext, aad);
      s.skipped.erase(it);
      return plaintext;
    }
  }

  if (!s.has_dhr || header.dh_pub != s.dhr_pub) {
    skip_message_keys(s, header.pn);
    dh_ratchet(s, header.dh_pub);
  }

  skip_message_keys(s, header.n);

  SecureBytes<32> mk;
  SecureBytes<32> new_ckr;
  kdf_ck(s.chain_key_recv, new_ckr, mk);
  s.chain_key_recv = std::move(new_ckr);
  s.nr += 1;

  return aead_decrypt(mk, ciphertext, aad);
}

}  // namespace

std::string decrypt(store::Session& s, const message::RatchetHeader& header,
                    const std::vector<uint8_t>& ciphertext) {
  // Everything decrypt_in_place touches -- the receiving chain, the root key
  // on a DH step, the skipped-key cache -- has to move before the tag is
  // checkable, because the tag cannot be checked until the key exists. So a
  // message that turns out to be forged, or simply delivered twice, rearranges
  // the session on its way to being rejected.
  //
  // Working on a copy and adopting it only on success makes the whole thing
  // atomic. This lives here rather than in the caller on purpose: it is a
  // property of the ratchet, and leaving it to whoever calls in means the
  // guarantee holds only for as long as every caller remembers -- which is not
  // a thing a type or an assertion can enforce, and not a thing a fuzz harness
  // does by default.
  store::Session candidate = store::clone_session(s);
  std::string plaintext = decrypt_in_place(candidate, header, ciphertext);
  s = std::move(candidate);
  return plaintext;
}

}  // namespace ratchet::ratchet
