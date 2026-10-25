// Known-answer tests for the primitives this build actually links, taken from
// the published RFCs. The key schedule has its own independent reference
// implementation (test/vectors); these pin the library calls underneath it, so
// a wrong libsodium/OpenSSL build is caught rather than agreeing with itself.

#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/secure.hpp"
#include "ratchet/x25519.hpp"
#include "test_support.hpp"

namespace {

std::vector<uint8_t> hex_bytes(std::string_view text) {
  if (text.size() % 2 != 0) {
    throw ratchet::Error("odd-length hex in test vector");
  }
  std::vector<uint8_t> out(text.size() / 2);
  std::size_t len = 0;
  if (sodium_hex2bin(out.data(), out.size(), text.data(), text.size(), nullptr,
                     &len, nullptr) != 0) {
    throw ratchet::Error("bad hex in test vector");
  }
  out.resize(len);
  return out;
}

template <std::size_t N>
std::array<uint8_t, N> hex_array(std::string_view text) {
  const std::vector<uint8_t> bytes = hex_bytes(text);
  if (bytes.size() != N) {
    throw ratchet::Error("wrong-length hex in test vector");
  }
  std::array<uint8_t, N> out{};
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

}  // namespace

TEST("kat: ChaCha20-Poly1305 (RFC 8439 section 2.8.2)") {
  const auto key = hex_array<crypto_aead_chacha20poly1305_ietf_KEYBYTES>(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const auto nonce = hex_array<crypto_aead_chacha20poly1305_ietf_NPUBBYTES>(
      "070000004041424344454647");
  const auto aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
  const std::string plaintext =
      "Ladies and Gentlemen of the class of '99: If I could offer you only "
      "one tip for the future, sunscreen would be it.";
  // Ciphertext followed by the Poly1305 tag, which is the combined layout
  // crypto_aead_chacha20poly1305_ietf_encrypt() produces.
  const auto expected = hex_bytes(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b6116"
      "1ae10b594f09e26a7e902ecbd0600691");

  std::vector<uint8_t> ciphertext(plaintext.size() +
                                  crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long ciphertext_len = 0;
  CHECK_EQ(crypto_aead_chacha20poly1305_ietf_encrypt(
               ciphertext.data(), &ciphertext_len,
               reinterpret_cast<const unsigned char*>(plaintext.data()),
               plaintext.size(), aad.data(), aad.size(), nullptr, nonce.data(),
               key.data()),
           0);
  ciphertext.resize(static_cast<std::size_t>(ciphertext_len));
  CHECK(ciphertext == expected);

  std::vector<uint8_t> decrypted(plaintext.size());
  unsigned long long decrypted_len = 0;
  CHECK_EQ(crypto_aead_chacha20poly1305_ietf_decrypt(
               decrypted.data(), &decrypted_len, nullptr, expected.data(),
               expected.size(), aad.data(), aad.size(), nonce.data(),
               key.data()),
           0);
  CHECK_EQ(decrypted_len, plaintext.size());
  CHECK(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0);
}

TEST("kat: X25519 (RFC 7748 section 6.1)") {
  const auto alice_sk = hex_array<32>(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  const auto alice_pk = hex_array<32>(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  const auto bob_sk = hex_array<32>(
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  const auto bob_pk = hex_array<32>(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  const auto expected = hex_array<32>(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

  ratchet::x25519::SecretKey secret;
  secret.assign(alice_sk.data(), alice_sk.size());
  unsigned char derived[crypto_scalarmult_BYTES];
  CHECK_EQ(crypto_scalarmult_base(derived, secret.data()), 0);
  CHECK(std::memcmp(derived, alice_pk.data(), alice_pk.size()) == 0);

  ratchet::x25519::PublicKey public_key{};
  std::copy(bob_pk.begin(), bob_pk.end(), public_key.begin());
  ratchet::SecureBytes<32> shared;
  ratchet::x25519::dh(secret, public_key, shared);
  CHECK(std::memcmp(shared.data(), expected.data(), expected.size()) == 0);

  secret.assign(bob_sk.data(), bob_sk.size());
  CHECK_EQ(crypto_scalarmult_base(derived, secret.data()), 0);
  CHECK(std::memcmp(derived, bob_pk.data(), bob_pk.size()) == 0);
  std::copy(alice_pk.begin(), alice_pk.end(), public_key.begin());
  ratchet::x25519::dh(secret, public_key, shared);
  CHECK(std::memcmp(shared.data(), expected.data(), expected.size()) == 0);
}

TEST("kat: Ed25519 (RFC 8032 section 7.1, test 1)") {
  const auto seed = hex_array<crypto_sign_SEEDBYTES>(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  const auto expected_pk = hex_array<crypto_sign_PUBLICKEYBYTES>(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const auto expected_sig = hex_array<crypto_sign_BYTES>(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  CHECK_EQ(crypto_sign_seed_keypair(pk, sk, seed.data()), 0);
  CHECK(std::memcmp(pk, expected_pk.data(), expected_pk.size()) == 0);

  unsigned char sig[crypto_sign_BYTES];
  unsigned long long sig_len = 0;
  CHECK_EQ(crypto_sign_detached(sig, &sig_len, nullptr, 0, sk), 0);
  CHECK_EQ(sig_len, static_cast<unsigned long long>(crypto_sign_BYTES));
  CHECK(std::memcmp(sig, expected_sig.data(), expected_sig.size()) == 0);
}
