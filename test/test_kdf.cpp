#include <sodium.h>

#include <string>
#include <vector>

#include "ratchet/bip39.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/kdf.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

std::vector<uint8_t> unhex(const std::string& hex) {
  std::vector<uint8_t> out(hex.size() / 2);
  size_t written = 0;
  if (sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(), nullptr,
                     &written, nullptr) != 0 ||
      written != out.size()) {
    throw Error("bad hex in test");
  }
  return out;
}

std::string hex(const uint8_t* data, size_t len) {
  return to_hex(data, len);
}

}  // namespace

// RFC 5869 appendix A, the two SHA-256 cases. These pin the KDF whichever
// implementation the build picked: libsodium's or the built-in fallback.
TEST("HKDF-SHA256 matches RFC 5869 test case 1") {
  const auto ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const auto salt = unhex("000102030405060708090a0b0c");
  const auto info = unhex("f0f1f2f3f4f5f6f7f8f9");

  kdf::Prk prk;
  kdf::extract(prk, salt.data(), salt.size(), ikm.data(), ikm.size());
  CHECK_EQ(hex(prk.data(), prk.size()),
           std::string("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844a"
                       "d7c2b3e5"));

  std::vector<uint8_t> okm(42);
  kdf::expand(okm.data(), okm.size(),
              std::string_view(reinterpret_cast<const char*>(info.data()),
                               info.size()),
              prk);
  CHECK_EQ(hex(okm.data(), okm.size()),
           std::string("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
                       "ecc4c5bf34007208d5b887185865"));
}

TEST("HKDF-SHA256 matches RFC 5869 test case 3 (empty salt and info)") {
  const auto ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

  kdf::Prk prk;
  kdf::extract(prk, nullptr, 0, ikm.data(), ikm.size());
  CHECK_EQ(hex(prk.data(), prk.size()),
           std::string("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c"
                       "293ccb04"));

  std::vector<uint8_t> okm(42);
  kdf::expand(okm.data(), okm.size(), "", prk);
  CHECK_EQ(hex(okm.data(), okm.size()),
           std::string("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f"
                       "3c738d2d9d201395faa4b61a96c8"));
}

TEST("HKDF-Expand rejects an output length outside the RFC bounds") {
  kdf::Prk prk;
  std::vector<uint8_t> out(1);
  CHECK_THROWS(kdf::expand(out.data(), 0, "x", prk));
  CHECK_THROWS(kdf::expand(out.data(), 255 * 32 + 1, "x", prk));
}

TEST("master seed and identity are deterministic") {
  bip39::Entropy entropy;
  bip39::decode("ozone drill grab fiber curtain grace pudding thank cruise "
                "elder eight picnic",
                entropy);

  MasterSeed seed_a;
  MasterSeed seed_b;
  derive_master_seed(entropy, seed_a);
  derive_master_seed(entropy, seed_b);
  CHECK(seed_a.equals(seed_b));

  IdentitySecretKey sk_a;
  IdentitySecretKey sk_b;
  IdentityPublicKey pk_a{};
  IdentityPublicKey pk_b{};
  derive_identity(seed_a, sk_a, pk_a);
  derive_identity(seed_b, sk_b, pk_b);
  CHECK(sk_a.equals(sk_b));
  CHECK(pk_a == pk_b);
}

TEST("different entropy yields a different identity") {
  bip39::Entropy e1;
  bip39::Entropy e2;
  bip39::generate_entropy(e1);
  bip39::generate_entropy(e2);
  CHECK(!e1.equals(e2));

  MasterSeed s1;
  MasterSeed s2;
  derive_master_seed(e1, s1);
  derive_master_seed(e2, s2);
  CHECK(!s1.equals(s2));

  IdentitySecretKey sk1;
  IdentitySecretKey sk2;
  IdentityPublicKey pk1{};
  IdentityPublicKey pk2{};
  derive_identity(s1, sk1, pk1);
  derive_identity(s2, sk2, pk2);
  CHECK(!sk1.equals(sk2));
  CHECK(pk1 != pk2);
}

TEST("the identity secret key is a clamped X25519 scalar") {
  bip39::Entropy entropy;
  bip39::generate_entropy(entropy);
  MasterSeed seed;
  derive_master_seed(entropy, seed);

  IdentitySecretKey sk;
  IdentityPublicKey pk{};
  derive_identity(seed, sk, pk);

  CHECK_EQ(sk[0] & 7, 0);
  CHECK_EQ(sk[31] & 128, 0);
  CHECK_EQ(sk[31] & 64, 64);

  // The public key must be the one X25519 derives from the stored scalar.
  IdentityPublicKey recomputed{};
  identity_public_from_secret(sk, recomputed);
  CHECK(recomputed == pk);
}

TEST("the master seed is not simply the entropy") {
  bip39::Entropy entropy;
  bip39::generate_entropy(entropy);
  MasterSeed seed;
  derive_master_seed(entropy, seed);
  CHECK(sodium_memcmp(seed.data(), entropy.data(), entropy.size()) != 0);
}
