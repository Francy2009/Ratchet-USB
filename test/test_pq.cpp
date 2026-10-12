#include "test_support.hpp"

#include "ratchet/pq.hpp"

using namespace ratchet;

TEST("ML-KEM-768 encapsulation and decapsulation agree") {
  pq::MlKemKeyPair key = pq::generate_ml_kem_768();
  pq::MlKemCiphertext ciphertext{};
  pq::MlKemSharedSecret sender;
  pq::MlKemSharedSecret receiver;
  pq::ml_kem_768_encapsulate(key.public_key, ciphertext, sender);
  pq::ml_kem_768_decapsulate(key.private_seed, ciphertext, receiver);
  CHECK(sender.equals(receiver));
}

TEST("ML-KEM-768 rejects a malformed ciphertext without exposing details") {
  pq::MlKemKeyPair key = pq::generate_ml_kem_768();
  pq::MlKemCiphertext ciphertext{};
  pq::MlKemSharedSecret sender;
  pq::MlKemSharedSecret receiver;
  pq::ml_kem_768_encapsulate(key.public_key, ciphertext, sender);
  ciphertext[0] ^= 0x80;
  // ML-KEM implicit rejection can return a pseudorandom secret.  The protocol
  // must detect the mismatch through its AEAD tag, never an oracle here.
  pq::ml_kem_768_decapsulate(key.private_seed, ciphertext, receiver);
  CHECK(!sender.equals(receiver));
}

TEST("ML-DSA-65 signs and verifies from a deterministic seed") {
  pq::MlDsaPrivateSeed seed;
  for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i);
  pq::MlDsaKeyPair key = pq::ml_dsa_65_from_seed(seed);
  const uint8_t message[] = {'r', 'a', 't', 'c', 'h', 'e', 't'};
  pq::MlDsaSignature signature{};
  pq::ml_dsa_65_sign(key.private_seed, message, sizeof message, signature);
  CHECK(pq::ml_dsa_65_verify(key.public_key, message, sizeof message, signature));
  uint8_t changed[sizeof message];
  std::copy(std::begin(message), std::end(message), changed);
  changed[0] ^= 1;
  CHECK(!pq::ml_dsa_65_verify(key.public_key, changed, sizeof changed, signature));
}
