#include "ratchet/pq.hpp"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <memory>

namespace ratchet::pq {
namespace {

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

PkeyPtr public_key_from_raw(const MlKemPublicKey& key) {
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr),
                 EVP_PKEY_CTX_free);
  EVP_PKEY* p = nullptr;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        const_cast<uint8_t*>(key.data()),
                                        key.size()),
      OSSL_PARAM_construct_end()};
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &p, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
      p == nullptr) {
    throw Error("ML-KEM public-key import failed");
  }
  return PkeyPtr(p, EVP_PKEY_free);
}

PkeyPtr private_key_from_seed(const MlKemPrivateSeed& seed) {
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr),
                 EVP_PKEY_CTX_free);
  EVP_PKEY* p = nullptr;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
          OSSL_PKEY_PARAM_ML_KEM_SEED,
          const_cast<uint8_t*>(seed.data()), seed.size()),
      OSSL_PARAM_construct_end()};
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &p, EVP_PKEY_KEYPAIR, params) <= 0 ||
      p == nullptr) {
    throw Error("ML-KEM private-key import failed");
  }
  return PkeyPtr(p, EVP_PKEY_free);
}

PkeyPtr ml_dsa_private_from_seed(const MlDsaPrivateSeed& seed) {
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr),
                 EVP_PKEY_CTX_free);
  EVP_PKEY* p = nullptr;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(
          OSSL_PKEY_PARAM_ML_DSA_SEED,
          const_cast<uint8_t*>(seed.data()), seed.size()),
      OSSL_PARAM_construct_end()};
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &p, EVP_PKEY_KEYPAIR, params) <= 0 || !p) {
    throw Error("ML-DSA private-key import failed");
  }
  return PkeyPtr(p, EVP_PKEY_free);
}

PkeyPtr ml_dsa_public_from_raw(const MlDsaPublicKey& key) {
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr),
                 EVP_PKEY_CTX_free);
  EVP_PKEY* p = nullptr;
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        const_cast<uint8_t*>(key.data()),
                                        key.size()),
      OSSL_PARAM_construct_end()};
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &p, EVP_PKEY_PUBLIC_KEY, params) <= 0 || !p) {
    throw Error("ML-DSA public-key import failed");
  }
  return PkeyPtr(p, EVP_PKEY_free);
}

}  // namespace

MlKemKeyPair generate_ml_kem_768() {
  init_sodium();
  MlKemPrivateSeed seed;
  randombytes_buf(seed.data(), seed.size());
  return ml_kem_768_from_seed(seed);
}

MlKemKeyPair ml_kem_768_from_seed(const MlKemPrivateSeed& seed) {
  MlKemKeyPair result;
  result.private_seed.assign(seed);
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr),
                 EVP_PKEY_CTX_free);
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    throw Error("ML-KEM key generation initialization failed");
  }
  int retain_seed = 1;
  OSSL_PARAM keygen_params[] = {
      OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED,
                               &retain_seed),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                        result.private_seed.data(),
                                        result.private_seed.size()),
      OSSL_PARAM_construct_end()};
  if (EVP_PKEY_CTX_set_params(ctx.get(), keygen_params) <= 0) {
    throw Error("ML-KEM provider cannot retain the private seed");
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_generate(ctx.get(), &raw) <= 0 || raw == nullptr) {
    throw Error("ML-KEM key generation failed");
  }
  PkeyPtr key(raw, EVP_PKEY_free);

  std::size_t public_len = result.public_key.size();
  if (EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                      result.public_key.data(),
                                      result.public_key.size(), &public_len) <= 0 ||
      public_len != result.public_key.size()) {
    throw Error("ML-KEM public-key export failed (length " +
                std::to_string(public_len) + ")");
  }
  return result;
}

void ml_kem_768_encapsulate(const MlKemPublicKey& public_key,
                            MlKemCiphertext& ciphertext,
                            MlKemSharedSecret& shared_secret) {
  PkeyPtr key = public_key_from_raw(public_key);
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
  if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
    throw Error("ML-KEM encapsulation initialization failed");
  }
  std::size_t ct_len = ciphertext.size();
  std::size_t ss_len = shared_secret.size();
  if (EVP_PKEY_encapsulate(ctx.get(), ciphertext.data(), &ct_len,
                           shared_secret.data(), &ss_len) <= 0 ||
      ct_len != ciphertext.size() || ss_len != shared_secret.size()) {
    shared_secret.wipe();
    throw Error("ML-KEM encapsulation failed");
  }
}

void ml_kem_768_decapsulate(const MlKemPrivateSeed& private_seed,
                            const MlKemCiphertext& ciphertext,
                            MlKemSharedSecret& shared_secret) {
  PkeyPtr key = private_key_from_seed(private_seed);
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new(key.get(), nullptr), EVP_PKEY_CTX_free);
  if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
    throw Error("message authentication failed");
  }
  std::size_t ss_len = shared_secret.size();
  if (EVP_PKEY_decapsulate(ctx.get(), shared_secret.data(), &ss_len,
                           ciphertext.data(), ciphertext.size()) <= 0 ||
      ss_len != shared_secret.size()) {
    shared_secret.wipe();
    throw Error("message authentication failed");
  }
}

MlDsaKeyPair ml_dsa_65_from_seed(const MlDsaPrivateSeed& seed) {
  PkeyPtr key = ml_dsa_private_from_seed(seed);
  MlDsaKeyPair result;
  result.private_seed.assign(seed);
  std::size_t len = result.public_key.size();
  if (EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                      result.public_key.data(),
                                      result.public_key.size(), &len) <= 0 ||
      len != result.public_key.size()) {
    throw Error("ML-DSA public-key export failed");
  }
  return result;
}

void ml_dsa_65_sign(const MlDsaPrivateSeed& seed, const uint8_t* message,
                    std::size_t message_len, MlDsaSignature& signature) {
  PkeyPtr key = ml_dsa_private_from_seed(seed);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                             EVP_MD_CTX_free);
  if (!ctx || EVP_DigestSignInit_ex(ctx.get(), nullptr, nullptr, nullptr,
                                    nullptr, key.get(), nullptr) <= 0) {
    throw Error("ML-DSA signing initialization failed");
  }
  std::size_t len = signature.size();
  if (EVP_DigestSign(ctx.get(), signature.data(), &len, message, message_len) <= 0 ||
      len != signature.size()) {
    throw Error("ML-DSA signing failed");
  }
}

bool ml_dsa_65_verify(const MlDsaPublicKey& public_key, const uint8_t* message,
                      std::size_t message_len,
                      const MlDsaSignature& signature) {
  PkeyPtr key = ml_dsa_public_from_raw(public_key);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                             EVP_MD_CTX_free);
  if (!ctx || EVP_DigestVerifyInit_ex(ctx.get(), nullptr, nullptr, nullptr,
                                      nullptr, key.get(), nullptr) <= 0) {
    throw Error("ML-DSA verification initialization failed");
  }
  return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                          message, message_len) == 1;
}

}  // namespace ratchet::pq
