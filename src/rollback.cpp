#include "ratchet/rollback.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "ratchet/kdf.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/serial.hpp"

#if defined(RATCHET_HAVE_LIBSECRET)
#include <libsecret/secret.h>
#endif

namespace ratchet::rollback {
namespace {

constexpr std::string_view kLegacyMagic = "RANCHOR1";
constexpr std::string_view kMacMagic = "RANCHOR2";
constexpr std::string_view kMacInfo = "Ratchet-USB/v4/rollback-anchor";
static_assert(kLegacyMagic.size() == kMacMagic.size());

void write_fields(serial::Writer<std::vector<uint8_t>>& writer,
                  std::string_view magic, const AnchorRecord& record) {
  writer.bytes(reinterpret_cast<const uint8_t*>(magic.data()), magic.size());
  writer.bytes(record.vault_id.data(), record.vault_id.size());
  writer.u64(record.generation);
  writer.bytes(record.vault_digest.data(), record.vault_digest.size());
}

std::vector<uint8_t> mac_message(const AnchorRecord& record) {
  std::vector<uint8_t> raw;
  serial::Writer<std::vector<uint8_t>> writer(raw);
  write_fields(writer, kMacMagic, record);
  return raw;
}

void derive_mac_key(const MasterSeed& seed, SecureBytes<32>& key) {
  kdf::Prk prk;
  kdf::extract(prk, nullptr, 0, seed.data(), seed.size());
  kdf::expand(key.data(), key.size(), kMacInfo, prk);
}

std::string base64_url(const std::vector<uint8_t>& raw) {
  std::string out(sodium_base64_ENCODED_LEN(
                      raw.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING),
                  '\0');
  sodium_bin2base64(out.data(), out.size(), raw.data(), raw.size(),
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  out.resize(std::strlen(out.c_str()));
  return out;
}

bool magic_is(const std::array<uint8_t, kMacMagic.size()>& magic,
              std::string_view expected) {
  return std::equal(magic.begin(), magic.end(), expected.begin());
}

#if defined(RATCHET_HAVE_LIBSECRET)
const SecretSchema kSchema = {
    "org.ratchet_usb.RollbackAnchor", SECRET_SCHEMA_NONE,
    {{"vault-id", SECRET_SCHEMA_ATTRIBUTE_STRING},
     {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}}};
#endif

}  // namespace

Digest digest(const uint8_t* bytes, std::size_t size) {
  Digest out{};
  crypto_hash_sha256(out.data(), bytes, static_cast<unsigned long long>(size));
  return out;
}

std::string vault_id_text(const store::VaultId& id) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(id.size() * 2, '0');
  for (std::size_t i = 0; i < id.size(); ++i) {
    out[2 * i] = kHex[id[i] >> 4];
    out[2 * i + 1] = kHex[id[i] & 0x0f];
  }
  return out;
}

void authenticate(AnchorRecord& record, const MasterSeed& seed) {
  SecureBytes<32> key;
  derive_mac_key(seed, key);
  const std::vector<uint8_t> message = mac_message(record);
  if (crypto_auth_hmacsha256(record.mac.data(), message.data(), message.size(),
                             key.data()) != 0) {
    throw Error("rollback anchor authentication failed");
  }
  record.authenticated = true;
}

std::string encode(const AnchorRecord& record) {
  std::vector<uint8_t> raw;
  if (record.authenticated) {
    raw = mac_message(record);
    raw.insert(raw.end(), record.mac.begin(), record.mac.end());
  } else {
    serial::Writer<std::vector<uint8_t>> writer(raw);
    write_fields(writer, kLegacyMagic, record);
  }
  return base64_url(raw);
}

AnchorRecord decode(std::string_view text) {
  std::vector<uint8_t> raw(text.size());
  std::size_t size = 0;
  if (sodium_base642bin(raw.data(), raw.size(), text.data(), text.size(),
                        nullptr, &size, nullptr,
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
    throw Error("host rollback anchor is corrupt");
  }
  raw.resize(size);
  serial::Reader reader(raw.data(), raw.size());
  std::array<uint8_t, kMacMagic.size()> magic{};
  reader.bytes(magic.data(), magic.size());
  const bool authenticated = magic_is(magic, kMacMagic);
  if (!authenticated && !magic_is(magic, kLegacyMagic)) {
    throw Error("host rollback anchor has an unsupported format");
  }
  AnchorRecord record;
  reader.bytes(record.vault_id.data(), record.vault_id.size());
  record.generation = reader.u64();
  reader.bytes(record.vault_digest.data(), record.vault_digest.size());
  record.authenticated = authenticated;
  if (authenticated) {
    reader.bytes(record.mac.data(), record.mac.size());
  }
  if (!reader.at_end()) throw Error("host rollback anchor has trailing data");
  return record;
}

Status validate(const AnchorRecord& anchor, const store::VaultStore& usb,
                const Digest& usb_digest) {
  // An unauthenticated anchor is a legacy RANCHOR1 record: it carries no tag,
  // so nothing in it can be trusted, not even the vault id it names. It is
  // refused outright rather than downgraded to generation-only checks -- which
  // is exactly what would let anyone able to write the host anchor store
  // bypass rollback detection by replacing the signed record with a forged
  // legacy one. The fix for an old anchor is to re-enroll it.
  if (!anchor.authenticated) {
    throw Error(
        "rollback anchor is not authenticated; re-enroll it with "
        "`ratchet-usb anchor`");
  }
  if (sodium_memcmp(anchor.vault_id.data(), usb.vault_id.data(),
                    usb.vault_id.size()) != 0) {
    throw Error("rollback anchor belongs to a different vault");
  }
  SecureBytes<32> key;
  derive_mac_key(usb.seed, key);
  const std::vector<uint8_t> message = mac_message(anchor);
  if (crypto_auth_hmacsha256_verify(anchor.mac.data(), message.data(),
                                    message.size(), key.data()) != 0) {
    throw Error("rollback anchor authentication failed");
  }
  if (usb.generation < anchor.generation) {
    throw Error("vault rollback detected: USB generation is older than host anchor");
  }
  if (usb.generation == anchor.generation) {
    if (sodium_memcmp(anchor.vault_digest.data(), usb_digest.data(),
                      usb_digest.size()) != 0) {
      throw Error("vault fork or same-generation replacement detected");
    }
    return Status::Protected;
  }
  if (anchor.generation != UINT64_MAX &&
      usb.generation == anchor.generation + 1 &&
      sodium_memcmp(usb.previous_digest.data(), anchor.vault_digest.data(),
                    anchor.vault_digest.size()) == 0) {
    return Status::AdvancedAfterCrash;
  }
  throw Error("vault generation gap or invalid rollback chain detected");
}

bool backend_available() {
#if defined(RATCHET_HAVE_LIBSECRET)
  return true;
#else
  return false;
#endif
}

std::optional<AnchorRecord> load(const store::VaultId& vault_id) {
  const std::string id = vault_id_text(vault_id);
#if defined(RATCHET_HAVE_LIBSECRET)
  GError* error = nullptr;
  gchar* password = secret_password_lookup_sync(&kSchema, nullptr, &error,
                                                 "vault-id", id.c_str(), nullptr);
  if (error != nullptr) {
    const std::string message = error->message;
    g_error_free(error);
    throw Error("cannot read rollback anchor from Secret Service: " + message);
  }
  if (password == nullptr) return std::nullopt;
  const AnchorRecord record = decode(password);
  secret_password_free(password);
  // A legacy RANCHOR1 record carries no tag, so it cannot be told apart from
  // one an attacker wrote. It is reported as "no anchor" rather than returned:
  // trusting it would defeat the authenticated format, and returning it would
  // only invite a caller to. The user sees USB-only mode and can re-enroll.
  if (!record.authenticated) {
    return std::nullopt;
  }
  return record;
#else
  (void)id;
  return std::nullopt;
#endif
}

void store(const AnchorRecord& record, const MasterSeed& seed) {
  AnchorRecord authenticated = record;
  authenticate(authenticated, seed);
  const std::string id = vault_id_text(authenticated.vault_id);
  const std::string value = encode(authenticated);
#if defined(RATCHET_HAVE_LIBSECRET)
  GError* error = nullptr;
  const gboolean ok = secret_password_store_sync(
      &kSchema, SECRET_COLLECTION_DEFAULT, "Ratchet-USB rollback anchor",
      value.c_str(), nullptr, &error, "vault-id", id.c_str(), nullptr);
  if (!ok || error != nullptr) {
    const std::string message = error == nullptr ? "unknown error" : error->message;
    if (error != nullptr) g_error_free(error);
    throw Error("cannot store rollback anchor in Secret Service: " + message);
  }
#else
  (void)id;
  (void)value;
  throw Error("no supported host rollback-anchor service is available");
#endif
}

void enroll(const store::VaultStore& usb, const Digest& usb_digest) {
  if (!backend_available()) {
    throw Error("no supported host rollback-anchor service is available");
  }
  if (load(usb.vault_id)) {
    throw Error("this vault already has a rollback anchor on this host");
  }
  store(AnchorRecord{usb.vault_id, usb.generation, usb_digest}, usb.seed);
}

}  // namespace ratchet::rollback
