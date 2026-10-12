#include "ratchet/rollback.hpp"

#include <sodium.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <memory>
#include <string_view>
#include <vector>

#include "ratchet/secure.hpp"
#include "ratchet/serial.hpp"

#if defined(RATCHET_HAVE_LIBSECRET)
#include <libsecret/secret.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#endif

namespace ratchet::rollback {
namespace {

constexpr std::string_view kRecordMagic = "RANCHOR1";

[[maybe_unused]] std::string encode(const AnchorRecord& record) {
  std::vector<uint8_t> raw;
  serial::Writer<std::vector<uint8_t>> w(raw);
  w.bytes(reinterpret_cast<const uint8_t*>(kRecordMagic.data()),
          kRecordMagic.size());
  w.bytes(record.vault_id.data(), record.vault_id.size());
  w.u64(record.generation);
  w.bytes(record.vault_digest.data(), record.vault_digest.size());
  return [&] {
    std::string out(sodium_base64_ENCODED_LEN(raw.size(),
                                             sodium_base64_VARIANT_URLSAFE_NO_PADDING),
                    '\0');
    sodium_bin2base64(out.data(), out.size(), raw.data(), raw.size(),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(std::strlen(out.c_str()));
    return out;
  }();
}

[[maybe_unused]] AnchorRecord decode(std::string_view text) {
  std::vector<uint8_t> raw(text.size());
  std::size_t size = 0;
  if (sodium_base642bin(raw.data(), raw.size(), text.data(), text.size(), nullptr,
                        &size, nullptr,
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
    throw Error("host rollback anchor is corrupt");
  }
  raw.resize(size);
  serial::Reader r(raw.data(), raw.size());
  std::array<uint8_t, kRecordMagic.size()> magic{};
  r.bytes(magic.data(), magic.size());
  if (!std::equal(magic.begin(), magic.end(), kRecordMagic.begin())) {
    throw Error("host rollback anchor has an unsupported format");
  }
  AnchorRecord record;
  r.bytes(record.vault_id.data(), record.vault_id.size());
  record.generation = r.u64();
  r.bytes(record.vault_digest.data(), record.vault_digest.size());
  if (!r.at_end()) throw Error("host rollback anchor has trailing data");
  return record;
}

#if defined(RATCHET_HAVE_LIBSECRET)
const SecretSchema kSchema = {
    "org.ratchet_usb.RollbackAnchor", SECRET_SCHEMA_NONE,
    {{"vault-id", SECRET_SCHEMA_ATTRIBUTE_STRING},
     {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}}};
#elif defined(__APPLE__)
// Current macOS SDKs mark the SecKeychain functions deprecated, and CI builds
// with -Werror. SecItem is the supported Keychain interface.
struct ReleaseCf {
  void operator()(CFTypeRef value) const noexcept {
    if (value != nullptr) CFRelease(value);
  }
};

template <typename Ref>
using CfPtr = std::unique_ptr<std::remove_pointer_t<Ref>, ReleaseCf>;

constexpr std::string_view kKeychainService = "Ratchet-USB";

CfPtr<CFStringRef> cf_string(std::string_view text) {
  CFStringRef raw = CFStringCreateWithBytes(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(text.data()),
      static_cast<CFIndex>(text.size()), kCFStringEncodingUTF8, false);
  if (raw == nullptr) throw Error("cannot encode a Keychain attribute");
  return CfPtr<CFStringRef>(raw);
}

CfPtr<CFDataRef> cf_data(std::string_view bytes) {
  CFDataRef raw = CFDataCreate(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(bytes.data()),
      static_cast<CFIndex>(bytes.size()));
  if (raw == nullptr) throw Error("cannot encode a Keychain value");
  return CfPtr<CFDataRef>(raw);
}

CfPtr<CFMutableDictionaryRef> keychain_query(CFStringRef account) {
  CFMutableDictionaryRef raw = CFDictionaryCreateMutable(
      kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  if (raw == nullptr) throw Error("cannot build a Keychain query");
  CfPtr<CFMutableDictionaryRef> query(raw);
  const CfPtr<CFStringRef> service = cf_string(kKeychainService);
  CFDictionarySetValue(query.get(), kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query.get(), kSecAttrService, service.get());
  CFDictionarySetValue(query.get(), kSecAttrAccount, account);
  return query;
}
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

Status validate(const AnchorRecord& anchor, const store::VaultStore& usb,
                const Digest& usb_digest) {
  if (sodium_memcmp(anchor.vault_id.data(), usb.vault_id.data(),
                    usb.vault_id.size()) != 0) {
    throw Error("rollback anchor belongs to a different vault");
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
#if defined(RATCHET_HAVE_LIBSECRET) || defined(__APPLE__)
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
  return record;
#elif defined(__APPLE__)
  const CfPtr<CFStringRef> account = cf_string(id);
  CfPtr<CFMutableDictionaryRef> query = keychain_query(account.get());
  CFDictionarySetValue(query.get(), kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(query.get(), kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef found = nullptr;
  const OSStatus status = SecItemCopyMatching(query.get(), &found);
  if (status == errSecItemNotFound) return std::nullopt;
  if (status != errSecSuccess || found == nullptr ||
      CFGetTypeID(found) != CFDataGetTypeID()) {
    if (found != nullptr) CFRelease(found);
    throw Error("cannot read rollback anchor from Keychain");
  }
  const CfPtr<CFDataRef> secret(static_cast<CFDataRef>(found));
  const UInt8* bytes = CFDataGetBytePtr(secret.get());
  const CFIndex length = CFDataGetLength(secret.get());
  const char* text = bytes == nullptr ? "" : reinterpret_cast<const char*>(bytes);
  return decode(std::string_view(text, static_cast<std::size_t>(length)));
#else
  (void)id;
  return std::nullopt;
#endif
}

void store(const AnchorRecord& record) {
  const std::string id = vault_id_text(record.vault_id);
  const std::string value = encode(record);
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
#elif defined(__APPLE__)
  const CfPtr<CFStringRef> account = cf_string(id);
  CfPtr<CFMutableDictionaryRef> query = keychain_query(account.get());
  const CfPtr<CFDataRef> secret = cf_data(value);
  const void* keys[] = {kSecValueData};
  const void* values[] = {secret.get()};
  const CfPtr<CFDictionaryRef> changes(CFDictionaryCreate(
      kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks));
  if (changes == nullptr) throw Error("cannot store rollback anchor in Keychain");
  OSStatus status = SecItemUpdate(query.get(), changes.get());
  if (status == errSecItemNotFound) {
    CFDictionarySetValue(query.get(), kSecValueData, secret.get());
    status = SecItemAdd(query.get(), nullptr);
  }
  if (status != errSecSuccess) throw Error("cannot store rollback anchor in Keychain");
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
  store(AnchorRecord{usb.vault_id, usb.generation, usb_digest});
}

}  // namespace ratchet::rollback
