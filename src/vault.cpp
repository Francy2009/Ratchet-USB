#include "ratchet/vault.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>

namespace ratchet::vault {
namespace {

void put_u32_le(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
}

uint32_t get_u32_le(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

void check_params(uint32_t time_cost, uint32_t mem_cost_kb) {
  if (time_cost < kMinTimeCost || time_cost > kMaxTimeCost) {
    throw Error("Argon2id time cost out of range (" +
                std::to_string(kMinTimeCost) + ".." +
                std::to_string(kMaxTimeCost) + ")");
  }
  if (mem_cost_kb < kMinMemCostKb || mem_cost_kb > kMaxMemCostKb) {
    throw Error("Argon2id memory cost out of range (" +
                std::to_string(kMinMemCostKb) + ".." +
                std::to_string(kMaxMemCostKb) + " KiB)");
  }
}

// passphrase -> 32-byte ChaCha20-Poly1305 key, using the salt and costs from
// the header. This is the only place the passphrase is used.
void derive_vault_key(SecureBytes<crypto_aead_chacha20poly1305_ietf_KEYBYTES>& key,
                      const SecureString& passphrase, const VaultHeader& header) {
  static_assert(sizeof header.argon2_salt == crypto_pwhash_SALTBYTES,
                "header salt must match the Argon2id salt size");
  check_params(header.argon2_time_cost, header.argon2_mem_cost_kb);

  const size_t memlimit = static_cast<size_t>(header.argon2_mem_cost_kb) * 1024u;
  if (crypto_pwhash(key.data(), key.size(), passphrase.data(), passphrase.size(),
                    header.argon2_salt,
                    static_cast<unsigned long long>(header.argon2_time_cost),
                    memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
    // crypto_pwhash only fails when it cannot allocate its memory block.
    throw Error("Argon2id failed: not enough memory for the requested cost");
  }
}

}  // namespace

std::vector<uint8_t> serialize_header(const VaultHeader& header) {
  std::vector<uint8_t> out;
  out.reserve(kHeaderBytes);
  out.insert(out.end(), std::begin(header.magic), std::end(header.magic));
  out.push_back(header.version);
  out.insert(out.end(), std::begin(header.argon2_salt),
             std::end(header.argon2_salt));
  put_u32_le(out, header.argon2_time_cost);
  put_u32_le(out, header.argon2_mem_cost_kb);
  out.insert(out.end(), std::begin(header.nonce), std::end(header.nonce));
  if (out.size() != kHeaderBytes) {
    throw Error("internal: header serialisation produced the wrong size");
  }
  return out;
}

VaultHeader parse_header(const uint8_t* data, std::size_t len) {
  if (len < kHeaderBytes) {
    throw Error("vault file is truncated (header incomplete)");
  }

  VaultHeader header{};
  std::size_t off = 0;
  std::memcpy(header.magic, data + off, sizeof header.magic);
  off += sizeof header.magic;

  if (std::memcmp(header.magic, kMagic.data(), kMagic.size()) != 0) {
    throw Error("not a Ratchet-USB vault (bad magic)");
  }

  header.version = data[off++];
  if (header.version != kVersion) {
    throw Error("unsupported vault version " + std::to_string(header.version) +
                " (this build understands version " + std::to_string(kVersion) +
                ")");
  }

  std::memcpy(header.argon2_salt, data + off, sizeof header.argon2_salt);
  off += sizeof header.argon2_salt;

  header.argon2_time_cost = get_u32_le(data + off);
  off += 4;
  header.argon2_mem_cost_kb = get_u32_le(data + off);
  off += 4;

  std::memcpy(header.nonce, data + off, sizeof header.nonce);
  off += sizeof header.nonce;

  check_params(header.argon2_time_cost, header.argon2_mem_cost_kb);
  return header;
}

std::vector<uint8_t> seal(const SecureBuffer& plaintext,
                          const SecureString& passphrase, const Params& params) {
  init_sodium();
  check_params(params.time_cost, params.mem_cost_kb);
  if (passphrase.empty()) {
    throw Error("passphrase must not be empty");
  }

  VaultHeader header{};
  std::memcpy(header.magic, kMagic.data(), kMagic.size());
  header.version = kVersion;
  randombytes_buf(header.argon2_salt, sizeof header.argon2_salt);
  header.argon2_time_cost = params.time_cost;
  header.argon2_mem_cost_kb = params.mem_cost_kb;
  randombytes_buf(header.nonce, sizeof header.nonce);

  const std::vector<uint8_t> aad = serialize_header(header);

  SecureBytes<crypto_aead_chacha20poly1305_ietf_KEYBYTES> key;
  derive_vault_key(key, passphrase, header);

  std::vector<uint8_t> file(kHeaderBytes + plaintext.size() + kTagBytes);
  std::memcpy(file.data(), aad.data(), aad.size());

  unsigned long long ct_len = 0;
  // The header is authenticated as additional data, so the salt, the nonce and
  // the cost parameters are covered by the tag even though they stay in clear.
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          file.data() + kHeaderBytes, &ct_len, plaintext.data(),
          plaintext.size(), aad.data(), aad.size(), nullptr, header.nonce,
          key.data()) != 0) {
    throw Error("vault encryption failed");
  }
  if (ct_len != plaintext.size() + kTagBytes) {
    throw Error("internal: unexpected ciphertext length");
  }

  return file;
}

void unseal(const uint8_t* data, std::size_t len, const SecureString& passphrase,
           SecureBuffer& out) {
  init_sodium();
  if (len < kHeaderBytes + kTagBytes) {
    throw Error("vault file is too short to be valid");
  }

  const VaultHeader header = parse_header(data, len);
  const std::vector<uint8_t> aad = serialize_header(header);

  SecureBytes<crypto_aead_chacha20poly1305_ietf_KEYBYTES> key;
  derive_vault_key(key, passphrase, header);

  const std::size_t ct_len = len - kHeaderBytes;
  const std::size_t plaintext_len = ct_len - kTagBytes;
  std::vector<uint8_t> plaintext(plaintext_len);  // decrypted here, wiped below
  unsigned long long pt_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          plaintext.data(), &pt_len, nullptr, data + kHeaderBytes, ct_len,
          aad.data(), aad.size(), header.nonce, key.data()) != 0) {
    sodium_memzero(plaintext.data(), plaintext.size());
    // A wrong passphrase and a tampered file are the same failure here, and
    // saying which one it was would tell an attacker whether they guessed the
    // format right.
    throw Error("cannot open vault: wrong passphrase or corrupted file");
  }

  out.clear();
  out.append(plaintext.data(), static_cast<std::size_t>(pt_len));
  sodium_memzero(plaintext.data(), plaintext.size());
}

std::filesystem::path vault_path(const std::filesystem::path& usb_path) {
  return usb_path / kVaultFilename;
}

void write_file(const std::filesystem::path& path,
                const std::vector<uint8_t>& bytes, bool overwrite) {
  if (!overwrite && std::filesystem::exists(path)) {
    throw Error("refusing to overwrite an existing vault at " + path.string() +
                " (pass --force to replace it)");
  }

  // Write to a sibling temporary file first: a crash halfway through must not
  // destroy a vault that is still readable.
  const std::filesystem::path tmp = path.string() + ".tmp";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    throw Error("cannot create " + tmp.string() + ": " +
                std::strerror(errno));
  }

  std::size_t written = 0;
  while (written < bytes.size()) {
    const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      const std::string msg = std::strerror(errno);
      ::close(fd);
      std::filesystem::remove(tmp);
      throw Error("cannot write " + tmp.string() + ": " + msg);
    }
    written += static_cast<std::size_t>(n);
  }

  // fsync before the rename, otherwise the rename can reach the USB stick
  // before the data does.
  if (::fsync(fd) != 0) {
    const std::string msg = std::strerror(errno);
    ::close(fd);
    std::filesystem::remove(tmp);
    throw Error("cannot flush " + tmp.string() + ": " + msg);
  }
  ::close(fd);

  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(tmp);
    throw Error("cannot move the vault into place: " + ec.message());
  }

  // Flush the directory entry too, so the file survives an unplug.
  const int dir_fd = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd >= 0) {
    ::fsync(dir_fd);
    ::close(dir_fd);
  }
}

std::vector<uint8_t> read_file(const std::filesystem::path& path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) {
    throw Error("no vault at " + path.string() + " (run `init` first)");
  }

  const auto size = std::filesystem::file_size(path, ec);
  if (ec) {
    throw Error("cannot stat " + path.string() + ": " + ec.message());
  }
  if (size < kHeaderBytes + kTagBytes) {
    throw Error("vault file at " + path.string() + " is too short to be valid");
  }

  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) {
    throw Error("cannot open " + path.string() + ": " + std::strerror(errno));
  }
  std::vector<uint8_t> bytes(static_cast<std::size_t>(size));
  const std::size_t got = std::fread(bytes.data(), 1, bytes.size(), f);
  std::fclose(f);
  if (got != bytes.size()) {
    throw Error("short read on " + path.string());
  }
  return bytes;
}

}  // namespace ratchet::vault
