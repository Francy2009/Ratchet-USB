#include "ratchet/vault.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>

namespace ratchet::vault {
namespace {

[[noreturn]] void throw_errno(const char* action) {
  throw Error(std::string(action) + ": " + std::strerror(errno));
}

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

FileLock::FileLock(const std::filesystem::path& vault_path) {
  const int dir_fd = ::open(vault_path.parent_path().c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd < 0) throw_errno("cannot open vault directory for locking");
  fd_ = ::openat(dir_fd, ".ratchet-usb.lock",
                 O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
  const int open_error = errno;
  ::close(dir_fd);
  errno = open_error;
  if (fd_ < 0 || ::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
    throw Error("vault is already open or its filesystem cannot provide a safe lock");
  }
  struct stat st {};
  if (::fstat(fd_, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != ::geteuid()) {
    ::close(fd_);
    fd_ = -1;
    throw Error("vault lock file is unsafe");
  }
}

FileLock::~FileLock() {
  if (fd_ >= 0) {
    (void)::flock(fd_, LOCK_UN);
    (void)::close(fd_);
  }
}

FileLock::FileLock(FileLock&& other) noexcept : fd_(other.fd_) {
  other.fd_ = -1;
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) { (void)::flock(fd_, LOCK_UN); (void)::close(fd_); }
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  return *this;
}

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
  if (header.version != kVersion && header.version != kWordVersion &&
      header.version != kLegacyVersion) {
    throw Error("unsupported vault version " + std::to_string(header.version) +
                " (this build understands versions " +
                std::to_string(kLegacyVersion) + ", " + std::to_string(kVersion) +
                " and " + std::to_string(kWordVersion) + ")");
  }

  std::memcpy(header.argon2_salt, data + off, sizeof header.argon2_salt);
  off += sizeof header.argon2_salt;

  header.argon2_time_cost = get_u32_le(data + off);
  off += 4;
  header.argon2_mem_cost_kb = get_u32_le(data + off);
  off += 4;

  std::memcpy(header.nonce, data + off, sizeof header.nonce);
  // The cursor is not read again, but every field advances it: dropping the
  // last increment is how the next field added here acquires a silent bug.
  off += sizeof header.nonce;
  (void)off;

  check_params(header.argon2_time_cost, header.argon2_mem_cost_kb);
  return header;
}

std::vector<uint8_t> seal(const SecureBuffer& plaintext,
                          const SecureString& passphrase, const Params& params,
                          uint8_t version) {
  init_sodium();
  check_params(params.time_cost, params.mem_cost_kb);
  if (passphrase.empty()) {
    throw Error("passphrase must not be empty");
  }
  if (version != kVersion && version != kWordVersion) {
    throw Error("internal: seal called with an unsupported vault version");
  }

  VaultHeader header{};
  std::memcpy(header.magic, kMagic.data(), kMagic.size());
  header.version = version;
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
  if (len > kMaxVaultBytes) {
    throw Error("vault file exceeds the 64 MiB format limit");
  }

  const VaultHeader header = parse_header(data, len);
  const std::vector<uint8_t> aad = serialize_header(header);

  SecureBytes<crypto_aead_chacha20poly1305_ietf_KEYBYTES> key;
  derive_vault_key(key, passphrase, header);

  const std::size_t ct_len = len - kHeaderBytes;
  const std::size_t plaintext_len = ct_len - kTagBytes;
  out.clear();
  out.resize(plaintext_len);
  unsigned long long pt_len = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          out.data(), &pt_len, nullptr, data + kHeaderBytes, ct_len,
          aad.data(), aad.size(), header.nonce, key.data()) != 0) {
    out.clear();
    // A wrong passphrase and a tampered file are the same failure here, and
    // saying which one it was would tell an attacker whether they guessed the
    // format right.
    throw Error("cannot open vault: wrong passphrase or corrupted file");
  }
  out.resize(static_cast<std::size_t>(pt_len));
}

std::filesystem::path vault_path(const std::filesystem::path& usb_path) {
  return usb_path / kVaultFilename;
}

void write_file(const std::filesystem::path& path,
                const std::vector<uint8_t>& bytes, bool overwrite) {
  if (bytes.size() > kMaxVaultBytes) {
    throw Error("refusing to write a vault larger than 64 MiB");
  }
  const int dir_fd = ::open(path.parent_path().c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd < 0) throw_errno("cannot open vault directory");
  const std::string name = path.filename().string();
  struct stat existing {};
  if (::fstatat(dir_fd, name.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0) {
    if (!overwrite) {
      ::close(dir_fd);
      throw Error("refusing to overwrite an existing vault at " + path.string() +
                  " (pass --force to replace it)");
    }
    if (!S_ISREG(existing.st_mode) || existing.st_uid != ::geteuid() ||
        existing.st_nlink != 1) {
      ::close(dir_fd);
      throw Error("existing vault path is unsafe to replace");
    }
  } else if (errno != ENOENT) {
    const int saved = errno;
    ::close(dir_fd);
    errno = saved;
    throw_errno("cannot inspect destination vault");
  }

  // Write to a sibling temporary file first: a crash halfway through must not
  // destroy a vault that is still readable.
  std::array<uint8_t, 12> suffix{};
  randombytes_buf(suffix.data(), suffix.size());
  char suffix_hex[suffix.size() * 2 + 1]{};
  sodium_bin2hex(suffix_hex, sizeof suffix_hex, suffix.data(), suffix.size());
  const std::string tmp_name = name + ".tmp." + suffix_hex;
  const int fd = ::openat(dir_fd, tmp_name.c_str(),
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          0600);
  if (fd < 0) {
    const int saved = errno;
    ::close(dir_fd);
    errno = saved;
    throw_errno("cannot create temporary vault");
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
      ::unlinkat(dir_fd, tmp_name.c_str(), 0);
      ::close(dir_fd);
      throw Error("cannot write temporary vault: " + msg);
    }
    written += static_cast<std::size_t>(n);
  }

  // fsync before the rename, otherwise the rename can reach the USB stick
  // before the data does.
  if (::fsync(fd) != 0) {
    const std::string msg = std::strerror(errno);
    ::close(fd);
    ::unlinkat(dir_fd, tmp_name.c_str(), 0);
    ::close(dir_fd);
    throw Error("cannot flush temporary vault: " + msg);
  }
  if (::close(fd) != 0) {
    const int saved = errno;
    ::unlinkat(dir_fd, tmp_name.c_str(), 0);
    ::close(dir_fd);
    errno = saved;
    throw_errno("cannot close temporary vault");
  }

  if (::renameat(dir_fd, tmp_name.c_str(), dir_fd, name.c_str()) != 0) {
    const int saved = errno;
    ::unlinkat(dir_fd, tmp_name.c_str(), 0);
    ::close(dir_fd);
    errno = saved;
    throw_errno("cannot move the vault into place");
  }

  // Flush the directory entry too, so the file survives an unplug.
  if (::fsync(dir_fd) != 0) {
    const std::string msg = std::strerror(errno);
    ::close(dir_fd);
    throw Error("cannot flush vault directory: " + msg);
  }
  if (::close(dir_fd) != 0) throw_errno("cannot close vault directory");
}

std::vector<uint8_t> read_file(const std::filesystem::path& path) {
  const int dir_fd = ::open(path.parent_path().c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd < 0) throw_errno("cannot open vault directory");
  const std::string name = path.filename().string();
  const int fd = ::openat(dir_fd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    const int saved = errno;
    ::close(dir_fd);
    errno = saved;
    throw_errno(("cannot open " + path.string()).c_str());
  }
  ::close(dir_fd);
  struct stat st {};
  if (::fstat(fd, &st) != 0) {
    const std::string msg = std::strerror(errno);
    ::close(fd);
    throw Error("cannot stat " + path.string() + ": " + msg);
  }
  if (!S_ISREG(st.st_mode) || st.st_nlink != 1) {
    ::close(fd);
    throw Error("vault path is not a uniquely linked regular file");
  }
  if (st.st_uid != ::geteuid()) {
    ::close(fd);
    throw Error("vault file is not owned by the current user");
  }
  const auto size = static_cast<uint64_t>(st.st_size);
  if (size < kHeaderBytes + kTagBytes) {
    ::close(fd);
    throw Error("vault file at " + path.string() + " is too short to be valid");
  }
  if (size > kMaxVaultBytes) {
    ::close(fd);
    throw Error("vault file exceeds the 64 MiB format limit");
  }
  std::vector<uint8_t> bytes(static_cast<std::size_t>(size));
  std::size_t got = 0;
  while (got < bytes.size()) {
    const ssize_t n = ::read(fd, bytes.data() + got, bytes.size() - got);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      ::close(fd);
      throw Error("short read on " + path.string());
    }
    got += static_cast<std::size_t>(n);
  }
  ::close(fd);
  return bytes;
}

void promote_prepared(const std::filesystem::path& prepared,
                      const std::filesystem::path& target) {
  if (prepared.parent_path() != target.parent_path()) {
    throw Error("prepared vault must be on the same filesystem as vault.bin");
  }
  const std::filesystem::path dir_path = target.parent_path();
  const int dir_fd = ::open(dir_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir_fd < 0) throw_errno("cannot open vault directory");
  if (::renameat(dir_fd, prepared.filename().c_str(), dir_fd,
                 target.filename().c_str()) != 0) {
    const int saved = errno;
    ::close(dir_fd);
    errno = saved;
    throw_errno("cannot promote prepared vault");
  }
  if (::fsync(dir_fd) != 0) {
    const int saved = errno;
    ::close(dir_fd);
    errno = saved;
    throw_errno("cannot fsync vault directory after migration commit");
  }
  if (::close(dir_fd) != 0) throw_errno("cannot close vault directory");
}

}  // namespace ratchet::vault
