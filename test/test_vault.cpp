#include <sys/stat.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ratchet/bip39.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/vault.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
using namespace ratchet;

namespace {

// Argon2id at its cheapest. Real vaults use the defaults from vault.hpp; the
// tests only care that the key derivation is wired up, not that it is slow.
constexpr vault::Params kFastParams{/*time_cost=*/1, /*mem_cost_kb=*/8};

SecureString make_pass(std::string_view text) {
  SecureString s;
  for (char c : text) {
    s.push_back(c);
  }
  return s;
}

// Secrets holds SecureBytes, which cannot be copied or moved on purpose, so
// this fills a buffer owned by the caller.
void make_secrets(vault::Secrets& secrets) {
  bip39::Entropy entropy;
  bip39::decode("ozone drill grab fiber curtain grace pudding thank cruise "
                "elder eight picnic",
                entropy);
  derive_master_seed(entropy, secrets.seed);
  IdentityPublicKey pk{};
  derive_identity(secrets.seed, secrets.identity_sk, pk);
}

// Unique scratch directory per test, removed when the object goes out of scope.
class TempDir {
 public:
  TempDir() {
    char suffix[17];
    randombytes_buf(suffix, sizeof suffix - 1);
    for (size_t i = 0; i + 1 < sizeof suffix; ++i) {
      suffix[i] = static_cast<char>('a' + (static_cast<unsigned char>(suffix[i]) % 26));
    }
    suffix[sizeof suffix - 1] = '\0';
    path_ = fs::temp_directory_path() / ("ratchet-test-" + std::string(suffix));
    fs::create_directories(path_);
  }

  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }

  const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

}  // namespace

TEST("header serialises to exactly 41 bytes in the documented order") {
  vault::VaultHeader header{};
  std::memcpy(header.magic, vault::kMagic.data(), vault::kMagic.size());
  header.version = vault::kVersion;
  for (size_t i = 0; i < sizeof header.argon2_salt; ++i) {
    header.argon2_salt[i] = static_cast<uint8_t>(i);
  }
  header.argon2_time_cost = 3;
  header.argon2_mem_cost_kb = 262144;
  for (size_t i = 0; i < sizeof header.nonce; ++i) {
    header.nonce[i] = static_cast<uint8_t>(0xA0 + i);
  }

  const std::vector<uint8_t> bytes = vault::serialize_header(header);
  CHECK_EQ(bytes.size(), vault::kHeaderBytes);
  CHECK_EQ(bytes.size(), 41u);

  CHECK_EQ(bytes[0], uint8_t('R'));
  CHECK_EQ(bytes[1], uint8_t('C'));
  CHECK_EQ(bytes[2], uint8_t('H'));
  CHECK_EQ(bytes[3], uint8_t('T'));
  CHECK_EQ(bytes[4], vault::kVersion);
  CHECK_EQ(bytes[5], 0u);
  CHECK_EQ(bytes[20], 15u);
  // Little-endian 32-bit costs.
  CHECK_EQ(bytes[21], 3u);
  CHECK_EQ(bytes[22], 0u);
  CHECK_EQ(bytes[25], 0u);
  CHECK_EQ(bytes[26], 0x00u);
  CHECK_EQ(bytes[27], 0x04u);  // 262144 = 0x00040000
  CHECK_EQ(bytes[28], 0x00u);
  CHECK_EQ(bytes[29], 0xA0u);
  CHECK_EQ(bytes[40], 0xABu);

  // And it parses back to the same values.
  const vault::VaultHeader parsed =
      vault::parse_header(bytes.data(), bytes.size());
  CHECK_EQ(parsed.version, vault::kVersion);
  CHECK_EQ(parsed.argon2_time_cost, 3u);
  CHECK_EQ(parsed.argon2_mem_cost_kb, 262144u);
  CHECK(std::memcmp(parsed.nonce, header.nonce, sizeof header.nonce) == 0);
  CHECK(std::memcmp(parsed.argon2_salt, header.argon2_salt,
                    sizeof header.argon2_salt) == 0);
}

TEST("parse_header rejects malformed headers") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("correct horse battery staple");
  std::vector<uint8_t> file = vault::seal(secrets, pass, kFastParams);

  CHECK_THROWS(vault::parse_header(file.data(), 10));

  std::vector<uint8_t> bad_magic = file;
  bad_magic[0] = 'X';
  CHECK_THROWS(vault::parse_header(bad_magic.data(), bad_magic.size()));

  std::vector<uint8_t> bad_version = file;
  bad_version[4] = 99;
  CHECK_THROWS(vault::parse_header(bad_version.data(), bad_version.size()));

  // A doctored memory cost must be refused before it reaches Argon2, or
  // opening a hostile file would try to allocate terabytes.
  std::vector<uint8_t> huge_mem = file;
  huge_mem[25] = 0xFF;
  huge_mem[26] = 0xFF;
  huge_mem[27] = 0xFF;
  huge_mem[28] = 0xFF;
  CHECK_THROWS(vault::parse_header(huge_mem.data(), huge_mem.size()));

  std::vector<uint8_t> zero_time = file;
  zero_time[21] = 0;
  zero_time[22] = 0;
  zero_time[23] = 0;
  zero_time[24] = 0;
  CHECK_THROWS(vault::parse_header(zero_time.data(), zero_time.size()));
}

TEST("seal/unseal round-trip recovers seed and identity key") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("un passphrase abbastanza lunga 42");

  const std::vector<uint8_t> file = vault::seal(secrets, pass, kFastParams);
  CHECK_EQ(file.size(), vault::kVaultBytes);
  CHECK_EQ(file.size(), 41u + 64u + 16u);

  vault::Secrets opened;
  vault::unseal(file.data(), file.size(), pass, opened);
  CHECK(opened.seed.equals(secrets.seed));
  CHECK(opened.identity_sk.equals(secrets.identity_sk));

  // The public key derived after a round-trip must be the original one.
  IdentityPublicKey before{};
  IdentityPublicKey after{};
  identity_public_from_secret(secrets.identity_sk, before);
  identity_public_from_secret(opened.identity_sk, after);
  CHECK(before == after);
}

TEST("the plaintext never appears in the vault file") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> file = vault::seal(secrets, pass, kFastParams);

  for (size_t i = 0; i + kSeedBytes <= file.size(); ++i) {
    CHECK(std::memcmp(file.data() + i, secrets.seed.data(), kSeedBytes) != 0);
    CHECK(std::memcmp(file.data() + i, secrets.identity_sk.data(),
                      kX25519SecretBytes) != 0);
  }
}

TEST("sealing the same secrets twice produces different bytes") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("passphrase");

  const std::vector<uint8_t> a = vault::seal(secrets, pass, kFastParams);
  const std::vector<uint8_t> b = vault::seal(secrets, pass, kFastParams);
  CHECK(a != b);

  // Both still open: the salt and the nonce differ, the secrets do not.
  vault::Secrets from_a;
  vault::Secrets from_b;
  vault::unseal(a.data(), a.size(), pass, from_a);
  vault::unseal(b.data(), b.size(), pass, from_b);
  CHECK(from_a.seed.equals(from_b.seed));
}

TEST("a wrong passphrase does not open the vault") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const std::vector<uint8_t> file =
      vault::seal(secrets, make_pass("right passphrase"), kFastParams);

  vault::Secrets out;
  CHECK_THROWS(
      vault::unseal(file.data(), file.size(), make_pass("wrong passphrase"), out));
  CHECK_THROWS(
      vault::unseal(file.data(), file.size(), make_pass("right passphras"), out));
  CHECK_THROWS(
      vault::unseal(file.data(), file.size(), make_pass("Right passphrase"), out));
}

TEST("an empty passphrase is refused") {
  vault::Secrets secrets;
  make_secrets(secrets);
  CHECK_THROWS(vault::seal(secrets, make_pass(""), kFastParams));
}

TEST("tampering with any byte of the file is detected") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> file = vault::seal(secrets, pass, kFastParams);

  // The header is authenticated as additional data, so flipping a bit in the
  // salt, in the cost parameters or in the nonce has to fail just like
  // flipping one in the ciphertext or in the tag.
  for (size_t i = 4; i < file.size(); ++i) {
    std::vector<uint8_t> broken = file;
    broken[i] ^= 0x01;
    vault::Secrets out;
    CHECK_THROWS(vault::unseal(broken.data(), broken.size(), pass, out));
  }
}

TEST("truncated or padded vault files are refused") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("passphrase");
  std::vector<uint8_t> file = vault::seal(secrets, pass, kFastParams);

  vault::Secrets out;
  std::vector<uint8_t> short_file(file.begin(), file.end() - 1);
  CHECK_THROWS(vault::unseal(short_file.data(), short_file.size(), pass, out));

  std::vector<uint8_t> long_file = file;
  long_file.push_back(0);
  CHECK_THROWS(vault::unseal(long_file.data(), long_file.size(), pass, out));
}

TEST("seal rejects out-of-range Argon2 parameters") {
  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("passphrase");

  CHECK_THROWS(vault::seal(secrets, pass, vault::Params{0, 8}));
  CHECK_THROWS(vault::seal(secrets, pass, vault::Params{1, 4}));
  CHECK_THROWS(
      vault::seal(secrets, pass, vault::Params{1, vault::kMaxMemCostKb + 1}));
  CHECK_THROWS(
      vault::seal(secrets, pass, vault::Params{vault::kMaxTimeCost + 1, 8}));
}

TEST("write_file creates a 0600 file and read_file returns it unchanged") {
  TempDir dir;
  const fs::path path = vault::vault_path(dir.path());
  CHECK_EQ(path.filename().string(), std::string("vault.bin"));

  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> file = vault::seal(secrets, pass, kFastParams);

  vault::write_file(path, file, /*overwrite=*/false);
  CHECK(fs::exists(path));

  struct stat st {};
  CHECK_EQ(::stat(path.c_str(), &st), 0);
  CHECK_EQ(st.st_mode & 0777u, 0600u);

  // No temporary file is left behind.
  CHECK(!fs::exists(path.string() + ".tmp"));

  const std::vector<uint8_t> read_back = vault::read_file(path);
  CHECK(read_back == file);

  vault::Secrets opened;
  vault::unseal(read_back.data(), read_back.size(), pass, opened);
  CHECK(opened.identity_sk.equals(secrets.identity_sk));
}

TEST("write_file refuses to clobber an existing vault unless told to") {
  TempDir dir;
  const fs::path path = vault::vault_path(dir.path());

  vault::Secrets secrets;
  make_secrets(secrets);
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> first = vault::seal(secrets, pass, kFastParams);
  const std::vector<uint8_t> second = vault::seal(secrets, pass, kFastParams);

  vault::write_file(path, first, /*overwrite=*/false);
  CHECK_THROWS(vault::write_file(path, second, /*overwrite=*/false));
  CHECK(vault::read_file(path) == first);

  vault::write_file(path, second, /*overwrite=*/true);
  CHECK(vault::read_file(path) == second);
}

TEST("read_file rejects a missing or wrongly sized file") {
  TempDir dir;
  const fs::path path = vault::vault_path(dir.path());
  CHECK_THROWS(vault::read_file(path));

  std::ofstream out(path, std::ios::binary);
  out << "not a vault";
  out.close();
  CHECK_THROWS(vault::read_file(path));
}
