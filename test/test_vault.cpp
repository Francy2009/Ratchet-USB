#include <sys/stat.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

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

SecureBuffer make_plaintext(std::string_view text) {
  SecureBuffer b;
  b.append(reinterpret_cast<const uint8_t*>(text.data()), text.size());
  return b;
}

bool buffers_equal(const SecureBuffer& a, const SecureBuffer& b) {
  return a.size() == b.size() &&
        (a.size() == 0 || std::memcmp(a.data(), b.data(), a.size()) == 0);
}

class TempDir {
 public:
  TempDir() {
    char suffix[17];
    randombytes_buf(suffix, sizeof suffix - 1);
    for (size_t i = 0; i + 1 < sizeof suffix; ++i) {
      suffix[i] =
          static_cast<char>('a' + (static_cast<unsigned char>(suffix[i]) % 26));
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
  const SecureBuffer plaintext = make_plaintext("hello vault");
  const SecureString pass = make_pass("correct horse battery staple");
  const std::vector<uint8_t> file = vault::seal(plaintext, pass, kFastParams);

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

TEST("seal/unseal round-trip recovers arbitrary-length plaintext") {
  const std::string long_text(5000, 'z');
  const std::string_view cases[] = {"", "x", "a fairly ordinary short message",
                                    long_text};
  for (std::string_view text : cases) {
    const SecureBuffer plaintext = make_plaintext(text);
    const SecureString pass = make_pass("un passphrase abbastanza lunga 42");

    const std::vector<uint8_t> file = vault::seal(plaintext, pass, kFastParams);
    CHECK_EQ(file.size(), vault::kHeaderBytes + text.size() + vault::kTagBytes);

    SecureBuffer opened;
    vault::unseal(file.data(), file.size(), pass, opened);
    CHECK(buffers_equal(opened, plaintext));
  }
}

TEST("the plaintext never appears in the vault file") {
  const std::string secret_marker = "THIS-MUST-NOT-LEAK-1234567890";
  const SecureBuffer plaintext = make_plaintext(secret_marker);
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> file = vault::seal(plaintext, pass, kFastParams);

  for (size_t i = 0; i + secret_marker.size() <= file.size(); ++i) {
    CHECK(std::memcmp(file.data() + i, secret_marker.data(),
                      secret_marker.size()) != 0);
  }
}

TEST("sealing the same plaintext twice produces different bytes") {
  const SecureBuffer plaintext = make_plaintext("same content, sealed twice");
  const SecureString pass = make_pass("passphrase");

  const std::vector<uint8_t> a = vault::seal(plaintext, pass, kFastParams);
  const std::vector<uint8_t> b = vault::seal(plaintext, pass, kFastParams);
  CHECK(a != b);

  SecureBuffer from_a;
  SecureBuffer from_b;
  vault::unseal(a.data(), a.size(), pass, from_a);
  vault::unseal(b.data(), b.size(), pass, from_b);
  CHECK(buffers_equal(from_a, from_b));
}

TEST("a wrong passphrase does not open the vault") {
  const SecureBuffer plaintext = make_plaintext("payload");
  const std::vector<uint8_t> file =
      vault::seal(plaintext, make_pass("right passphrase"), kFastParams);

  SecureBuffer out;
  CHECK_THROWS(
      vault::unseal(file.data(), file.size(), make_pass("wrong passphrase"), out));
  CHECK_THROWS(
      vault::unseal(file.data(), file.size(), make_pass("right passphras"), out));
  CHECK_THROWS(
      vault::unseal(file.data(), file.size(), make_pass("Right passphrase"), out));
}

TEST("an empty passphrase is refused") {
  const SecureBuffer plaintext = make_plaintext("payload");
  CHECK_THROWS(vault::seal(plaintext, make_pass(""), kFastParams));
}

TEST("tampering with any byte of the file is detected") {
  const SecureBuffer plaintext = make_plaintext("a message worth protecting");
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> file = vault::seal(plaintext, pass, kFastParams);

  // The header is authenticated as additional data, so flipping a bit in the
  // salt, in the cost parameters or in the nonce has to fail just like
  // flipping one in the ciphertext or in the tag.
  for (size_t i = 4; i < file.size(); ++i) {
    std::vector<uint8_t> broken = file;
    broken[i] ^= 0x01;
    SecureBuffer out;
    CHECK_THROWS(vault::unseal(broken.data(), broken.size(), pass, out));
  }
}

TEST("truncated or padded vault files are refused") {
  const SecureBuffer plaintext = make_plaintext("payload");
  const SecureString pass = make_pass("passphrase");
  std::vector<uint8_t> file = vault::seal(plaintext, pass, kFastParams);

  SecureBuffer out;
  std::vector<uint8_t> short_file(file.begin(), file.end() - 1);
  CHECK_THROWS(vault::unseal(short_file.data(), short_file.size(), pass, out));

  std::vector<uint8_t> long_file = file;
  long_file.push_back(0);
  CHECK_THROWS(vault::unseal(long_file.data(), long_file.size(), pass, out));
}

TEST("seal rejects out-of-range Argon2 parameters") {
  const SecureBuffer plaintext = make_plaintext("payload");
  const SecureString pass = make_pass("passphrase");

  CHECK_THROWS(vault::seal(plaintext, pass, vault::Params{0, 8}));
  CHECK_THROWS(vault::seal(plaintext, pass, vault::Params{1, 4}));
  CHECK_THROWS(
      vault::seal(plaintext, pass, vault::Params{1, vault::kMaxMemCostKb + 1}));
  CHECK_THROWS(
      vault::seal(plaintext, pass, vault::Params{vault::kMaxTimeCost + 1, 8}));
}

TEST("write_file creates a 0600 file and read_file returns it unchanged") {
  TempDir dir;
  const fs::path path = vault::vault_path(dir.path());
  CHECK_EQ(path.filename().string(), std::string("vault.bin"));

  const SecureBuffer plaintext = make_plaintext("payload");
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> file = vault::seal(plaintext, pass, kFastParams);

  vault::write_file(path, file, /*overwrite=*/false);
  CHECK(fs::exists(path));

  struct stat st {};
  CHECK_EQ(::stat(path.c_str(), &st), 0);
  CHECK_EQ(st.st_mode & 0777u, 0600u);

  CHECK(!fs::exists(path.string() + ".tmp"));

  const std::vector<uint8_t> read_back = vault::read_file(path);
  CHECK(read_back == file);

  SecureBuffer opened;
  vault::unseal(read_back.data(), read_back.size(), pass, opened);
  CHECK(buffers_equal(opened, plaintext));
}

TEST("write_file refuses to clobber an existing vault unless told to") {
  TempDir dir;
  const fs::path path = vault::vault_path(dir.path());

  const SecureBuffer plaintext = make_plaintext("payload");
  const SecureString pass = make_pass("passphrase");
  const std::vector<uint8_t> first = vault::seal(plaintext, pass, kFastParams);
  const std::vector<uint8_t> second = vault::seal(plaintext, pass, kFastParams);

  vault::write_file(path, first, /*overwrite=*/false);
  CHECK_THROWS(vault::write_file(path, second, /*overwrite=*/false));
  CHECK(vault::read_file(path) == first);

  vault::write_file(path, second, /*overwrite=*/true);
  CHECK(vault::read_file(path) == second);
}

TEST("read_file rejects a missing or too-short file") {
  TempDir dir;
  const fs::path path = vault::vault_path(dir.path());
  CHECK_THROWS(vault::read_file(path));

  std::ofstream out(path, std::ios::binary);
  out << "short";
  out.close();
  CHECK_THROWS(vault::read_file(path));
}
