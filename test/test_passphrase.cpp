// The generated vault passphrase: how the words are drawn, how they are read
// back one per line, and how a passphrase change re-encrypts the vault without
// touching anything inside it.
//
// The passphrase is not the recovery phrase. The recovery phrase rebuilds the
// identity from 128 bits of mnemonic entropy; this is a separate, uniformly
// random word phrase whose only job is to key Argon2id. These tests pin the
// entropy claim, the word source, and the reader that turns typed lines back
// into the string Argon2id is given.

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fcntl.h>

#include <cstring>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/app.hpp"
#include "ratchet/bip39.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/passphrase.hpp"
#include "ratchet/store.hpp"
#include "ratchet/terminal.hpp"
#include "ratchet/vault.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
using namespace ratchet;

namespace {

constexpr vault::Params kFastParams{/*time_cost=*/vault::kMinTimeCost,
                                    /*mem_cost_kb=*/vault::kMinMemCostKb};

SecureString make_secure(std::string_view text) {
  SecureString s;
  for (char c : text) {
    s.push_back(c);
  }
  return s;
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
    path_ = fs::temp_directory_path() / ("ratchet-pass-" + std::string(suffix));
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

// Runs terminal::read_word_phrase in a child process with `input` on its stdin,
// and returns what it read. `refused` is set when the reader threw (empty
// input). A child is used because the reader consumes the process's stdin, and
// a test must not leave the runner's stdin pointing at a closed pipe.
std::string read_word_phrase_from(const std::string& input, bool* refused) {
  int in_pipe[2];
  int out_pipe[2];
  if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
    throw test::Failure("pipe() failed");
  }
  const pid_t pid = fork();
  if (pid < 0) {
    throw test::Failure("fork() failed");
  }
  if (pid == 0) {
    if (in_pipe[0] != STDIN_FILENO) {
      (void)dup2(in_pipe[0], STDIN_FILENO);
      close(in_pipe[0]);
    }
    close(in_pipe[1]);
    close(out_pipe[0]);
    const int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      (void)dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    try {
      SecureString phrase = terminal::read_word_phrase("");
      const char status = 'O';
      (void)write(out_pipe[1], &status, 1);
      (void)write(out_pipe[1], phrase.data(), phrase.size());
    } catch (const Error&) {
      const char status = 'E';
      (void)write(out_pipe[1], &status, 1);
    }
    close(out_pipe[1]);
    _exit(0);
  }
  close(in_pipe[0]);
  close(out_pipe[1]);
  std::size_t off = 0;
  while (off < input.size()) {
    const ssize_t n = write(in_pipe[1], input.data() + off, input.size() - off);
    if (n <= 0) {
      break;
    }
    off += static_cast<std::size_t>(n);
  }
  close(in_pipe[1]);

  std::string out;
  char buf[256];
  ssize_t n;
  while ((n = read(out_pipe[0], buf, sizeof buf)) > 0) {
    out.append(buf, static_cast<std::size_t>(n));
  }
  close(out_pipe[0]);
  int status = 0;
  (void)waitpid(pid, &status, 0);

  if (out.empty()) {
    *refused = true;
    return {};
  }
  *refused = (out.front() == 'E');
  out.erase(out.begin());
  return out;
}

// Runs terminal::confirm_enter_or_escape in a child with `input` on its stdin
// and returns what it decided.
bool confirm_from(const std::string& input) {
  int in_pipe[2];
  int out_pipe[2];
  if (pipe(in_pipe) != 0 || pipe(out_pipe) != 0) {
    throw test::Failure("pipe() failed");
  }
  const pid_t pid = fork();
  if (pid < 0) {
    throw test::Failure("fork() failed");
  }
  if (pid == 0) {
    if (in_pipe[0] != STDIN_FILENO) {
      (void)dup2(in_pipe[0], STDIN_FILENO);
      close(in_pipe[0]);
    }
    close(in_pipe[1]);
    close(out_pipe[0]);
    const int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      (void)dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    const char result = terminal::confirm_enter_or_escape("") ? '1' : '0';
    (void)write(out_pipe[1], &result, 1);
    close(out_pipe[1]);
    _exit(0);
  }
  close(in_pipe[0]);
  close(out_pipe[1]);
  std::size_t off = 0;
  while (off < input.size()) {
    const ssize_t n = write(in_pipe[1], input.data() + off, input.size() - off);
    if (n <= 0) {
      break;
    }
    off += static_cast<std::size_t>(n);
  }
  close(in_pipe[1]);

  char result = '0';
  (void)read(out_pipe[0], &result, 1);
  close(out_pipe[0]);
  int status = 0;
  (void)waitpid(pid, &status, 0);
  return result == '1';
}

// A vault store with a contact, a session and an accepted handshake, so a
// re-encryption has something of every kind to preserve.
store::VaultStore make_store() {
  store::VaultStore store;
  randombytes_buf(store.vault_id.data(), store.vault_id.size());
  store.generation = 7;
  randombytes_buf(store.seed.data(), store.seed.size());

  IdentitySigningSecretKey sk;
  IdentitySigningPublicKey pk;
  derive_identity(store.seed, sk, pk);

  store::Contact contact;
  contact.alias = "alice";
  contact.identity_pub = pk;
  contact.verified = true;
  store.contacts.push_back(std::move(contact));

  store::Session session;
  session.contact_index = 0;
  session.status = store::Session::Status::Pending;
  randombytes_buf(session.session_id.data(), session.session_id.size());
  randombytes_buf(session.root_key.data(), session.root_key.size());
  session.has_cks = true;
  randombytes_buf(session.chain_key_send.data(), session.chain_key_send.size());
  session.ns = 3;
  store.sessions.push_back(std::move(session));

  store::AcceptedHandshake handshake;
  handshake.initiator_identity = pk;
  randombytes_buf(handshake.ephemeral_pub.data(), handshake.ephemeral_pub.size());
  handshake.accepted_at = 1234;
  store.accepted_handshakes.push_back(handshake);

  return store;
}

// Writes `store` to vault.bin under `passphrase` and returns the path.
fs::path write_vault(const fs::path& dir, store::VaultStore& store,
                     std::string_view passphrase) {
  const fs::path path = dir / vault::kVaultFilename;
  const SecureBuffer plaintext = store::serialize(store);
  const std::vector<uint8_t> file =
      vault::seal(plaintext, make_secure(passphrase), kFastParams);
  vault::write_file(path, file, /*overwrite=*/false);
  return path;
}

}  // namespace

// --- entropy and word source -------------------------------------------------

TEST("passphrase: entropy is 11 bits per word and five is below the floor") {
  CHECK_EQ(passphrase::kBitsPerWord, static_cast<std::size_t>(11));
  CHECK_EQ(passphrase::entropy_bits(5), static_cast<std::size_t>(55));
  CHECK_EQ(passphrase::entropy_bits(6), static_cast<std::size_t>(66));
  CHECK_EQ(passphrase::entropy_bits(8), static_cast<std::size_t>(88));
  // The default and the floor are both at least six: five words is 55 bits,
  // under the 64-bit floor usually asked of a generated secret.
  CHECK(passphrase::kMinWords >= 6);
  CHECK(passphrase::kDefaultWords >= passphrase::kMinWords);
}

TEST("passphrase: generated words have the requested count and come from the list") {
  for (const std::size_t words :
       {std::size_t{6}, std::size_t{8}, std::size_t{12}}) {
    SecureString phrase;
    passphrase::generate(phrase, words);
    CHECK_EQ(passphrase::word_count(phrase), words);

    const std::string_view all(phrase.data(), phrase.size());
    std::size_t start = 0;
    for (std::size_t i = 0; i <= all.size(); ++i) {
      if (i == all.size() || all[i] == ' ') {
        const std::string_view word = all.substr(start, i - start);
        CHECK(!word.empty());
        CHECK(bip39::word_index(word) != bip39::kWordlistSize);
        start = i + 1;
      }
    }
  }
}

TEST("passphrase: two draws do not repeat") {
  std::set<std::string> seen;
  for (int i = 0; i < 64; ++i) {
    SecureString phrase;
    passphrase::generate(phrase, passphrase::kDefaultWords);
    CHECK(seen.insert(std::string(phrase.data(), phrase.size())).second);
  }
}

TEST("passphrase: a zero or oversized word count is refused") {
  SecureString phrase;
  CHECK_THROWS(passphrase::generate(phrase, 0));
  CHECK_THROWS(passphrase::generate(phrase, passphrase::kMaxWords + 1));
}

TEST("passphrase: word_count counts space-separated words") {
  CHECK_EQ(passphrase::word_count(make_secure("a b c")), static_cast<std::size_t>(3));
  CHECK_EQ(passphrase::word_count(make_secure("solo")), static_cast<std::size_t>(1));
  CHECK_EQ(passphrase::word_count(make_secure("  a   b  ")),
           static_cast<std::size_t>(2));
  CHECK_EQ(passphrase::word_count(make_secure("")), static_cast<std::size_t>(0));
}

// --- reading one word per line -----------------------------------------------

TEST("read_word_phrase: lines are joined with single spaces") {
  bool refused = false;
  const std::string phrase =
      read_word_phrase_from("wild\nregion\nmind\n", &refused);
  CHECK(!refused);
  CHECK_EQ(phrase, std::string("wild region mind"));
}

TEST("read_word_phrase: an empty line ends the passphrase") {
  bool refused = false;
  // A blank line terminates: whatever follows is not part of the passphrase.
  CHECK_EQ(read_word_phrase_from("a\nb\n\nc\n", &refused), std::string("a b"));
  CHECK(!refused);
  // A missing final newline still ends at end of input.
  CHECK_EQ(read_word_phrase_from("a\nb", &refused), std::string("a b"));
  CHECK(!refused);
  // A legacy single-line passphrase plus the confirming empty line.
  CHECK_EQ(read_word_phrase_from("hunter2\n\n", &refused), std::string("hunter2"));
  CHECK(!refused);
}

TEST("read_word_phrase: a legacy single-line passphrase is preserved") {
  bool refused = false;
  const std::string phrase =
      read_word_phrase_from("correct horse battery staple\n", &refused);
  CHECK(!refused);
  CHECK_EQ(phrase, std::string("correct horse battery staple"));
}

TEST("read_word_phrase: empty input is refused") {
  bool refused = false;
  (void)read_word_phrase_from("", &refused);
  CHECK(refused);
}

TEST("read_word_phrase: a generated phrase round-trips word by word") {
  SecureString phrase;
  passphrase::generate(phrase, passphrase::kDefaultWords);

  const std::string_view all(phrase.data(), phrase.size());
  std::string input;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= all.size(); ++i) {
    if (i == all.size() || all[i] == ' ') {
      input.append(all.substr(start, i - start));
      input.push_back('\n');
      start = i + 1;
    }
  }

  bool refused = false;
  const std::string read = read_word_phrase_from(input, &refused);
  CHECK(!refused);
  CHECK_EQ(read, std::string(phrase.data(), phrase.size()));
}

TEST("confirm_enter_or_escape: Enter confirms, Esc cancels, EOF cancels") {
  CHECK(confirm_from("\n"));
  CHECK(confirm_from("\r"));
  CHECK(!confirm_from("\x1b"));
  CHECK(!confirm_from(""));
  // Any other key followed by Enter still confirms.
  CHECK(confirm_from("y\n"));
}

// --- changing the passphrase -------------------------------------------------

TEST("rekey: the same vault is preserved under a new passphrase") {
  TempDir dir;
  store::VaultStore store = make_store();
  const fs::path path = write_vault(dir.path(), store, "old phrase words here");

  uint64_t generation_before = 0;
  SecureBuffer before;
  {
    app::OpenedVault opened = app::open_vault(app::read_vault(path),
                                              make_secure("old phrase words here"));
    generation_before = opened.store.generation;
    before = store::serialize(opened.store);

    app::rekey_vault(path, opened.store, kFastParams,
                     make_secure("brand new phrase drawn fresh"));
    CHECK_EQ(opened.store.generation, generation_before + 1);
  }

  // The new passphrase opens the vault; everything but the generation counter
  // is byte-for-byte what it was, contacts and sessions included.
  {
    const std::vector<uint8_t> bytes = vault::read_file(path);
    CHECK_EQ(vault::parse_header(bytes.data(), bytes.size()).version,
             vault::kWordVersion);
    app::OpenedVault reopened = app::open_vault(
        app::read_vault(path), make_secure("brand new phrase drawn fresh"));
    reopened.store.generation = generation_before;
    const SecureBuffer after = store::serialize(reopened.store);
    CHECK(buffers_equal(before, after));
    CHECK_EQ(reopened.store.contacts.size(), static_cast<std::size_t>(1));
    CHECK_EQ(reopened.store.sessions.size(), static_cast<std::size_t>(1));
  }

  // The old passphrase no longer opens it.
  CHECK_THROWS(app::open_vault(app::read_vault(path),
                               make_secure("old phrase words here")));
}

TEST("rekey: a failure before promotion leaves the original vault untouched") {
  TempDir dir;
  store::VaultStore store = make_store();
  const fs::path path = write_vault(dir.path(), store, "old phrase words here");
  const std::vector<uint8_t> original = vault::read_file(path);

  // A directory where the prepared file would go makes the write fail after the
  // store has been prepared but before anything is promoted over vault.bin.
  CHECK(fs::create_directory(dir.path() / vault::kRekeyPreparedFilename));
  {
    app::OpenedVault opened = app::open_vault(app::read_vault(path),
                                              make_secure("old phrase words here"));
    CHECK_THROWS(app::rekey_vault(path, opened.store, kFastParams,
                                  make_secure("brand new phrase drawn fresh")));
  }

  // The original container is bit-for-bit unchanged and still opens.
  CHECK(vault::read_file(path) == original);
  app::OpenedVault still = app::open_vault(app::read_vault(path),
                                           make_secure("old phrase words here"));
  CHECK_EQ(still.store.contacts.size(), static_cast<std::size_t>(1));
}

TEST("rekey: an empty new passphrase is refused") {
  TempDir dir;
  store::VaultStore store = make_store();
  const fs::path path = write_vault(dir.path(), store, "old phrase words here");

  app::OpenedVault opened = app::open_vault(app::read_vault(path),
                                            make_secure("old phrase words here"));
  CHECK_THROWS(app::rekey_vault(path, opened.store, kFastParams, make_secure("")));
}
