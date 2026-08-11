#include <set>
#include <string>

#include "ratchet/bip39.hpp"
#include "test_support.hpp"

using namespace ratchet;
using namespace ratchet::bip39;

namespace {

// SecureBytes is deliberately neither copyable nor movable, so test helpers
// fill a buffer the caller owns instead of returning one.
void from_hex(Entropy& out, const std::string& hex) {
  size_t written = 0;
  if (sodium_hex2bin(out.data(), out.size(), hex.c_str(), hex.size(), nullptr,
                     &written, nullptr) != 0 ||
      written != out.size()) {
    throw Error("bad test vector");
  }
}

std::string to_hex(const Entropy& e) {
  char buf[kEntropyBytes * 2 + 1];
  sodium_bin2hex(buf, sizeof buf, e.data(), e.size());
  return std::string(buf);
}

}  // namespace

TEST("wordlist has 2048 unique, sorted, lowercase words") {
  CHECK_EQ(kEnglishWordlist.size(), kWordlistSize);

  std::set<std::string_view> unique;
  for (size_t i = 0; i < kEnglishWordlist.size(); ++i) {
    const std::string_view word = kEnglishWordlist[i];
    CHECK(!word.empty());
    for (char c : word) {
      CHECK(c >= 'a' && c <= 'z');
    }
    if (i > 0) {
      CHECK(kEnglishWordlist[i - 1] < word);
    }
    unique.insert(word);
  }
  CHECK_EQ(unique.size(), kWordlistSize);

  // Spot-check the normative endpoints of the list.
  CHECK_EQ(std::string(kEnglishWordlist.front()), std::string("abandon"));
  CHECK_EQ(std::string(kEnglishWordlist.back()), std::string("zoo"));
}

TEST("word_index finds words and rejects non-words") {
  CHECK_EQ(word_index("abandon"), 0u);
  CHECK_EQ(word_index("zoo"), kWordlistSize - 1);
  CHECK_EQ(word_index("about"), 3u);
  CHECK_EQ(word_index("notaword"), kWordlistSize);
  CHECK_EQ(word_index(""), kWordlistSize);
  CHECK_EQ(word_index("ABANDON"), kWordlistSize);
}

TEST("encode matches the BIP-39 reference vectors") {
  struct Vector {
    const char* entropy;
    const char* mnemonic;
  };
  // From the BIP-0039 English test vectors.
  const Vector vectors[] = {
      {"00000000000000000000000000000000",
       "abandon abandon abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon about"},
      {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
       "legal winner thank year wave sausage worth useful legal winner thank "
       "yellow"},
      {"80808080808080808080808080808080",
       "letter advice cage absurd amount doctor acoustic avoid letter advice "
       "cage above"},
      {"ffffffffffffffffffffffffffffffff",
       "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
      {"9e885d952ad362caeb4efe34a8e91bd2",
       "ozone drill grab fiber curtain grace pudding thank cruise elder eight "
       "picnic"},
      {"c0ba5a8e914111210f2bd131f3d5e08d",
       "scheme spot photo card baby mountain device kick cradle pact join "
       "borrow"},
  };

  for (const Vector& v : vectors) {
    Entropy entropy;
    from_hex(entropy, v.entropy);
    CHECK_EQ(encode(entropy), std::string(v.mnemonic));
  }
}

TEST("decode is the inverse of encode on the reference vectors") {
  const char* hexes[] = {"00000000000000000000000000000000",
                         "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                         "80808080808080808080808080808080",
                         "ffffffffffffffffffffffffffffffff",
                         "9e885d952ad362caeb4efe34a8e91bd2"};
  for (const char* hex : hexes) {
    Entropy entropy;
    from_hex(entropy, hex);
    Entropy round_trip;
    decode(encode(entropy), round_trip);
    CHECK_EQ(to_hex(round_trip), std::string(hex));
  }
}

TEST("encode/decode round-trip on freshly generated entropy") {
  for (int i = 0; i < 64; ++i) {
    Entropy entropy;
    generate_entropy(entropy);

    const std::string mnemonic = encode(entropy);

    size_t spaces = 0;
    for (char c : mnemonic) {
      if (c == ' ') {
        ++spaces;
      }
    }
    CHECK_EQ(spaces, kWordCount - 1);

    Entropy decoded;
    decode(mnemonic, decoded);
    CHECK(decoded.equals(entropy));
  }
}

TEST("generate_entropy does not repeat itself") {
  std::set<std::string> seen;
  for (int i = 0; i < 32; ++i) {
    Entropy entropy;
    generate_entropy(entropy);
    // A repeat here means the RNG is not being seeded, which would be fatal.
    CHECK(seen.insert(to_hex(entropy)).second);
  }
}

TEST("decode tolerates irregular whitespace") {
  Entropy entropy;
  from_hex(entropy, "9e885d952ad362caeb4efe34a8e91bd2");
  Entropy decoded;
  decode("  ozone\tdrill  grab fiber\ncurtain grace pudding thank cruise "
         "elder eight picnic  ",
         decoded);
  CHECK(decoded.equals(entropy));
}

TEST("decode rejects a wrong word count") {
  Entropy out;
  CHECK_THROWS(decode("abandon abandon about", out));
  CHECK_THROWS(decode("", out));
  CHECK_THROWS(decode("abandon abandon abandon abandon abandon abandon "
                      "abandon abandon abandon abandon abandon abandon about",
                      out));
}

TEST("decode rejects a word outside the wordlist") {
  Entropy out;
  CHECK_THROWS(decode("banana abandon abandon abandon abandon abandon abandon "
                      "abandon abandon abandon abandon about",
                      out));
}

TEST("decode rejects a broken checksum") {
  Entropy out;
  // Valid words, valid count, but the last word carries the checksum and
  // "abandon" is not the right one for eleven leading "abandon"s.
  CHECK_THROWS(decode("abandon abandon abandon abandon abandon abandon abandon "
                      "abandon abandon abandon abandon abandon",
                      out));
  // A single mistyped word also has to be caught: this is the vector from the
  // encode test with its last word changed from "yellow" to "you".
  CHECK_THROWS(decode("legal winner thank year wave sausage worth useful legal "
                      "winner thank you",
                      out));
}
