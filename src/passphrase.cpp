#include "ratchet/passphrase.hpp"

#include <sodium.h>

#include "ratchet/bip39.hpp"

namespace ratchet::passphrase {

void generate(SecureString& out, std::size_t words) {
  init_sodium();
  if (words == 0 || words > kMaxWords) {
    throw Error("passphrase word count out of range");
  }
  out.clear();
  for (std::size_t i = 0; i < words; ++i) {
    // 2048 is a power of two, but randombytes_uniform() is used anyway: it is
    // the audited, bias-free way to map random bytes onto a range, and the cost
    // is irrelevant next to Argon2id.
    const std::size_t index =
        randombytes_uniform(static_cast<uint32_t>(bip39::kWordlistSize));
    if (i > 0) {
      out.push_back(' ');
    }
    // Character by character: appending the word as a block would go through
    // an intermediate the caller cannot wipe.
    for (const char c : bip39::kEnglishWordlist[index]) {
      out.push_back(c);
    }
  }
}

std::size_t word_count(const SecureString& phrase) {
  std::size_t count = 0;
  bool in_word = false;
  const char* data = phrase.data();
  for (std::size_t i = 0; i < phrase.size(); ++i) {
    const bool space = data[i] == ' ';
    if (space) {
      in_word = false;
    } else if (!in_word) {
      ++count;
      in_word = true;
    }
  }
  return count;
}

}  // namespace ratchet::passphrase
