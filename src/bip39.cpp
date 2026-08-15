#include "ratchet/bip39.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>

namespace ratchet::bip39 {
namespace {

constexpr std::size_t kChecksumBits = kEntropyBytes * 8 / 32;  // 4
constexpr std::size_t kBitsPerWord = 11;

static_assert(kEntropyBytes * 8 + kChecksumBits == kWordCount * kBitsPerWord,
              "128 entropy bits + 4 checksum bits = 12 words of 11 bits");

// Reads the bit at `index` of a big-endian bit string.
bool bit_at(const uint8_t* data, std::size_t index) {
  return (data[index / 8] >> (7 - (index % 8))) & 1u;
}

std::vector<std::string_view> split_words(std::string_view text) {
  std::vector<std::string_view> words;
  std::size_t i = 0;
  while (i < text.size()) {
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) {
      ++i;
    }
    const std::size_t start = i;
    while (i < text.size() && !std::isspace(static_cast<unsigned char>(text[i]))) {
      ++i;
    }
    if (i > start) {
      words.push_back(text.substr(start, i - start));
    }
  }
  return words;
}

}  // namespace

std::size_t word_index(std::string_view word) {
  // The wordlist is sorted, so a binary search is enough and avoids building a
  // hash map at startup.
  const auto* it = std::lower_bound(kEnglishWordlist.begin(),
                                    kEnglishWordlist.end(), word);
  if (it == kEnglishWordlist.end() || *it != word) {
    return kWordlistSize;
  }
  return static_cast<std::size_t>(it - kEnglishWordlist.begin());
}

void generate_entropy(Entropy& out) {
  init_sodium();
  randombytes_buf(out.data(), out.size());
}

void encode(const Entropy& entropy, SecureString& out) {
  init_sodium();
  out.clear();

  // The checksum is the first 4 bits of SHA-256(entropy); appending it to the
  // entropy gives the 132 bits that split evenly into 12 eleven-bit indices.
  uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, entropy.data(), entropy.size());

  uint8_t bits[kEntropyBytes + 1];
  std::memcpy(bits, entropy.data(), kEntropyBytes);
  bits[kEntropyBytes] = digest[0];

  for (std::size_t w = 0; w < kWordCount; ++w) {
    std::size_t index = 0;
    for (std::size_t b = 0; b < kBitsPerWord; ++b) {
      index = (index << 1) | (bit_at(bits, w * kBitsPerWord + b) ? 1u : 0u);
    }
    if (w > 0) {
      out.push_back(' ');
    }
    // Character by character: appending the word as a block would go through
    // an intermediate the caller cannot wipe, which is the whole thing this
    // signature exists to avoid.
    for (const char c : kEnglishWordlist[index]) {
      out.push_back(c);
    }
  }

  sodium_memzero(bits, sizeof bits);
  sodium_memzero(digest, sizeof digest);
}

void decode(std::string_view mnemonic, Entropy& out) {
  init_sodium();

  const std::vector<std::string_view> words = split_words(mnemonic);
  if (words.size() != kWordCount) {
    throw Error("mnemonic must be exactly " + std::to_string(kWordCount) +
                " words, got " + std::to_string(words.size()));
  }

  uint8_t bits[kEntropyBytes + 1] = {0};
  std::size_t bit = 0;
  for (std::size_t w = 0; w < kWordCount; ++w) {
    const std::size_t index = word_index(words[w]);
    if (index == kWordlistSize) {
      // The offending word is not echoed back: it is part of a seed phrase and
      // has no business ending up in a log or a screenshot.
      throw Error("word " + std::to_string(w + 1) +
                  " is not in the BIP-39 English wordlist");
    }
    for (std::size_t b = 0; b < kBitsPerWord; ++b) {
      const bool value = (index >> (kBitsPerWord - 1 - b)) & 1u;
      if (value) {
        bits[bit / 8] |= static_cast<uint8_t>(1u << (7 - (bit % 8)));
      }
      ++bit;
    }
  }

  uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, bits, kEntropyBytes);

  // Compare only the 4 checksum bits, i.e. the high nibble of the trailing byte.
  const uint8_t expected = static_cast<uint8_t>(digest[0] & 0xF0u);
  const uint8_t actual = static_cast<uint8_t>(bits[kEntropyBytes] & 0xF0u);
  const bool checksum_ok = (expected == actual);

  if (checksum_ok) {
    out.assign(bits, kEntropyBytes);
  }

  sodium_memzero(bits, sizeof bits);
  sodium_memzero(digest, sizeof digest);

  if (!checksum_ok) {
    throw Error("mnemonic checksum does not match (a word is likely mistyped)");
  }
}

}  // namespace ratchet::bip39
