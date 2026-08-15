#ifndef RATCHET_BIP39_HPP
#define RATCHET_BIP39_HPP

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/secure.hpp"

namespace ratchet::bip39 {

inline constexpr std::size_t kWordlistSize = 2048;

// 128 bits of entropy -> 12 words. The rest of the code assumes this size;
// larger mnemonics are not supported on purpose (one format, one code path).
inline constexpr std::size_t kEntropyBytes = 16;
inline constexpr std::size_t kWordCount = 12;

using Entropy = SecureBytes<kEntropyBytes>;

// The official BIP-0039 English wordlist, in normative order.
extern const std::array<std::string_view, kWordlistSize> kEnglishWordlist;

// Fills `out` with 128 fresh bits from randombytes_buf.
void generate_entropy(Entropy& out);

// Encodes entropy as a 12-word mnemonic (words separated by single spaces),
// appending the BIP-39 checksum nibble.
//
// The result goes into a SecureString rather than being returned as a
// std::string, because the mnemonic *is* the master secret -- those twelve
// words rebuild the seed and the identity on their own. Returning it by value
// would put the one secret the whole project is built around into ordinary
// heap memory that is never wiped and can be paged out to swap, which is the
// treatment every other secret here is carefully spared.
void encode(const Entropy& entropy, SecureString& out);

// Parses a 12-word mnemonic back into entropy. Words may be separated by any
// run of whitespace. Throws Error on an unknown word, a wrong word count, or a
// failed checksum.
void decode(std::string_view mnemonic, Entropy& out);

// Index of `word` in the wordlist, or kWordlistSize if absent.
std::size_t word_index(std::string_view word);

}  // namespace ratchet::bip39

#endif  // RATCHET_BIP39_HPP
