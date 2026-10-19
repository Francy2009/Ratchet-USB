#ifndef RATCHET_PASSPHRASE_HPP
#define RATCHET_PASSPHRASE_HPP

#include <cstddef>

#include "ratchet/secure.hpp"

// Random word passphrases for the vault.
//
// A vault passphrase is generated, not chosen: the program draws the words,
// shows them once, and the user writes them down and types them back one per
// line to unlock. This is deliberately *not* a BIP-39 mnemonic. BIP-39 encodes
// a checksummed bit string in standard lengths (12, 15, 18, 21, 24 words); here
// the words are independent uniform samples and the result carries no checksum.
// The BIP-39 English wordlist is used only as a source of 2048 short, common,
// unambiguously spelled words. Calling a phrase like this "BIP-39" would be
// wrong, and confusing it with the 12-word *recovery* phrase is worse: the
// recovery phrase rebuilds the identity, while this passphrase only unlocks the
// vault and can never bring back contacts, prekeys or sessions.
//
// Entropy is exactly log2(2048) * words = 11 * words bits, because each word is
// drawn uniformly and independently:
//
//     words   entropy   note
//       5     55 bits   below the 64-bit floor usually asked of a generated
//                       secret; this is why five words are not the default
//       6     66 bits   the default: clears that floor, and is comparable to
//                       the classic "five diceware words" (5 * log2(7776) is
//                       about 64.6 bits) while staying short to write down
//       8     88 bits   comfortable margin, more to write down and to type
//
// More words trade typing for margin, and `--passphrase-words` exposes the
// range. Argon2id is what stands between a stolen vault and an offline guess,
// but it multiplies the cost of each guess rather than raising the entropy of
// the phrase, so the word count is the part that has to be chosen honestly.
namespace ratchet::passphrase {

inline constexpr std::size_t kBitsPerWord = 11;  // log2(2048)
inline constexpr std::size_t kDefaultWords = 6;
inline constexpr std::size_t kMinWords = 6;
inline constexpr std::size_t kMaxWords = 12;

// Entropy of a `words`-word phrase, in bits. Exact rather than estimated: the
// words are uniform, independent samples from a 2048-word list.
constexpr std::size_t entropy_bits(std::size_t words) noexcept {
  return words * kBitsPerWord;
}

// Fills `out` with `words` uniformly random words from the BIP-39 English
// wordlist, separated by single spaces. randombytes_uniform() is used so the
// index is unbiased. Throws Error for a count outside [1, kMaxWords].
void generate(SecureString& out, std::size_t words = kDefaultWords);

// Number of space-separated words in `phrase`.
std::size_t word_count(const SecureString& phrase);

}  // namespace ratchet::passphrase

#endif  // RATCHET_PASSPHRASE_HPP
