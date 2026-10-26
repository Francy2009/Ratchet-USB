#ifndef RATCHET_GUI_FORMAT_HPP
#define RATCHET_GUI_FORMAT_HPP

#include <cstddef>
#include <ostream>
#include <string_view>

// The opt-in machine-readable result the desktop GUI asks the CLI for.
//
// The default CLI output is human text and stays exactly as it was. With
// --structured-output, `init` and `passphrase` emit this block instead of the
// human word grids. The block is small, has no dependency beyond the standard
// library, and carries nothing but the command, its status, whether init
// generated or restored the identity, and the generated word phrases.
//
// Why a separate format rather than parsing the headings: the human grid is a
// presentation detail. The GUI used to find "Vault passphrase" / "Recovery
// phrase" by name and collect numbered words with a regular expression, so a
// changed heading or a stray numbered line could silently produce a short
// phrase. This format names every field, states the expected word count, and
// makes a partial block an error rather than something to display.
//
// The phrases are BIP-39 English words: lowercase ASCII words separated by a
// single space. That restriction is deliberate -- it means the format needs no
// escaping and can be validated without allocating a copy of a secret. A
// passphrase is 6..12 words (see ratchet/passphrase.hpp); a recovery phrase is
// 12 words.
namespace ratchet::gui_format {

inline constexpr std::string_view kBegin =
    "-----BEGIN RATCHET GUI RESULT-----";
inline constexpr std::string_view kEnd = "-----END RATCHET GUI RESULT-----";
inline constexpr std::string_view kVersion = "1";

// Kept in sync with ratchet/passphrase.hpp by a static_assert in the .cpp; the
// GUI needs the numbers without linking ratchet_core.
inline constexpr std::size_t kMinPassphraseWords = 6;
inline constexpr std::size_t kMaxPassphraseWords = 12;
inline constexpr std::size_t kRecoveryWords = 12;

// True when `phrase` is exactly `expected_words` lowercase ASCII words
// separated by single spaces. Leading, trailing and repeated spaces are
// rejected. The length bound keeps a malformed stream from making the parser
// walk an unbounded string.
inline bool valid_phrase(std::string_view phrase,
                         std::size_t expected_words) noexcept {
  constexpr std::size_t kMaxPhraseBytes = 1024;
  if (expected_words == 0 || phrase.empty() ||
      phrase.size() > kMaxPhraseBytes) {
    return false;
  }
  std::size_t words = 0;
  std::size_t start = 0;
  for (;;) {
    const std::size_t space = phrase.find(' ', start);
    const std::size_t end = space == std::string_view::npos ? phrase.size()
                                                            : space;
    if (end == start) {
      return false;
    }
    for (std::size_t i = start; i < end; ++i) {
      const char c = phrase[i];
      if (c < 'a' || c > 'z') {
        return false;
      }
    }
    ++words;
    if (space == std::string_view::npos) {
      break;
    }
    start = space + 1;
  }
  return words == expected_words;
}

struct Result {
  std::string_view command;   // "init" or "passphrase"
  std::string_view status;    // "ok" or "cancelled"
  // init only: "generated" means `recovery` must be present; "mnemonic" means
  // the identity was restored from the words the user supplied and there is no
  // new recovery phrase to show. This field is what stops a missing recovery
  // phrase from being read as a successful restore.
  std::string_view source;
  std::string_view passphrase;  // empty only when status is "cancelled"
  std::size_t passphrase_words = 0;
  std::string_view recovery;  // init with source="generated"
  std::size_t recovery_words = 0;
};

// Writes one block and returns true, or returns false without writing anything
// when a field is invalid for the command/status. A stream failure can still
// leave a partial block; the reader must treat a block without its END marker
// (or with an invalid field) as an error.
bool write_result(std::ostream& os, const Result& result);

}  // namespace ratchet::gui_format

#endif  // RATCHET_GUI_FORMAT_HPP
