#ifndef RATCHET_GUI_FORMAT_HPP
#define RATCHET_GUI_FORMAT_HPP

#include <cstddef>
#include <ostream>
#include <string>
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

// --- recv --------------------------------------------------------------------
//
// A received message has two outcomes: a text body, which is plaintext and is
// truncated and control-escaped before it is printed, and a framed file, whose
// presence the desktop GUI has to act on (it offers to open the folder the
// file was staged in). The GUI used to recognise the second by matching a
// pattern in the CLI's human stderr -- which begins with the sender's alias,
// a value the sender chose, so an alias spelling that pattern out opened the
// file dialog for a message that was not a file.
//
// `recv --structured-output` therefore ends its stdout with this block:
//
//     -----BEGIN RATCHET GUI RESULT-----
//     version=1
//     command=recv
//     kind=text|file
//     ext=<sanitised extension, file only>
//     staged=yes|no
//     path=<path, only when staged>
//     marker=hex-colon
//     ----------------------------------
//     -----END RATCHET GUI RESULT-----
//
// Every value on the right-hand side comes from this program, not from the
// message: the kind is what the framing byte said, the extension is the
// sanitised one decoded from the frame, and the path is what this process
// staged. The alias is deliberately not in the block. stdout carries the
// message body first (a GUI printing it to a terminal path still gets the text
// it always got), then the block, which begins on a line of its own and is the
// last thing written.
//
// The body is chosen by the sender, so it can contain the begin marker itself.
// Two things keep the two apart: the block is the *last* occurrence in stdout
// (the reader takes the last marker, not the first), and -- when the writer is
// used -- every literal occurrence in the body is written as its hex spelling
// (`-----BEGIN RATCHET GUI RESULT-----` becomes
// `2d2d2d2d2d424547494e...`), which `marker=hex-colon` announces so the reader
// can put it back. A stream where the marker occurs exactly once needs no
// disambiguation at all, which is why the field is optional for the parser but
// always written by this build.
inline constexpr std::string_view kRecvText = "text";
inline constexpr std::string_view kRecvFile = "file";
inline constexpr std::string_view kMarkerHexColon = "hex-colon";

struct RecvResult {
  std::string_view kind;        // kRecvText or kRecvFile
  std::string_view ext;         // file only, validated like a phrase below
  bool staged = false;          // the file was written to `path`
  // Owned, not a view. The path is produced by staging while the command runs
  // and read back when the block is written at the end of it; a view into the
  // local string would dangle by then, which is exactly what it did.
  std::string path;             // only meaningful when staged is true
};

// Writes `body` with every occurrence of the begin and end markers replaced by
// their hex spelling, so the only literal marker in the stream is the real
// block's. Nothing else is touched: NUL bytes, control characters and UTF-8
// pass through, which is what keeps the body the text that was received.
void write_body_without_markers(std::ostream& os, std::string_view body);

// True when `ext` is what a staged file name may carry: 1..16 characters of
// [a-z0-9], which is what file::decode_file_payload already sanitises to and
// what mkostemps embeds in the name.
bool valid_extension(std::string_view ext) noexcept;

// True when `path` is a plane absolute path with no byte that could end the
// line or start a control sequence: no space, no newline, no control byte, no
// escape. A staged name is "mkdtemp(" + the base + "/ratchet-file-XXXXXX." +
// ext, so anything else has not come from this program.
bool valid_staged_path(std::string_view path) noexcept;

// Writes the recv block, with the same all-or-nothing validation as
// write_result.
bool write_recv_result(std::ostream& os, const RecvResult& result);

}  // namespace ratchet::gui_format

#endif  // RATCHET_GUI_FORMAT_HPP
