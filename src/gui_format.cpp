#include "ratchet/gui_format.hpp"

#include <algorithm>
#include <cstdint>

#include "ratchet/passphrase.hpp"

namespace ratchet::gui_format {
namespace {

static_assert(kMinPassphraseWords == passphrase::kMinWords,
              "GUI format and passphrase generation disagree on the minimum");
static_assert(kMaxPassphraseWords == passphrase::kMaxWords,
              "GUI format and passphrase generation disagree on the maximum");

bool valid_status(std::string_view status) {
  return status == "ok" || status == "cancelled";
}

bool valid_command(std::string_view command) {
  return command == "init" || command == "passphrase";
}

// Everything is validated before the first byte is written, so an invalid
// result leaves no partial block behind. Only the stream itself can fail after
// that point.
bool valid_result(const Result& result) {
  if (!valid_command(result.command) || !valid_status(result.status)) {
    return false;
  }
  if (result.status == "cancelled") {
    return result.command == "passphrase" && result.source.empty() &&
           result.passphrase.empty() && result.passphrase_words == 0 &&
           result.recovery.empty() && result.recovery_words == 0;
  }

  if (result.passphrase_words < kMinPassphraseWords ||
      result.passphrase_words > kMaxPassphraseWords ||
      !valid_phrase(result.passphrase, result.passphrase_words)) {
    return false;
  }

  if (result.command == "passphrase") {
    return result.source.empty() && result.recovery.empty() &&
           result.recovery_words == 0;
  }

  // init: the source decides whether a recovery phrase must be present.
  if (result.source == "generated") {
    return result.recovery_words == kRecoveryWords &&
           valid_phrase(result.recovery, result.recovery_words);
  }
  if (result.source == "mnemonic") {
    return result.recovery.empty() && result.recovery_words == 0;
  }
  return false;
}

}  // namespace

bool write_result(std::ostream& os, const Result& result) {
  if (!os.good() || !valid_result(result)) {
    return false;
  }

  os << kBegin << '\n'
     << "version=" << kVersion << '\n'
     << "command=" << result.command << '\n'
     << "status=" << result.status << '\n';
  if (result.status == "ok") {
    if (result.command == "init") {
      os << "source=" << result.source << '\n';
    }
    os << "passphrase_words=" << result.passphrase_words << '\n'
       << "passphrase=" << result.passphrase << '\n';
    if (!result.recovery.empty()) {
      os << "recovery_words=" << result.recovery_words << '\n'
         << "recovery=" << result.recovery << '\n';
    }
  }
  os << kEnd << '\n';
  return os.good();
}

// --- recv --------------------------------------------------------------------

bool valid_extension(std::string_view ext) noexcept {
  constexpr std::size_t kMaxExt = 16;  // file::kMaxExtensionLength
  if (ext.empty() || ext.size() > kMaxExt) {
    return false;
  }
  for (const char c : ext) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
      return false;
    }
  }
  return true;
}

bool valid_staged_path(std::string_view path) noexcept {
  if (path.empty() || path.front() != '/') {
    return false;
  }
  if (path.size() > 4096) {
    return false;
  }
  // A staged name has no space in it (mkdtemp's template and this program's
  // prefix after it carry none), so refusing one rejects a hand-crafted value
  // without coming near a real path.
  if (path.find(' ') != std::string_view::npos) {
    return false;
  }
  if (!valid_extension(path.substr(path.rfind('.') == std::string_view::npos
                                       ? path.size()
                                       : path.rfind('.') + 1))) {
    return false;
  }
  for (const char c : path) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20 || byte == 0x7F) {
      return false;
    }
  }
  return true;
}

bool write_recv_result(std::ostream& os, const RecvResult& result) {
  const bool text = result.kind == kRecvText;
  const bool file = result.kind == kRecvFile;
  if (!os.good() || (!text && !file)) {
    return false;
  }
  if (text) {
    if (!result.ext.empty() || result.staged || !result.path.empty()) {
      return false;
    }
  } else {
    if (!valid_extension(result.ext)) {
      return false;
    }
    if (result.staged != !result.path.empty()) {
      return false;
    }
    if (result.staged && !valid_staged_path(result.path)) {
      return false;
    }
  }

  // A body that happens to contain the begin marker would be easy to mistake
  // for the block by a reader that took the first occurrence. The block is
  // written last, so the reader can simply take the last occurrence -- but an
  // unambiguous stream is cheaper to reason about than that contract, so the
  // body is escaped (see write_body_escaped) and the block names the mode so
  // the reader can put the text back.
  os << kBegin << '\n'
     << "version=" << kVersion << '\n'
     << "command=recv\n"
     << "kind=" << result.kind << '\n'
     << "marker=percent-hex" << '\n';
  if (file) {
    os << "ext=" << result.ext << '\n'
       << "staged=" << (result.staged ? "yes" : "no") << '\n';
    if (result.staged) {
      os << "path=" << result.path << '\n';
    }
  }
  os << kEnd << '\n';
  return os.good();
}

void write_body_escaped(std::ostream& os, std::string_view body) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::size_t i = 0;
  while (i < body.size()) {
    const bool is_begin =
        body.compare(i, kBegin.size(), kBegin) == 0;
    const bool is_end = body.compare(i, kEnd.size(), kEnd) == 0;
    if (is_begin || is_end) {
      // The escape character, then the marker's colon-hex spelling. The '%' is
      // what makes this reversible: without it, a message that already
      // contained the spelling would be indistinguishable from a marker.
      os.put('%');
      const std::size_t length = is_begin ? kBegin.size() : kEnd.size();
      for (std::size_t k = 0; k < length; ++k) {
        const auto byte = static_cast<unsigned char>(body[i + k]);
        if (k > 0) os.put(':');
        os.put(kHex[byte >> 4]);
        os.put(kHex[byte & 0x0F]);
      }
      i += length;
      continue;
    }
    if (body[i] == '%') {
      // The escape character itself, doubled so the reader does not take it
      // for the start of one.
      os << "%%";
      ++i;
      continue;
    }
    // Not a marker and not the escape here. Skip ahead in one pass to the next
    // byte that could start either -- '%' for the escape, '-' for the marker
    // framing. Two independent find() calls would rescan the whole remaining
    // body for the pattern that is absent, which is quadratic on a body of
    // millions of '%' or '-'.
    std::size_t next = body.find_first_of("%-", i + 1);
    if (next == std::string_view::npos) next = body.size();
    os.write(body.data() + i, static_cast<std::streamsize>(next - i));
    i = next;
  }
}

}  // namespace ratchet::gui_format
