#include "ratchet/screen.hpp"

#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

namespace ratchet::screen {
namespace {

// The whole vocabulary of escape sequences this file emits. Written out here
// so the list can be read in one go and checked against what the header
// promises never to send.
constexpr std::string_view kAltScreenOn = "\033[?1049h";
constexpr std::string_view kAltScreenOff = "\033[?1049l";
constexpr std::string_view kCursorHide = "\033[?25l";
constexpr std::string_view kCursorShow = "\033[?25h";
constexpr std::string_view kBracketedPasteOn = "\033[?2004h";
constexpr std::string_view kBracketedPasteOff = "\033[?2004l";
constexpr std::string_view kHome = "\033[H";
constexpr std::string_view kEraseLine = "\033[2K";
constexpr std::string_view kEraseBelow = "\033[J";
constexpr std::string_view kReverseOn = "\033[7m";
constexpr std::string_view kReverseOff = "\033[27m";

// Whether `byte` continues a UTF-8 sequence rather than starting one.
bool is_continuation(unsigned char byte) { return (byte & 0xC0) == 0x80; }

// How many bytes the UTF-8 sequence starting with `lead` occupies, or 0 if
// `lead` cannot start one.
std::size_t sequence_length(unsigned char lead) {
  if (lead < 0x80) return 1;
  if ((lead & 0xE0) == 0xC0) return 2;
  if ((lead & 0xF0) == 0xE0) return 3;
  if ((lead & 0xF8) == 0xF0) return 4;
  return 0;
}

// Maps a CSI or SS3 sequence -- its parameter bytes and its final byte -- onto
// a key. Anything unrecognised is KeyCode::None, which the caller consumes and
// ignores.
KeyCode csi_to_key(std::string_view params, char final_byte) {
  if (params.empty()) {
    switch (final_byte) {
      case 'A': return KeyCode::Up;
      case 'B': return KeyCode::Down;
      case 'C': return KeyCode::Right;
      case 'D': return KeyCode::Left;
      case 'H': return KeyCode::Home;
      case 'F': return KeyCode::End;
      default: return KeyCode::None;
    }
  }
  if (final_byte == '~') {
    if (params == "1" || params == "7") return KeyCode::Home;
    if (params == "3") return KeyCode::Delete;
    if (params == "4" || params == "8") return KeyCode::End;
    if (params == "5") return KeyCode::PageUp;
    if (params == "6") return KeyCode::PageDown;
    if (params == "200") return KeyCode::PasteBegin;
    if (params == "201") return KeyCode::PasteEnd;
  }
  return KeyCode::None;
}

// Decodes ESC-prefixed input. `in` starts at the ESC. Returns bytes consumed,
// or 0 when the sequence is still incomplete and flush is false.
std::size_t decode_escape(std::string_view in, bool flush, Key& out) {
  if (in.size() == 1) {
    if (!flush) {
      return 0;  // might still grow into an arrow key
    }
    out.code = KeyCode::Escape;
    return 1;
  }

  const char introducer = in[1];
  if (introducer != '[' && introducer != 'O') {
    // ESC followed by anything else -- Alt+key on most terminals. Not a key
    // this interface uses, so both bytes go in the bin.
    out.code = KeyCode::None;
    return 2;
  }

  std::size_t i = 2;
  const std::size_t limit = in.size() < kMaxEscapeSequence ? in.size()
                                                           : kMaxEscapeSequence;
  while (i < limit) {
    const auto byte = static_cast<unsigned char>(in[i]);
    // Parameter and intermediate bytes run 0x20-0x3F; the sequence ends at the
    // first byte in 0x40-0x7E.
    if (byte >= 0x40 && byte <= 0x7E) {
      out.code = csi_to_key(in.substr(2, i - 2), in[i]);
      return i + 1;
    }
    if (byte < 0x20 || byte > 0x3F) {
      // Not part of a control sequence at all: a truncated one, most likely.
      // Drop what we have rather than swallowing the bytes that follow.
      out.code = KeyCode::None;
      return i;
    }
    ++i;
  }

  if (i >= kMaxEscapeSequence) {
    // Longer than any real key. Consume the cap so a stream of parameter bytes
    // cannot stall the decoder, and ignore it.
    out.code = KeyCode::None;
    return kMaxEscapeSequence;
  }
  if (flush) {
    out.code = KeyCode::None;
    return in.size();
  }
  return 0;  // incomplete, and more may still arrive
}

}  // namespace

std::string sanitize_line(std::string_view text) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    const auto byte = static_cast<unsigned char>(ch);
    // 0x80-0x9F are left alone for the same reason terminal.cpp leaves them
    // alone: in UTF-8 they are continuation bytes, and escaping them would
    // mangle every alias that is not pure ASCII.
    if (byte < 0x20 || byte == 0x7F) {
      out += "\\x";
      out.push_back(kHex[byte >> 4]);
      out.push_back(kHex[byte & 0x0F]);
    } else {
      out.push_back(ch);
    }
  }
  return out;
}

std::size_t display_width(std::string_view text) {
  std::size_t width = 0;
  for (const char ch : text) {
    if (!is_continuation(static_cast<unsigned char>(ch))) {
      ++width;
    }
  }
  return width;
}

std::string truncate_to_width(std::string_view text, std::size_t max_width) {
  if (display_width(text) <= max_width) {
    return std::string(text);
  }
  static constexpr std::string_view kEllipsis = "...";
  // ASCII rather than U+2026, so the marker is one column per byte on a
  // terminal that is not reading this as UTF-8.
  if (max_width <= kEllipsis.size()) {
    return std::string(kEllipsis.substr(0, max_width));
  }

  const std::size_t keep = max_width - kEllipsis.size();
  std::size_t width = 0;
  std::size_t bytes = 0;
  while (bytes < text.size()) {
    if (!is_continuation(static_cast<unsigned char>(text[bytes]))) {
      if (width == keep) {
        break;
      }
      ++width;
    }
    ++bytes;
  }
  std::string out(text.substr(0, bytes));
  out += kEllipsis;
  return out;
}

std::vector<std::string> wrap_text(std::string_view text, std::size_t width) {
  std::vector<std::string> out;
  if (width == 0) {
    return out;
  }

  std::string line;
  std::size_t line_width = 0;
  std::size_t last_space = std::string::npos;  // byte offset within `line`

  auto flush_line = [&](std::size_t keep_bytes) {
    out.push_back(line.substr(0, keep_bytes));
    std::string rest = line.substr(keep_bytes);
    // The space the break happened at is not carried onto the next line.
    while (!rest.empty() && rest.front() == ' ') {
      rest.erase(rest.begin());
    }
    line = std::move(rest);
    line_width = display_width(line);
    last_space = std::string::npos;
  };

  std::size_t i = 0;
  while (i < text.size()) {
    const auto lead = static_cast<unsigned char>(text[i]);
    if (lead == '\n') {
      out.push_back(line);
      line.clear();
      line_width = 0;
      last_space = std::string::npos;
      ++i;
      continue;
    }

    std::size_t step = sequence_length(lead);
    if (step == 0 || i + step > text.size()) {
      step = 1;  // malformed; take the byte and carry on
    }
    if (lead == ' ') {
      last_space = line.size();
    }
    line.append(text, i, step);
    ++line_width;
    i += step;

    if (line_width > width) {
      if (last_space != std::string::npos && last_space > 0) {
        flush_line(last_space);
      } else {
        // No space to break at: drop the character that overflowed onto the
        // next line, which keeps the cut on a UTF-8 boundary.
        flush_line(line.size() - step);
      }
    }
  }
  out.push_back(line);
  return out;
}

std::size_t decode_key(std::string_view in, bool flush, Key& out) {
  out.code = KeyCode::None;
  out.text.clear();
  if (in.empty()) {
    return 0;
  }

  const auto lead = static_cast<unsigned char>(in[0]);

  if (lead == 0x1B) {
    return decode_escape(in, flush, out);
  }

  switch (lead) {
    case '\r':
    case '\n':
      out.code = KeyCode::Enter;
      return 1;
    case '\t':
      out.code = KeyCode::Tab;
      return 1;
    case 0x7F:
    case 0x08:
      out.code = KeyCode::Backspace;
      return 1;
    case 0x03:
      out.code = KeyCode::CtrlC;
      return 1;
    case 0x04:
      out.code = KeyCode::CtrlD;
      return 1;
    case 0x0C:
      out.code = KeyCode::CtrlL;
      return 1;
    case 0x15:
      out.code = KeyCode::CtrlU;
      return 1;
    case 0x17:
      out.code = KeyCode::CtrlW;
      return 1;
    default:
      break;
  }

  if (lead < 0x20) {
    // Some other control byte. Not a key here, and never text.
    out.code = KeyCode::None;
    return 1;
  }

  const std::size_t needed = sequence_length(lead);
  if (needed == 0) {
    // A continuation byte with no lead, or a byte no UTF-8 encoder produces.
    out.code = KeyCode::None;
    return 1;
  }
  if (in.size() < needed) {
    if (!flush) {
      return 0;
    }
    out.code = KeyCode::None;
    return in.size();
  }
  for (std::size_t i = 1; i < needed; ++i) {
    if (!is_continuation(static_cast<unsigned char>(in[i]))) {
      // Malformed: the sequence is shorter than its lead byte claimed. Consume
      // just the lead so the bytes that follow get their own chance.
      out.code = KeyCode::None;
      return 1;
    }
  }

  out.code = KeyCode::Char;
  out.text.assign(in.substr(0, needed));
  return needed;
}

// --- Frame ------------------------------------------------------------------

Frame::Frame(std::size_t width, std::size_t height)
    : width_(width), height_(height) {}

void Frame::clear() {
  lines_.clear();
  highlighted_.clear();
  cursor_row_ = 0;
  cursor_col_ = 0;
}

void Frame::line(std::string_view text) {
  if (lines_.size() >= height_) {
    return;
  }
  lines_.push_back(truncate_to_width(sanitize_line(text), width_));
  highlighted_.push_back(false);
}

void Frame::highlight(std::string_view text) {
  if (lines_.size() >= height_) {
    return;
  }
  lines_.push_back(truncate_to_width(sanitize_line(text), width_));
  highlighted_.push_back(true);
}

void Frame::cursor(std::size_t row, std::size_t col) {
  cursor_row_ = row;
  cursor_col_ = col;
}

std::string Frame::render() const {
  std::string out;
  out.reserve((width_ + 8) * lines_.size() + 32);
  out += kHome;
  for (std::size_t i = 0; i < lines_.size(); ++i) {
    out += kEraseLine;
    if (highlighted_[i]) {
      out += kReverseOn;
      out += lines_[i];
      out += kReverseOff;
    } else {
      out += lines_[i];
    }
    if (i + 1 < lines_.size()) {
      out += "\n";
    }
  }
  out += "\n";
  out += kEraseBelow;
  if (cursor_row_ > 0 && cursor_col_ > 0) {
    out += "\033[";
    out += std::to_string(cursor_row_);
    out += ";";
    out += std::to_string(cursor_col_);
    out += "H";
    out += kCursorShow;
  } else {
    out += kCursorHide;
  }
  return out;
}

// --- terminal state ---------------------------------------------------------

bool usable() {
  if (isatty(STDIN_FILENO) == 0 || isatty(STDOUT_FILENO) == 0) {
    return false;
  }
  const char* term = std::getenv("TERM");
  if (term == nullptr || term[0] == '\0') {
    return false;
  }
  // The one thing TERM is used for: telling a terminal that cannot move a
  // cursor apart from one that can. It is compared, never parsed, and no
  // terminfo entry is looked up.
  return std::strcmp(term, "dumb") != 0;
}

Size size() {
  Size result;
  struct winsize ws {};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 &&
      ws.ws_row > 0) {
    result.width = ws.ws_col;
    result.height = ws.ws_row;
  }
  return result;
}

RawMode::RawMode() {
  if (tcgetattr(STDIN_FILENO, &saved_) != 0) {
    return;
  }
  struct termios raw = saved_;
  // No echo (a passphrase must not appear), no line discipline (keys arrive as
  // they are pressed), no signals from Ctrl-C (see the header), no flow
  // control from Ctrl-S, and no CR-to-LF rewriting on the way in.
  raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON | ISIG | IEXTEN));
  raw.c_iflag &= static_cast<tcflag_t>(~(IXON | ICRNL | INLCR | IGNCR | BRKINT |
                                         ISTRIP));
  // Output processing stays on, so a "\n" in a frame still returns the cursor
  // to the first column.
  raw.c_cc[VMIN] = 0;
  raw.c_cc[VTIME] = 0;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0) {
    active_ = true;
  }
}

RawMode::~RawMode() {
  if (active_) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_);
  }
}

void set_bracketed_paste(bool on) {
  write_all(on ? kBracketedPasteOn : kBracketedPasteOff);
}

AltScreen::AltScreen() {
  write_all(kAltScreenOn);
  write_all(kCursorHide);
  write_all(kBracketedPasteOn);
}

AltScreen::~AltScreen() {
  write_all(kBracketedPasteOff);
  write_all(kCursorShow);
  write_all(kAltScreenOff);
}

bool write_all(std::string_view text) {
  const char* data = text.data();
  std::size_t left = text.size();
  while (left > 0) {
    const ssize_t written = ::write(STDOUT_FILENO, data, left);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    data += written;
    left -= static_cast<std::size_t>(written);
  }
  return true;
}

bool read_available(std::string& buffer, int timeout_ms) {
  struct pollfd pfd {};
  pfd.fd = STDIN_FILENO;
  pfd.events = POLLIN;

  const int ready = ::poll(&pfd, 1, timeout_ms);
  if (ready < 0) {
    return errno == EINTR;  // a signal, not the end of input
  }
  if (ready == 0) {
    return true;  // nothing to read yet, which is not a failure
  }

  char chunk[512];
  const ssize_t got = ::read(STDIN_FILENO, chunk, sizeof chunk);
  if (got < 0) {
    return errno == EINTR || errno == EAGAIN;
  }
  if (got == 0) {
    return false;  // stdin closed
  }
  buffer.append(chunk, static_cast<std::size_t>(got));
  return true;
}

void emergency_restore() noexcept {
  // Signal-handler context: only async-signal-safe calls. Nothing here tries
  // to wipe memory -- almost nothing that could is safe here, and the pages
  // holding key material are mlock'd (so never written to swap) with core
  // dumps already refused by harden_process(). Leaving the terminal usable is
  // what this can do, and it is what matters at this point.
  struct termios current {};
  if (tcgetattr(STDIN_FILENO, &current) == 0) {
    current.c_lflag |= (ECHO | ICANON | ISIG);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &current);
  }
  const char restore[] = "\033[?2004l\033[?25h\033[?1049l";
  const ssize_t ignored =
      ::write(STDOUT_FILENO, restore, sizeof restore - 1);
  (void)ignored;
}

}  // namespace ratchet::screen
