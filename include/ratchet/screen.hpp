#ifndef RATCHET_SCREEN_HPP
#define RATCHET_SCREEN_HPP

#include <termios.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// The terminal underneath the interface in ui.cpp: raw mode, the alternate
// screen, a frame buffer, and a decoder that turns bytes into keys.
//
// This is deliberately not a curses binding. ncurses would be a second
// dependency in a project that has exactly one, and it reads and interprets
// terminfo -- files outside this process, parsed by code that is not this
// code, on behalf of a tool whose whole point is a small attack surface. What
// is here instead is the fixed handful of ANSI sequences every terminal
// written in the last thirty years understands, emitted unconditionally.
//
// Three things this never does, and they are requirements rather than
// omissions:
//
//   * It never sets the window title (OSC 0/1/2). A title says what you are
//     running, and it shows up in the taskbar, the window switcher, a
//     screenshot and a screen share. This is a tool for keeping data private
//     on a machine; announcing itself there would undo that for free.
//   * It never touches the clipboard, in either direction, and in particular
//     never emits OSC 52.
//   * It never enables mouse reporting. Keyboard only: fewer escape sequences
//     to decode, and the terminal's own selection keeps working, which is how
//     a user copies a message block out.
namespace ratchet::screen {

// --- text measurement -------------------------------------------------------

// Number of code points in `text`, which is what the layout needs rather than
// the number of bytes: an alias with an accent in it would otherwise be
// measured a column wider than it draws.
//
// Code points, not display columns. A CJK ideograph draws two columns wide and
// is counted as one here, so a line of them can overflow by its own length.
// Getting that right means shipping a copy of the Unicode width tables, which
// is a lot of data to carry for contact aliases; the frame is truncated
// defensively instead, so the failure is a slightly short line rather than a
// broken layout.
std::size_t display_width(std::string_view text);

// `text` shortened to at most `max_width` code points, cut on a UTF-8
// boundary so a multi-byte sequence is never sliced in half, with "..." in
// place of what was dropped. Returns `text` unchanged when it already fits.
std::string truncate_to_width(std::string_view text, std::size_t max_width);

// Rewrites every C0 control character and DEL as a visible \xNN escape.
//
// This is terminal::escape_control_chars with newline and tab included rather
// than spared. A message body printed by `recv` legitimately spans lines; a
// row of a frame never does, and a newline in one would push everything below
// it down a line -- which is the same trick as an unescaped ESC, just quieter.
//
// Frame::line applies this to everything it is given, so a caller cannot
// forget to. That is the point of having it there rather than at the call
// sites: aliases and message bodies come from other people, and "we escaped it
// everywhere it mattered" is a claim that decays with every new call site.
std::string sanitize_line(std::string_view text);

// Splits `text` into lines of at most `width` code points.
//
// Existing newlines are honoured, and a break falls on the last space of the
// line when there is one, so a message reads as prose rather than as a block
// cut every N characters. A run with no space in it -- a base64 block, a URL
// -- is cut where the width runs out, always on a UTF-8 boundary.
std::vector<std::string> wrap_text(std::string_view text, std::size_t width);

// --- keys -------------------------------------------------------------------

enum class KeyCode : uint8_t {
  None,        // a byte or sequence that means nothing here; ignore it
  Char,        // a printable character; the bytes are in Key::text
  Enter,
  Backspace,
  Tab,
  Escape,
  Up,
  Down,
  Left,
  Right,
  Home,
  End,
  Delete,
  PageUp,
  PageDown,
  CtrlC,
  CtrlD,
  CtrlL,
  CtrlU,
  CtrlW,
  PasteBegin,  // the terminal is about to send pasted bytes
  PasteEnd,    // the pasted bytes are done
};

struct Key {
  KeyCode code = KeyCode::None;
  // For KeyCode::Char, the whole UTF-8 sequence (one to four bytes). Empty
  // otherwise.
  std::string text;
};

// The longest escape sequence this decoder will ever look at. Anything longer
// is not a key, so consuming it and moving on is the correct answer and also
// the one that keeps a hostile stream from making the decoder hold bytes
// forever.
inline constexpr std::size_t kMaxEscapeSequence = 16;

// Decodes one key from the front of `in`, returning how many bytes it used.
//
// A return of 0 means `in` holds only the beginning of something -- a lone ESC
// that might still become an arrow key, a UTF-8 sequence cut off mid-way --
// and the caller should read more before asking again. `flush` says there will
// be no more: a lone ESC is then the Escape key, and a truncated sequence is
// dropped, so the return is never 0.
//
// Nothing here allocates in proportion to the input, and nothing is buffered
// between calls.
std::size_t decode_key(std::string_view in, bool flush, Key& out);

// --- frame buffer -----------------------------------------------------------

// A screen's worth of lines, drawn in a single write.
//
// Every line is truncated to the frame's width rather than wrapped. That is a
// safety property, not a style choice: aliases and message bodies are written
// by other people, and a line that wraps can push a warning off the bottom of
// the screen -- "this contact is not verified" is exactly the line an attacker
// would want scrolled away.
class Frame {
 public:
  Frame(std::size_t width, std::size_t height);

  std::size_t width() const { return width_; }
  std::size_t height() const { return height_; }

  void clear();

  // Appends one line, truncated to the frame width. Lines past the frame's
  // height are dropped.
  void line(std::string_view text);
  void blank() { line({}); }

  // Same, in reverse video, for a selected row or a header.
  void highlight(std::string_view text);

  // Places the visible cursor, one-based. Without a call to this the cursor is
  // parked at the bottom left and hidden by the driver.
  void cursor(std::size_t row, std::size_t col);

  const std::vector<std::string>& lines() const { return lines_; }

  // The whole frame as one string of text and escape sequences, ready to be
  // handed to write(). Idempotent: rendering twice yields the same bytes.
  std::string render() const;

 private:
  std::size_t width_;
  std::size_t height_;
  std::vector<std::string> lines_;
  std::vector<bool> highlighted_;
  std::size_t cursor_row_ = 0;  // zero means "no cursor"
  std::size_t cursor_col_ = 0;
};

// --- terminal state ---------------------------------------------------------

// True when stdin and stdout are both a terminal and TERM names one that can
// do anything. The interface refuses to start otherwise, which is what keeps
// every existing scripted use of this program on exactly the path it was on
// before.
bool usable();

struct Size {
  std::size_t width = 80;
  std::size_t height = 24;
};

// The terminal's current size, falling back to 80x24 when it cannot be asked.
Size size();

// Raw mode for as long as this object exists, restored by the destructor --
// including when the stack is unwound by an exception.
//
// ISIG is switched off, so Ctrl-C arrives as a keystroke rather than a signal.
// That is on purpose: a SIGINT handler cannot safely wipe the vault out of
// memory (almost nothing is async-signal-safe), while a keystroke can be
// handled by the ordinary loop, which zeroes everything on its way out.
class RawMode {
 public:
  RawMode();
  ~RawMode();
  RawMode(const RawMode&) = delete;
  RawMode& operator=(const RawMode&) = delete;

  bool active() const { return active_; }

 private:
  struct termios saved_ {};
  bool active_ = false;
};

// The alternate screen buffer, plus a hidden cursor and bracketed paste, all
// undone by the destructor.
//
// The alternate screen is what keeps the session from ending up in the
// scrollback: on exit the terminal shows exactly what it showed before the
// program started, with no contact list or message left behind to scroll back
// to.
//
// Bracketed paste is a defence rather than a nicety. With it on, the terminal
// wraps pasted bytes in markers, so a message block that contains an escape
// sequence or a newline is delivered as data to a text field instead of being
// mistaken for the user pressing keys.
class AltScreen {
 public:
  AltScreen();
  ~AltScreen();
  AltScreen(const AltScreen&) = delete;
  AltScreen& operator=(const AltScreen&) = delete;
};

// Writes every byte of `text` to stdout, retrying on a short write and on
// EINTR. Returns false if the terminal went away.
bool write_all(std::string_view text);

// Waits up to `timeout_ms` for input (negative to wait indefinitely) and
// appends whatever arrived to `buffer`. Returns false on end of input or an
// error; a timeout with nothing to read returns true having appended nothing.
bool read_available(std::string& buffer, int timeout_ms);

// Restores the terminal from a signal handler: raw mode off, alternate screen
// left, cursor shown. Only async-signal-safe calls, so it is safe to run from
// a handler for the signals that mean the terminal is going away.
void emergency_restore() noexcept;

}  // namespace ratchet::screen

#endif  // RATCHET_SCREEN_HPP
