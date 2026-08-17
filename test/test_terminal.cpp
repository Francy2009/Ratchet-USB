#include <string>

#include "ratchet/terminal.hpp"
#include "test_support.hpp"

using namespace ratchet;

// A decrypted message body is chosen by the sender. The sender is
// authenticated -- they are a contact whose card was imported -- but that is
// not the same as trusted, and "not yet trusted" is precisely the state the
// warning printed alongside the message exists to announce. A terminal treats
// the bytes it is handed as instructions, so an unescaped ESC in a message is
// a way for the sender to redraw the recipient's screen.

TEST("escape_control_chars neutralises ESC and the rest of C0") {
  const std::string payload = "ok\x1b[1A\x1b[2K\rwarning: NONE. all verified.";
  const std::string escaped = terminal::escape_control_chars(payload);

  // Nothing that a terminal reads as a command survives.
  CHECK(escaped.find('\x1b') == std::string::npos);
  CHECK(escaped.find('\r') == std::string::npos);
  // The escape is visible rather than silently dropped, so the recipient can
  // see that something was in there.
  CHECK(escaped.find("\\x1b") != std::string::npos);
  CHECK(escaped.find("\\x0d") != std::string::npos);
  // The readable text is still readable.
  CHECK(escaped.find("warning: NONE. all verified.") != std::string::npos);
}

TEST("escape_control_chars leaves newline and tab alone") {
  const std::string payload = "line one\nline two\tcolumn";
  CHECK_EQ(terminal::escape_control_chars(payload), payload);
}

TEST("escape_control_chars catches DEL and NUL") {
  const std::string payload = std::string("a\x7f") + std::string(1, '\0') + "b";
  const std::string escaped = terminal::escape_control_chars(payload);
  CHECK(escaped.find("\\x7f") != std::string::npos);
  CHECK(escaped.find("\\x00") != std::string::npos);
  CHECK(escaped.find('\x7f') == std::string::npos);
}

TEST("escape_control_chars passes UTF-8 through untouched") {
  // Bytes 0x80-0x9f are the C1 controls only in a non-UTF-8 terminal; in UTF-8
  // they are continuation bytes. Escaping them would mangle every message that
  // is not pure ASCII, which is most of them.
  const std::string payload = "ciao, però — 世界 🔐";
  CHECK_EQ(terminal::escape_control_chars(payload), payload);
}

TEST("escape_control_chars leaves ordinary printable ASCII alone") {
  const std::string payload =
      "The quick brown fox: 0123456789 !\"#$%&'()*+,-./;<=>?@[]^_`{|}~";
  CHECK_EQ(terminal::escape_control_chars(payload), payload);
}

TEST("an OSC 52 clipboard-write sequence does not survive escaping") {
  // Some terminals let a program write the system clipboard with OSC 52. The
  // BEL that terminates it is a C0 control, and so is the ESC that opens it.
  const std::string payload = "hi\x1b]52;c;cHduZWQ=\x07";
  const std::string escaped = terminal::escape_control_chars(payload);
  CHECK(escaped.find('\x1b') == std::string::npos);
  CHECK(escaped.find('\x07') == std::string::npos);
}

TEST("escaping is idempotent on text that has already been escaped") {
  const std::string once = terminal::escape_control_chars("a\x1b b");
  CHECK_EQ(terminal::escape_control_chars(once), once);
}

TEST("escape_if_tty returns the bytes verbatim when stdout is not a terminal") {
  // Under the test runner stdout is a pipe or a file, never a tty, so a
  // redirect must get exactly what the sender wrote -- mangling it there would
  // be the bug, not the fix.
  const std::string payload = "raw\x1b[2Kbytes";
  if (!terminal::stdout_is_tty()) {
    CHECK_EQ(terminal::escape_if_tty(payload), payload);
  }
}
