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

TEST("escape_line_control_chars escapes newline and tab too") {
  // A value printed inside one line (an alias, a label) must not be able to
  // start a second line, even though a message is allowed to contain one.
  const std::string payload = "alice\nfingerprint: forged\tx";
  const std::string escaped = terminal::escape_line_control_chars(payload);
  CHECK(escaped.find('\n') == std::string::npos);
  CHECK(escaped.find('\t') == std::string::npos);
  CHECK(escaped.find("\\x0a") != std::string::npos);
  CHECK(escaped.find("\\x09") != std::string::npos);
  CHECK(escaped.find("alice") != std::string::npos);
  CHECK(escaped.find("fingerprint: forged") != std::string::npos);
}

TEST("escape_line_control_chars leaves ordinary text alone") {
  const std::string payload = "ciao, però — 世界 🔐";
  CHECK_EQ(terminal::escape_line_control_chars(payload), payload);
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

TEST("escape_control_chars neutralises a right-to-left override") {
  // U+202E reads as nothing but reverses the run that follows it: "photo\u202Egnp.exe"
  // is drawn as "photoexe.png". A contact chooses the alias, and the alias is
  // printed beside the message, so the override must not reach the terminal.
  const std::string payload = std::string("photo") + "\u202E" + "gnp.exe";
  const std::string escaped = terminal::escape_control_chars(payload);
  CHECK(escaped.find("\u202E") == std::string::npos);
  CHECK(escaped.find("\xe2\x80\xae") == std::string::npos);  // the raw bytes
  CHECK(escaped.find("\\u202e") != std::string::npos);
  CHECK(escaped.find("photo") != std::string::npos);
  CHECK(escaped.find("gnp.exe") != std::string::npos);
}

TEST("escape_control_chars neutralises every bidi character it lists") {
  // U+200E/U+200F, the U+202A..U+202E embeddings, U+2066..U+2069 isolates and
  // U+FEFF, plus the C1 controls spelled as UTF-8 (U+0080 and U+009F), the
  // Arabic letter mark, the zero-width space, the word joiner, the line
  // separator and a deprecated format character.
  const std::string payload =
      "a\u200Eb\u200Fc\u202Ad\u202Be\u202Cf\u202Dg\u202Eh"
      "\u2066i\u2067j\u2068k\u2069l\uFEFFm\u0080n\u009Fo"
      "\u061Cp\u200Bq\u2060r\u2028s\u206At";
  const std::string escaped = terminal::escape_control_chars(payload);
  CHECK(!has_unicode_format_chars(escaped));
  CHECK(escaped.find("\\u200e") != std::string::npos);
  CHECK(escaped.find("\\u202e") != std::string::npos);
  CHECK(escaped.find("\\u2066") != std::string::npos);
  CHECK(escaped.find("\\ufeff") != std::string::npos);
  CHECK(escaped.find("\\u0080") != std::string::npos);
  CHECK(escaped.find("\\u009f") != std::string::npos);
  CHECK(escaped.find("\\u061c") != std::string::npos);
  CHECK(escaped.find("\\u200b") != std::string::npos);
  CHECK(escaped.find("\\u2060") != std::string::npos);
  CHECK(escaped.find("\\u2028") != std::string::npos);
  CHECK(escaped.find("\\u206a") != std::string::npos);
  // The readable letters are still there, in order.
  CHECK(escaped.find('a') != std::string::npos);
  CHECK(escaped.find('o') != std::string::npos);
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
