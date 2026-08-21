#include <string>
#include <string_view>

#include "ratchet/screen.hpp"
#include "test_support.hpp"

using namespace ratchet;
using screen::Key;
using screen::KeyCode;

// The key decoder runs on bytes the terminal hands over, and some of those
// bytes are whatever somebody pasted into the window. It has to consume
// everything it is given, never block waiting for a byte that will not come,
// and never treat a fragment as a key it is not.

namespace {

// Feeds `input` through decode_key until it is exhausted, the way the driver
// does with flush set once the terminal has gone quiet.
std::vector<Key> decode_all(std::string_view input) {
  std::vector<Key> keys;
  std::size_t offset = 0;
  while (offset < input.size()) {
    Key key;
    const std::size_t used = screen::decode_key(input.substr(offset), true, key);
    CHECK(used > 0);  // with flush set, progress is guaranteed
    offset += used;
    keys.push_back(key);
  }
  return keys;
}

}  // namespace

TEST("decode_key reads plain characters one at a time") {
  const std::vector<Key> keys = decode_all("hi");
  CHECK_EQ(keys.size(), std::size_t{2});
  CHECK(keys[0].code == KeyCode::Char);
  CHECK_EQ(keys[0].text, std::string("h"));
  CHECK_EQ(keys[1].text, std::string("i"));
}

TEST("decode_key keeps a multi-byte character whole") {
  const std::vector<Key> keys = decode_all("è");  // U+00E8, two bytes
  CHECK_EQ(keys.size(), std::size_t{1});
  CHECK(keys[0].code == KeyCode::Char);
  CHECK_EQ(keys[0].text.size(), std::size_t{2});
}

TEST("decode_key waits for the rest of a split character") {
  const std::string first_byte = std::string("è").substr(0, 1);
  Key key;
  // Without flush there is no answer yet: the second byte may still arrive.
  CHECK_EQ(screen::decode_key(first_byte, false, key), std::size_t{0});
  // With flush, the fragment is dropped rather than turned into a character.
  CHECK_EQ(screen::decode_key(first_byte, true, key), std::size_t{1});
  CHECK(key.code == KeyCode::None);
}

TEST("decode_key recognises the arrow keys") {
  const std::vector<Key> keys = decode_all("\033[A\033[B\033[C\033[D");
  CHECK_EQ(keys.size(), std::size_t{4});
  CHECK(keys[0].code == KeyCode::Up);
  CHECK(keys[1].code == KeyCode::Down);
  CHECK(keys[2].code == KeyCode::Right);
  CHECK(keys[3].code == KeyCode::Left);
}

TEST("decode_key recognises the SS3 arrows some terminals send") {
  const std::vector<Key> keys = decode_all("\033OA\033OD");
  CHECK_EQ(keys.size(), std::size_t{2});
  CHECK(keys[0].code == KeyCode::Up);
  CHECK(keys[1].code == KeyCode::Left);
}

TEST("a lone ESC is only the Escape key once nothing more is coming") {
  Key key;
  CHECK_EQ(screen::decode_key("\033", false, key), std::size_t{0});
  CHECK_EQ(screen::decode_key("\033", true, key), std::size_t{1});
  CHECK(key.code == KeyCode::Escape);
}

TEST("decode_key recognises the bracketed paste markers") {
  const std::vector<Key> keys = decode_all("\033[200~x\033[201~");
  CHECK_EQ(keys.size(), std::size_t{3});
  CHECK(keys[0].code == KeyCode::PasteBegin);
  CHECK(keys[1].code == KeyCode::Char);
  CHECK(keys[2].code == KeyCode::PasteEnd);
}

TEST("an unknown escape sequence is consumed whole and ignored") {
  const std::vector<Key> keys = decode_all("\033[<35;10;20Mx");
  // Whatever the sequence was, it is not a key, and the 'x' after it still is.
  CHECK_EQ(keys.size(), std::size_t{2});
  CHECK(keys[0].code == KeyCode::None);
  CHECK(keys[1].code == KeyCode::Char);
  CHECK_EQ(keys[1].text, std::string("x"));
}

TEST("an endless escape sequence cannot stall the decoder") {
  // A hostile stream of parameter bytes with no final byte: the decoder has to
  // give up at its cap rather than hold the bytes forever waiting for an end
  // that never comes.
  const std::string endless = "\033[" + std::string(4096, '1');
  Key key;
  const std::size_t used = screen::decode_key(endless, false, key);
  CHECK(used > 0);
  CHECK(used <= screen::kMaxEscapeSequence);
  CHECK(key.code == KeyCode::None);
}

TEST("control bytes are never mistaken for text") {
  const std::vector<Key> keys = decode_all(std::string("\r\t\x7f\x03\x04"));
  CHECK_EQ(keys.size(), std::size_t{5});
  CHECK(keys[0].code == KeyCode::Enter);
  CHECK(keys[1].code == KeyCode::Tab);
  CHECK(keys[2].code == KeyCode::Backspace);
  CHECK(keys[3].code == KeyCode::CtrlC);
  CHECK(keys[4].code == KeyCode::CtrlD);
}

TEST("decode_key consumes every byte of arbitrary input") {
  // The property the driver depends on: with flush set, every call makes
  // progress, so no input can leave the loop spinning.
  std::string input;
  for (int i = 0; i < 256; ++i) {
    input.push_back(static_cast<char>(i));
  }
  std::size_t offset = 0;
  while (offset < input.size()) {
    Key key;
    const std::size_t used =
        screen::decode_key(std::string_view(input).substr(offset), true, key);
    CHECK(used > 0);
    offset += used;
  }
  CHECK_EQ(offset, input.size());
}

// --- measurement and truncation ---------------------------------------------

TEST("display_width counts characters, not bytes") {
  CHECK_EQ(screen::display_width("abc"), std::size_t{3});
  CHECK_EQ(screen::display_width("èàò"), std::size_t{3});
}

TEST("truncate_to_width leaves a line that fits alone") {
  CHECK_EQ(screen::truncate_to_width("alice", 10), std::string("alice"));
  CHECK_EQ(screen::truncate_to_width("alice", 5), std::string("alice"));
}

TEST("truncate_to_width never splits a multi-byte character") {
  // Six two-byte characters cut to five columns: the result has to be valid
  // UTF-8, or the terminal draws a replacement glyph and the layout shifts.
  const std::string text = "èèèèèè";
  const std::string cut = screen::truncate_to_width(text, 5);
  CHECK(screen::display_width(cut) <= std::size_t{5});
  // Every byte that is not a continuation byte starts a sequence, and each
  // sequence here is two bytes: an odd count of leading bytes plus
  // continuations would mean a sliced character.
  std::size_t leads = 0;
  std::size_t continuations = 0;
  for (const char ch : cut) {
    const auto byte = static_cast<unsigned char>(ch);
    if ((byte & 0xC0) == 0x80) {
      ++continuations;
    } else if (byte >= 0x80) {
      ++leads;
    }
  }
  CHECK_EQ(leads, continuations);
}

TEST("truncate_to_width copes with a width smaller than the marker") {
  CHECK_EQ(screen::truncate_to_width("alice", 2).size(), std::size_t{2});
  CHECK_EQ(screen::truncate_to_width("alice", 0), std::string(""));
}

// --- the frame --------------------------------------------------------------

TEST("a frame truncates rather than wraps") {
  screen::Frame frame(10, 5);
  frame.line("this line is far too long to fit");
  CHECK_EQ(frame.lines().size(), std::size_t{1});
  CHECK(screen::display_width(frame.lines()[0]) <= std::size_t{10});
}

TEST("a frame drops lines past its height") {
  // The property that matters: a long contact list cannot push a warning off
  // the bottom by making the frame taller than the screen.
  screen::Frame frame(20, 3);
  for (int i = 0; i < 50; ++i) {
    frame.line("row");
  }
  CHECK_EQ(frame.lines().size(), std::size_t{3});
}

TEST("rendering a frame twice gives the same bytes") {
  screen::Frame frame(20, 5);
  frame.line("one");
  frame.highlight("two");
  frame.cursor(2, 3);
  CHECK_EQ(frame.render(), frame.render());
}

TEST("a frame never emits a window-title sequence") {
  // OSC 0/1/2 would put "Ratchet-USB" in the taskbar and in any screen share.
  // Nothing drawn from user data may produce one, whatever that data contains.
  screen::Frame frame(40, 5);
  frame.line("\033]0;something\007");
  frame.line("plain");
  const std::string rendered = frame.render();
  CHECK(rendered.find("\033]") == std::string::npos);
  CHECK(rendered.find('\007') == std::string::npos);
}

TEST("a frame escapes a newline in the text it is given") {
  // A row is one line. A newline inside it would shift everything below it
  // down the screen, which is the cursor-moving trick again with a plainer
  // byte.
  screen::Frame frame(40, 5);
  frame.line("alice\nwarning: nothing to see here");
  CHECK_EQ(frame.lines().size(), std::size_t{1});
  CHECK(frame.lines()[0].find('\n') == std::string::npos);
  CHECK(frame.lines()[0].find("\\x0a") != std::string::npos);
}

// --- colour ------------------------------------------------------------------

TEST("a frame emits no colour unless it was asked for") {
  screen::Frame plain(20, 3);
  plain.line("hello", screen::Style::Bad);
  CHECK(plain.render().find("\033[1;31m") == std::string::npos);

  screen::Frame coloured(20, 3, /*color=*/true);
  coloured.line("hello", screen::Style::Bad);
  CHECK(coloured.render().find("\033[1;31m") != std::string::npos);
}

TEST("every styled run is closed again") {
  // A run left open paints whatever the terminal draws next -- including the
  // shell prompt after the program exits.
  screen::Frame frame(20, 4, /*color=*/true);
  frame.line("one", screen::Style::Good);
  frame.spans({{"a", screen::Style::Warn}, {"b", screen::Style::Normal}});
  const std::string rendered = frame.render();
  std::size_t opens = 0;
  std::size_t closes = 0;
  for (std::size_t i = 0; i + 1 < rendered.size(); ++i) {
    if (rendered.compare(i, 4, "\033[0m") == 0) {
      ++closes;
    } else if (rendered[i] == '\033' && rendered[i + 1] == '[' &&
               rendered.compare(i, 4, "\033[0m") != 0 &&
               rendered.compare(i, 4, "\033[2K") != 0 &&
               rendered.compare(i, 3, "\033[H") != 0 &&
               rendered.compare(i, 3, "\033[J") != 0 &&
               rendered.compare(i, 6, "\033[?25l") != 0 &&
               rendered.compare(i, 6, "\033[?25h") != 0) {
      ++opens;
    }
  }
  CHECK_EQ(opens, closes);
}

TEST("text cannot smuggle a colour of its own into a styled run") {
  screen::Frame frame(40, 3, /*color=*/true);
  frame.spans({{"\033[1;35mfake", screen::Style::Normal}});
  const std::string rendered = frame.render();
  // The only escapes present are the ones the frame chose; the text's own is
  // visible as characters.
  CHECK(rendered.find("\033[1;35m") == std::string::npos);
  CHECK(rendered.find("\\x1b[1;35mfake") != std::string::npos);
}

TEST("the selected row is a bar across the whole width") {
  screen::Frame frame(20, 3);
  frame.highlight("short");
  CHECK_EQ(screen::display_width(frame.lines()[0]), std::size_t{20});
}

TEST("spans are truncated as one line, not one by one") {
  screen::Frame frame(10, 3);
  frame.spans({{"12345", screen::Style::Normal}, {"67890abc", screen::Style::Normal}});
  CHECK(screen::display_width(frame.lines()[0]) <= std::size_t{10});
}

TEST("the banner is a rectangle of plain ASCII") {
  // It is decoration, and decoration that turns into mojibake on a terminal
  // that is not reading UTF-8 is worse than no decoration.
  const std::vector<std::string>& art = screen::banner();
  CHECK(!art.empty());
  for (const std::string& row : art) {
    CHECK_EQ(row.size(), screen::banner_width());
    for (const char ch : row) {
      const auto byte = static_cast<unsigned char>(ch);
      CHECK(byte >= 0x20 && byte < 0x7F);
    }
  }
}
