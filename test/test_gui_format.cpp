#include <sstream>
#include <string>
#include <string_view>

#include "ratchet/gui_format.hpp"
#include "test_support.hpp"

using namespace ratchet;

namespace {

constexpr std::string_view kPass6 =
    "abandon ability able about above absent";
constexpr std::string_view kRecovery12 =
    "abandon ability able about above absent absorb abstract absurd abuse "
    "access accident";

std::string write(const gui_format::Result& result, bool* ok = nullptr) {
  std::ostringstream out;
  const bool wrote = gui_format::write_result(out, result);
  if (ok != nullptr) {
    *ok = wrote;
  }
  return out.str();
}

}  // namespace

TEST("gui format: a phrase is lowercase words separated by single spaces") {
  CHECK(gui_format::valid_phrase(kPass6, 6));
  CHECK(gui_format::valid_phrase(kRecovery12, 12));
  CHECK(!gui_format::valid_phrase("", 1));
  CHECK(gui_format::valid_phrase("one", 1));
  CHECK(!gui_format::valid_phrase("one ", 1));
  CHECK(!gui_format::valid_phrase(" one", 1));
  CHECK(!gui_format::valid_phrase("one  two", 2));
  CHECK(!gui_format::valid_phrase("One two", 2));
  CHECK(!gui_format::valid_phrase("one2 two", 2));
  CHECK(!gui_format::valid_phrase("one\ntwo", 2));
  CHECK(!gui_format::valid_phrase(kPass6, 5));
  CHECK(!gui_format::valid_phrase(kPass6, 7));
  CHECK(!gui_format::valid_phrase(std::string(1025, 'a'), 1));
}

TEST("gui format: init result names every field and ends with the marker") {
  bool ok = false;
  const std::string text = write(
      gui_format::Result{"init", "ok", "generated", kPass6, 6, kRecovery12, 12}, &ok);
  CHECK(ok);
  const std::string expected =
      "-----BEGIN RATCHET GUI RESULT-----\n"
      "version=1\n"
      "command=init\n"
      "status=ok\n"
      "source=generated\n"
      "passphrase_words=6\n"
      "passphrase=abandon ability able about above absent\n"
      "recovery_words=12\n"
      "recovery=abandon ability able about above absent absorb abstract "
      "absurd abuse access accident\n"
      "-----END RATCHET GUI RESULT-----\n";
  CHECK_EQ(text, expected);
}

TEST("gui format: a restored init has no recovery phrase") {
  bool ok = false;
  const std::string text =
      write(gui_format::Result{"init", "ok", "mnemonic", kPass6, 6, {}, 0}, &ok);
  CHECK(ok);
  CHECK(text.find("recovery") == std::string::npos);
  CHECK(text.find("passphrase=abandon") != std::string::npos);
}

TEST("gui format: passphrase result and cancellation are distinct") {
  bool ok = false;
  const std::string changed =
      write(gui_format::Result{"passphrase", "ok", {}, kPass6, 6, {}, 0}, &ok);
  CHECK(ok);
  CHECK(changed.find("command=passphrase\n") != std::string::npos);
  CHECK(changed.find("status=ok\n") != std::string::npos);
  CHECK(changed.find("passphrase=abandon") != std::string::npos);
  CHECK(changed.find("recovery") == std::string::npos);

  const std::string cancelled =
      write(gui_format::Result{"passphrase", "cancelled", {}, {}, 0, {}, 0}, &ok);
  CHECK(ok);
  const std::string expected =
      "-----BEGIN RATCHET GUI RESULT-----\n"
      "version=1\n"
      "command=passphrase\n"
      "status=cancelled\n"
      "-----END RATCHET GUI RESULT-----\n";
  CHECK_EQ(cancelled, expected);
}

TEST("gui format: invalid results write nothing") {
  const gui_format::Result invalid[] = {
      {"unlock", "ok", {}, kPass6, 6, "", 0},
      {"init", "pending", "generated", kPass6, 6, "", 0},
      {"init", "cancelled", "generated", kPass6, 6, "", 0},
      {"passphrase", "cancelled", {}, kPass6, 6, "", 0},
      {"init", "ok", "generated", kPass6, 5, "", 0},
      {"init", "ok", "generated", "UPPER words here and there now", 6, "", 0},
      {"init", "ok", "generated", kPass6, 6, kRecovery12, 11},
      {"passphrase", "ok", {}, kPass6, 6, kRecovery12, 12},
      {"init", "ok", "bogus", kPass6, 6, kRecovery12, 12},
      {"init", "ok", "generated", kPass6, 6, {}, 0},
      {"init", "ok", "mnemonic", kPass6, 6, kRecovery12, 12},
      {"passphrase", "ok", "generated", kPass6, 6, {}, 0},
  };
  for (const gui_format::Result& result : invalid) {
    std::ostringstream out;
    CHECK(!gui_format::write_result(out, result));
    CHECK(out.str().empty());
  }
}

TEST("gui format: a failed stream is reported, not claimed successful") {
  std::ostringstream out;
  out.setstate(std::ios::badbit);
  CHECK(!gui_format::write_result(
      out, gui_format::Result{"init", "ok", "mnemonic", kPass6, 6, {}, 0}));
}

// --- recv --------------------------------------------------------------------

TEST("gui format: recv block names the kind and nothing a sender chose") {
  std::ostringstream out;
  CHECK(gui_format::write_recv_result(
      out, gui_format::RecvResult{gui_format::kRecvText, {}, false, {}}));
  const std::string text = out.str();
  CHECK(text.find("command=recv") != std::string::npos);
  CHECK(text.find("kind=text") != std::string::npos);
  CHECK(text.rfind(std::string(gui_format::kEnd) + "\n") ==
        text.size() - gui_format::kEnd.size() - 1);

  std::ostringstream staged;
  CHECK(gui_format::write_recv_result(
      staged, gui_format::RecvResult{gui_format::kRecvFile, "png", true,
                                     "/tmp/ratchet-Ab12/ratchet-file-x9.png"}));
  const std::string file = staged.str();
  CHECK(file.find("kind=file") != std::string::npos);
  CHECK(file.find("ext=png") != std::string::npos);
  CHECK(file.find("staged=yes") != std::string::npos);
  CHECK(file.find("path=/tmp/ratchet-Ab12/ratchet-file-x9.png") !=
        std::string::npos);
}

TEST("gui format: recv block refuses values that did not come from the frame") {
  std::ostringstream out;
  // A text result carries no file fields.
  CHECK(!gui_format::write_recv_result(
      out, gui_format::RecvResult{gui_format::kRecvText, "png", false, {}}));
  CHECK(out.str().empty());
  // An unknown kind is not a result.
  CHECK(!gui_format::write_recv_result(
      out, gui_format::RecvResult{"video", {}, false, {}}));
  // A file needs a sanitised extension, and a path exactly when it was staged.
  CHECK(!gui_format::write_recv_result(
      out, gui_format::RecvResult{gui_format::kRecvFile, "../x", false, {}}));
  CHECK(!gui_format::write_recv_result(
      out, gui_format::RecvResult{gui_format::kRecvFile, "png", true, {}}));
  CHECK(!gui_format::write_recv_result(
      out, gui_format::RecvResult{gui_format::kRecvFile, "png", false,
                                  "/tmp/x.png"}));
  CHECK(!gui_format::write_recv_result(
      out, gui_format::RecvResult{gui_format::kRecvFile, "png", true,
                                  "relative/x.png"}));
  CHECK(!gui_format::write_recv_result(
      out, gui_format::RecvResult{gui_format::kRecvFile, "png", true,
                                  "/tmp/a b.png"}));
  CHECK(out.str().empty());
}

TEST("gui format: staged paths and extensions are validated") {
  CHECK(gui_format::valid_extension("png"));
  CHECK(gui_format::valid_extension("tar0"));
  CHECK(!gui_format::valid_extension(""));
  CHECK(!gui_format::valid_extension("PNG"));
  CHECK(!gui_format::valid_extension(".png"));
  CHECK(!gui_format::valid_extension("p_ng"));
  CHECK(!gui_format::valid_extension("aaaaaaaaaaaaaaaaa"));  // 17 characters
  CHECK(gui_format::valid_staged_path("/run/user/1000/ratchet-a/ratchet-file-b.png"));
  CHECK(!gui_format::valid_staged_path(""));
  CHECK(!gui_format::valid_staged_path("ratchet-file-b.png"));
  CHECK(!gui_format::valid_staged_path("/tmp/x.png\n"));
  CHECK(!gui_format::valid_staged_path("/tmp/x.png\x1b"));
}

// --- recv: the body is the sender's text -------------------------------------

TEST("gui format: recv body cannot spell the block's marker") {
  // terminal::escape_control_chars leaves printable characters alone, so a
  // sender can put the begin marker in a message verbatim. The body writer
  // escapes both markers, which is what makes the stream hold exactly one of
  // each -- and the escape character makes the rewrite reversible.
  const std::string body = std::string("before\n") + std::string(gui_format::kBegin) +
                           "\nafter " + std::string(gui_format::kEnd) + "\n";
  std::ostringstream out;
  gui_format::write_body_escaped(out, body);
  const std::string written = out.str();
  CHECK(written.find(gui_format::kBegin) == std::string::npos);
  CHECK(written.find(gui_format::kEnd) == std::string::npos);
  CHECK(written.find("before\n") == 0);
  // The marker is `%` plus its colon-hex spelling, 18 bytes as 2-digit pairs.
  CHECK(written.find("%2d:2d:2d:2d:2d") != std::string::npos);
  CHECK_EQ(gui_format::unescape_body(written), body);

  // With the block after it, the marker occurs once and on its own line.
  std::ostringstream full;
  full << written;
  CHECK(gui_format::write_recv_result(
      full, gui_format::RecvResult{gui_format::kRecvText, {}, false, {}}));
  const std::string stream = full.str();
  const std::size_t first = stream.find(gui_format::kBegin);
  CHECK(first != std::string::npos);
  CHECK(stream.find(gui_format::kBegin, first + 1) == std::string::npos);
  CHECK(stream.find(gui_format::kEnd) ==
        stream.size() - gui_format::kEnd.size() - 1);
}

TEST("gui format: recv body passes NUL, Unicode and control bytes through") {
  // Only the markers are rewritten. A NUL, an ESC and a multi-byte character
  // are the received text, and the block is what the reader parses.
  // The escape is closed before the 'b': in "\x00b" the 'b' is a hex digit, so
  // the compiler would read the single byte 0x0b and the body would carry no
  // NUL at all -- which is what this test used to assert.
  const std::string body =
      std::string("a\x00" "b\xc3\xa8\xf0\x9f\x94\x90\x1b[31mc", 15);
  CHECK(body.size() == 15);
  CHECK(body.find('\0') != std::string::npos);
  std::ostringstream out;
  gui_format::write_body_escaped(out, body);
  CHECK(out.str() == body);

  // A body with no marker is copied unchanged, length included.
  const std::string long_body(200000, 'x');
  std::ostringstream large;
  gui_format::write_body_escaped(large, long_body);
  CHECK(large.str().size() == long_body.size());
}

TEST("gui format: the body escape is reversible, spelling and all") {
  // A message can contain the escape character itself and the exact hex
  // spelling the writer uses for a marker. Doubling `%` is what keeps the two
  // apart: after unescaping, the body is byte for byte what was sent.
  const std::string body = std::string("50% off, literal %2d:2d:2d\n") +
                           std::string(gui_format::kBegin) + "\n" +
                           std::string(gui_format::kEnd);
  std::ostringstream out;
  gui_format::write_body_escaped(out, body);
  const std::string written = out.str();
  CHECK(written.find(gui_format::kBegin) == std::string::npos);
  CHECK(written.find("50%% off") != std::string::npos);
  CHECK(written.find("%%2d:2d:2d") != std::string::npos);
  CHECK_EQ(gui_format::unescape_body(written), body);
}

TEST("gui format: recv body rewrites every marker, not just the first") {
  std::string body;
  for (int i = 0; i < 100; ++i) {
    body += gui_format::kBegin;
    body += "text";
  }
  std::ostringstream out;
  gui_format::write_body_escaped(out, body);
  CHECK(out.str().find(gui_format::kBegin) == std::string::npos);
  // Nothing but the markers was touched: every "text" survives.
  std::size_t count = 0;
  for (std::size_t at = out.str().find("text"); at != std::string::npos;
       at = out.str().find("text", at + 4)) {
    ++count;
  }
  CHECK_EQ(count, std::size_t{100});
}

