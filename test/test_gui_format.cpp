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
