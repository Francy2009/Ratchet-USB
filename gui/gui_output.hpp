#ifndef RATCHET_GUI_OUTPUT_HPP
#define RATCHET_GUI_OUTPUT_HPP

#include <QString>

#include <cstdint>

// Parses the opt-in block written by `ratchet-usb init --structured-output` and
// `ratchet-usb passphrase --structured-output`.
//
// The parser is deliberately strict. A missing block, a missing field, an
// unknown field, a duplicated field, a wrong word count or a non-BIP-39 word
// all make the whole result invalid. There is no textual fallback: a GUI that
// asked for the structured format must not silently show a phrase extracted
// from headings, because a changed heading or a stray numbered line could
// produce a short phrase that looks valid.
namespace ratchet::gui {

struct GuiResult {
  enum class Status : std::uint8_t { Ok, Cancelled };

  Status status = Status::Ok;
  QString passphrase;  // empty when status is Cancelled
  QString recovery;    // init only; empty with --from-mnemonic
};

struct ParsedGuiResult {
  bool ok = false;
  GuiResult value;
  QString error;  // safe to show: names fields, never their values
};

// `expected_command` is "init" or "passphrase". The block may be surrounded by
// the command's normal human output; the markers must be whole lines.
ParsedGuiResult parseGuiResult(const QString& text,
                               const QString& expected_command);

}  // namespace ratchet::gui

#endif  // RATCHET_GUI_OUTPUT_HPP
