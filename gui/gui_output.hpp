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

// The block `ratchet-usb recv --structured-output` appends after the message
// body. Unlike the two above there is nothing secret in it -- the sender's
// alias is not part of it -- so the values are kept, but only after the same
// strict checks: one whole-line block at the very end of stdout, known fields
// only, no duplicates, and a kind of "text" or "file". A "file" result is
// valid only with a safe extension, and with a staged path exactly when it says
// it staged one.
struct ParsedRecvResult {
  bool ok = false;
  bool is_file = false;
  QString ext;
  bool staged = false;
  QString path;
  // The message body: what the CLI wrote before the block, with the framing
  // newline removed and the writer's escape undone when the block names an
  // escape this parser can reverse. Valid when ok is true.
  QString body;
  // Sender-chosen expiry from the CLI's ephemeral framing: "off", "1h",
  // "24h" or "7d" ("off" also covers a block from a CLI that predates the
  // fields), plus the burn flag. The window shows both and, for a TTL,
  // clears what it showed when the time is up.
  QString ttl = QStringLiteral("off");
  bool burn = false;
  QString error;  // safe to show
};

ParsedRecvResult parseRecvResult(const QString& stdout_text);

}  // namespace ratchet::gui

#endif  // RATCHET_GUI_OUTPUT_HPP
