#ifndef RATCHET_GUI_PAYLOAD_INPUT_HPP
#define RATCHET_GUI_PAYLOAD_INPUT_HPP

#include <QByteArray>
#include <QStringList>

// How a message or a received block reaches the CLI without passing through
// argv.
//
// /proc/<pid>/cmdline is readable by every process of the same user, so a
// plaintext message passed as a positional argument is exposed for as long as
// the child runs. The CLI already reads its payload from stdin when no
// positional is given, but the vault passphrase arrives on the same stream;
// a delimiter is ambiguous because a message may contain blank lines.
// --stdin-payload names the exact byte count, so the parent can write
//
//     <payload bytes><passphrase input>
//
// and the child reads the payload first, then the passphrase. This keeps
// Unicode, embedded newlines, blank lines and NUL bytes intact.
namespace ratchet::gui {

struct PayloadInput {
  // Payload first, then the passphrase bytes, ready for QProcess::write().
  QByteArray stdin_data;
  // {"--stdin-payload", "<payload byte count>"}.
  QStringList flags;
};

PayloadInput payloadInput(const QByteArray& payload,
                          const QByteArray& passphrase_input);

// Best-effort wipe of a QByteArray that this process owns. It is not a
// security boundary: Qt may have made implicit copies (QProcess's own write
// buffer is one) that this cannot reach.
void wipeByteArray(QByteArray& bytes) noexcept;

}  // namespace ratchet::gui

#endif  // RATCHET_GUI_PAYLOAD_INPUT_HPP
