#include "payload_input.hpp"

#include <QString>

#include <cstddef>

namespace ratchet::gui {

PayloadInput payloadInput(const QByteArray& payload,
                          const QByteArray& passphrase_input) {
  PayloadInput out;
  out.flags << QStringLiteral("--stdin-payload")
            << QString::number(static_cast<qulonglong>(payload.size()));
  out.stdin_data.reserve(payload.size() + passphrase_input.size());
  out.stdin_data.append(payload);
  out.stdin_data.append(passphrase_input);
  return out;
}

void wipeByteArray(QByteArray& bytes) noexcept {
  // volatile keeps the stores from being treated as dead. QByteArray::data()
  // detaches if the buffer is shared, so this wipes only this object's copy;
  // other implicit copies are outside its reach.
  if (!bytes.isEmpty()) {
    volatile char* p = bytes.data();
    for (qsizetype i = 0; i < bytes.size(); ++i) {
      p[i] = 0;
    }
  }
  bytes.clear();
}

}  // namespace ratchet::gui
