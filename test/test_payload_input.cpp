#include <QtTest>

#include "payload_input.hpp"

// The GUI must not put a message or a received block in the child's argv:
// /proc/<pid>/cmdline is readable by every process of the same user. The CLI's
// --stdin-payload option takes an exact byte count, so the payload can contain
// newlines, blank lines, UTF-8 and NUL bytes and still stop exactly where the
// passphrase starts. This test pins the framing, not the Qt widget that feeds
// it.

class PayloadInputTest : public QObject {
  Q_OBJECT

 private slots:
  void putsPayloadBeforePassphrase();
  void preservesUnicodeAndMultilineText();
  void preservesEmbeddedNulBytes();
  void flagsNameTheExactByteCount();
};

void PayloadInputTest::putsPayloadBeforePassphrase() {
  const QByteArray payload("hello\nworld\n\nlast line");
  const QByteArray pass("word one word two\n\n");

  const ratchet::gui::PayloadInput framed =
      ratchet::gui::payloadInput(payload, pass);

  QCOMPARE(framed.stdin_data.size(), payload.size() + pass.size());
  QCOMPARE(framed.stdin_data.left(payload.size()), payload);
  QCOMPARE(framed.stdin_data.mid(payload.size()), pass);
  QCOMPARE(framed.flags.size(), qsizetype{2});
  QCOMPARE(framed.flags.at(0), QStringLiteral("--stdin-payload"));
  QCOMPARE(framed.flags.at(1),
           QString::number(static_cast<qulonglong>(payload.size())));
}

void PayloadInputTest::preservesUnicodeAndMultilineText() {
  // "città" is two UTF-8 bytes for the final a-grave, and the rocket is four.
  // Counting QString characters instead of UTF-8 bytes here would cut the
  // payload in the middle of a code point.
  const QString text = QString::fromUtf8("città 🚀\nseconda riga\n\nquarta");
  const QByteArray payload = text.toUtf8();
  const QByteArray pass("parola\n\n");

  const ratchet::gui::PayloadInput framed =
      ratchet::gui::payloadInput(payload, pass);

  QCOMPARE(framed.stdin_data.left(payload.size()), payload);
  QCOMPARE(framed.stdin_data.mid(payload.size()), pass);
  QCOMPARE(framed.flags.at(1),
           QString::number(static_cast<qulonglong>(payload.size())));
  QVERIFY(framed.stdin_data.size() > payload.size());
}

void PayloadInputTest::preservesEmbeddedNulBytes() {
  // QByteArray is length-delimited, so a message can carry a NUL; the byte
  // count is what keeps the CLI from treating it as a terminator.
  const QByteArray payload("before\0after", 12);
  const QByteArray pass("pass\n\n");

  const ratchet::gui::PayloadInput framed =
      ratchet::gui::payloadInput(payload, pass);

  QCOMPARE(framed.flags.at(1), QStringLiteral("12"));
  QCOMPARE(framed.stdin_data.size(), qsizetype{12 + 6});
  QCOMPARE(framed.stdin_data.left(12), payload);
  QCOMPARE(framed.stdin_data.at(6), '\0');
}

void PayloadInputTest::flagsNameTheExactByteCount() {
  // A non-ASCII payload repeated once: the flag must be the UTF-8 byte count,
  // not the number of QChars.
  const QString text = QString::fromUtf8("àèìòù");
  const QByteArray payload = text.toUtf8();
  const ratchet::gui::PayloadInput framed =
      ratchet::gui::payloadInput(payload, QByteArray());
  QCOMPARE(framed.flags.at(1),
           QString::number(static_cast<qulonglong>(payload.size())));
  QCOMPARE(framed.stdin_data, payload);
}

QTEST_GUILESS_MAIN(PayloadInputTest)
#include "test_payload_input.moc"
