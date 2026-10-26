#include <QtTest>

#include "gui_output.hpp"
#include "ratchet/gui_format.hpp"

using ratchet::gui::GuiResult;
using ratchet::gui::ParsedGuiResult;

namespace {

constexpr char kPass6[] = "abandon ability able about above absent";
constexpr char kRecovery12[] =
    "abandon ability able about above absent absorb abstract absurd abuse "
    "access accident";

QString block(const QString& body) {
  return QString::fromLatin1(ratchet::gui_format::kBegin) +
         QLatin1Char('\n') + body + QLatin1Char('\n') +
         QString::fromLatin1(ratchet::gui_format::kEnd);
}

QString init_body(const QString& passphrase = QString::fromLatin1(kPass6),
                  const QString& recovery = QString::fromLatin1(kRecovery12),
                  const QString& source = QStringLiteral("generated")) {
  QString body = QStringLiteral(
                     "version=1\n"
                     "command=init\n"
                     "status=ok\n"
                     "source=%1\n"
                     "passphrase_words=6\n"
                     "passphrase=%2")
                     .arg(source, passphrase);
  if (!recovery.isEmpty()) {
    body += QStringLiteral(
                "\nrecovery_words=12\n"
                "recovery=%1").arg(recovery);
  }
  return body;
}

QString passphrase_body(const QString& status = QStringLiteral("ok")) {
  if (status == QLatin1String("cancelled")) {
    return QStringLiteral(
        "version=1\n"
        "command=passphrase\n"
        "status=cancelled");
  }
  return QStringLiteral(
             "version=1\n"
             "command=passphrase\n"
             "status=%1\n"
             "passphrase_words=6\n"
             "passphrase=%2")
      .arg(status, QString::fromLatin1(kPass6));
}

void expectBad(const QString& text, const QString& command) {
  const ParsedGuiResult parsed = ratchet::gui::parseGuiResult(text, command);
  QVERIFY(!parsed.ok);
  QVERIFY(!parsed.error.isEmpty());
  QVERIFY(parsed.value.passphrase.isEmpty());
  QVERIFY(parsed.value.recovery.isEmpty());
  QVERIFY(parsed.value.status == GuiResult::Status::Ok);
}

}  // namespace

class GuiOutputTest : public QObject {
  Q_OBJECT

 private slots:
  void acceptsInitWithRecovery();
  void acceptsRestoredInitWithoutRecovery();
  void acceptsChangedPassphrase();
  void acceptsCancelledPassphrase();
  void acceptsHumanOutputAroundTheBlock();
  void rejectsMissingOrBrokenFraming();
  void rejectsMalformedFields();
  void rejectsIncompleteOrMismatchedPhrases();
  void rejectsSecretsOnCancelledResults();
  void rejectsWrongCommandOrStatus();
};

void GuiOutputTest::acceptsInitWithRecovery() {
  const QString text = QStringLiteral("human output\n") +
                       block(init_body()) + QStringLiteral("\nmore output\n");
  const ParsedGuiResult parsed =
      ratchet::gui::parseGuiResult(text, QStringLiteral("init"));
  QVERIFY(parsed.ok);
  QVERIFY(parsed.error.isEmpty());
  QCOMPARE(parsed.value.status, GuiResult::Status::Ok);
  QCOMPARE(parsed.value.passphrase, QString::fromLatin1(kPass6));
  QCOMPARE(parsed.value.recovery, QString::fromLatin1(kRecovery12));
}

void GuiOutputTest::acceptsRestoredInitWithoutRecovery() {
  const ParsedGuiResult parsed = ratchet::gui::parseGuiResult(
      block(init_body(QString::fromLatin1(kPass6), QString(),
                      QStringLiteral("mnemonic"))),
      QStringLiteral("init"));
  QVERIFY(parsed.ok);
  QCOMPARE(parsed.value.passphrase, QString::fromLatin1(kPass6));
  QVERIFY(parsed.value.recovery.isEmpty());
}

void GuiOutputTest::acceptsChangedPassphrase() {
  const ParsedGuiResult parsed = ratchet::gui::parseGuiResult(
      block(passphrase_body()), QStringLiteral("passphrase"));
  QVERIFY(parsed.ok);
  QCOMPARE(parsed.value.status, GuiResult::Status::Ok);
  QCOMPARE(parsed.value.passphrase, QString::fromLatin1(kPass6));
  QVERIFY(parsed.value.recovery.isEmpty());
}

void GuiOutputTest::acceptsCancelledPassphrase() {
  const ParsedGuiResult parsed = ratchet::gui::parseGuiResult(
      block(passphrase_body(QStringLiteral("cancelled"))),
      QStringLiteral("passphrase"));
  QVERIFY(parsed.ok);
  QCOMPARE(parsed.value.status, GuiResult::Status::Cancelled);
  QVERIFY(parsed.value.passphrase.isEmpty());
  QVERIFY(parsed.value.recovery.isEmpty());
}

void GuiOutputTest::acceptsHumanOutputAroundTheBlock() {
  const QString text = QStringLiteral("before\n") + block(init_body()) +
                       QStringLiteral("\nafter\n");
  QVERIFY(ratchet::gui::parseGuiResult(text, QStringLiteral("init")).ok);
}

void GuiOutputTest::rejectsMissingOrBrokenFraming() {
  expectBad(QString(), QStringLiteral("init"));
  expectBad(QStringLiteral("no block here"), QStringLiteral("init"));
  // The begin marker must be the first thing on its line.
  expectBad(QStringLiteral("prefix") +
                QString::fromLatin1(ratchet::gui_format::kBegin) +
                QLatin1Char('\n') + init_body() + QLatin1Char('\n') +
                QString::fromLatin1(ratchet::gui_format::kEnd),
            QStringLiteral("init"));
  // No end marker.
  expectBad(QString::fromLatin1(ratchet::gui_format::kBegin) +
                QLatin1Char('\n') + init_body(),
            QStringLiteral("init"));
  // Two blocks.
  const QString one = block(init_body());
  expectBad(one + QLatin1Char('\n') + one, QStringLiteral("init"));
  // An empty block has no required fields.
  expectBad(block(QString()), QStringLiteral("init"));
}

void GuiOutputTest::rejectsMalformedFields() {
  const QStringList malformed = {
      QStringLiteral("version=1\ncommand=init\nstatus=ok\nsource=generated\npassphrase_words=6"),
      QStringLiteral("version=1\ncommand=init\nstatus=ok\nsource=generated\nunknown=x"),
      QStringLiteral(
          "version=1\ncommand=init\nstatus=ok\nsource=generated\npassphrase_words=6\n"
          "passphrase=%1\npassphrase=%1")
          .arg(QString::fromLatin1(kPass6)),
      QStringLiteral(
          "version=2\ncommand=init\nstatus=ok\npassphrase_words=6\n"
          "passphrase=%1")
          .arg(QString::fromLatin1(kPass6)),
      QStringLiteral(
          "version=1\ncommand=init\nstatus=ok\nsource=generated\npassphrase_words=6\n"
          "passphrase=%1\nextra")
          .arg(QString::fromLatin1(kPass6)),
      QStringLiteral(
          "version=1\ncommand=init\nstatus=ok\nsource=generated\npassphrase_words=6\n"
          "passphrase=%1\n\n")
          .arg(QString::fromLatin1(kPass6)),
  };
  for (const QString& body : malformed) {
    expectBad(block(body), QStringLiteral("init"));
  }
}

void GuiOutputTest::rejectsIncompleteOrMismatchedPhrases() {
  // Missing passphrase / words.
  expectBad(block(QStringLiteral(
                "version=1\ncommand=init\nstatus=ok\nsource=generated\n"
                "passphrase_words=6")),
            QStringLiteral("init"));
  expectBad(block(QStringLiteral(
                "version=1\ncommand=init\nstatus=ok\nsource=generated\npassphrase=%1")
                .arg(QString::fromLatin1(kPass6))),
            QStringLiteral("init"));

  // Wrong or non-numeric word counts.
  for (const char* count : {"5", "13", "six", ""}) {
    expectBad(block(QStringLiteral(
                         "version=1\ncommand=init\nstatus=ok\nsource=generated\n"
                         "passphrase_words=%1\npassphrase=%2")
                         .arg(QString::fromLatin1(count),
                              QString::fromLatin1(kPass6))),
              QStringLiteral("init"));
  }

  // Malformed phrase shapes.
  for (const QString& phrase :
       {QStringLiteral("UPPER words here and now today"),
        QStringLiteral("abandon  ability able about above absent"),
        QStringLiteral(" abandon ability able about above absent"),
        QStringLiteral("abandon ability able about above absent "),
        QStringLiteral("abandon ability able about above")}) {
    expectBad(block(QStringLiteral(
                         "version=1\ncommand=init\nstatus=ok\nsource=generated\n"
                         "passphrase_words=6\npassphrase=%1")
                         .arg(phrase)),
              QStringLiteral("init"));
  }

  // The source field distinguishes a generated recovery phrase from a restored
  // identity; neither its absence nor a contradiction is accepted.
  expectBad(block(QStringLiteral(
                "version=1\ncommand=init\nstatus=ok\n"
                "passphrase_words=6\npassphrase=%1")
                .arg(QString::fromLatin1(kPass6))),
            QStringLiteral("init"));
  expectBad(block(init_body(QString::fromLatin1(kPass6), QString(),
                            QStringLiteral("generated"))),
            QStringLiteral("init"));
  expectBad(block(init_body(QString::fromLatin1(kPass6),
                            QString::fromLatin1(kRecovery12),
                            QStringLiteral("mnemonic"))),
            QStringLiteral("init"));
  expectBad(block(init_body(QString::fromLatin1(kPass6),
                            QString::fromLatin1(kRecovery12),
                            QStringLiteral("bogus"))),
            QStringLiteral("init"));
  expectBad(block(QStringLiteral(
                "version=1\ncommand=passphrase\nstatus=ok\n"
                "source=generated\npassphrase_words=6\npassphrase=%1")
                .arg(QString::fromLatin1(kPass6))),
            QStringLiteral("passphrase"));

  // Recovery must be complete and must be exactly 12 words.
  expectBad(block(init_body(QString::fromLatin1(kPass6),
                            QString::fromLatin1(kPass6))),
            QStringLiteral("init"));
  const QString only_words = QStringLiteral(
      "version=1\ncommand=init\nstatus=ok\nsource=generated\npassphrase_words=6\n"
      "passphrase=%1\nrecovery_words=12").arg(QString::fromLatin1(kPass6));
  expectBad(block(only_words), QStringLiteral("init"));
  const QString only_phrase = QStringLiteral(
      "version=1\ncommand=init\nstatus=ok\nsource=generated\npassphrase_words=6\n"
      "passphrase=%1\nrecovery=%2")
      .arg(QString::fromLatin1(kPass6), QString::fromLatin1(kRecovery12));
  expectBad(block(only_phrase), QStringLiteral("init"));
  // A recovery phrase on a passphrase change is a contract violation.
  const QString recovery_on_change = QStringLiteral(
      "version=1\ncommand=passphrase\nstatus=ok\npassphrase_words=6\n"
      "passphrase=%1\nrecovery_words=12\nrecovery=%2")
      .arg(QString::fromLatin1(kPass6), QString::fromLatin1(kRecovery12));
  expectBad(block(recovery_on_change), QStringLiteral("passphrase"));
}

void GuiOutputTest::rejectsSecretsOnCancelledResults() {
  const QString with_passphrase = QStringLiteral(
      "version=1\ncommand=passphrase\nstatus=cancelled\n"
      "passphrase_words=6\npassphrase=%1").arg(QString::fromLatin1(kPass6));
  expectBad(block(with_passphrase), QStringLiteral("passphrase"));
  expectBad(block(QStringLiteral(
                "version=1\ncommand=passphrase\nstatus=cancelled\n"
                "source=generated")),
            QStringLiteral("passphrase"));
  // Init has no cancellation path.
  expectBad(block(QStringLiteral("version=1\ncommand=init\nstatus=cancelled")),
            QStringLiteral("init"));
}

void GuiOutputTest::rejectsWrongCommandOrStatus() {
  expectBad(block(init_body()), QStringLiteral("passphrase"));
  expectBad(block(passphrase_body()), QStringLiteral("init"));
  expectBad(block(QStringLiteral("version=1\ncommand=init\nstatus=pending")),
            QStringLiteral("init"));
  expectBad(block(passphrase_body(QStringLiteral("pending"))),
            QStringLiteral("passphrase"));
}

QTEST_GUILESS_MAIN(GuiOutputTest)
#include "test_gui_output.moc"
