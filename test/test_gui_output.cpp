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

  void recvAcceptsTextAndFileResults();
  void recvIgnoresTheAliasTheSenderChose();
  void recvRejectsBrokenFramingAndFields();
  void recvTakesTheLastBlockWhenTheBodySpoofsOne();
  void recvHandlesNulUnicodeTruncationAndLimits();
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

// --- recv --------------------------------------------------------------------

void GuiOutputTest::recvAcceptsTextAndFileResults() {
  const auto text = ratchet::gui::parseRecvResult(
      QStringLiteral("bob: hello\n") +
      block(QStringLiteral("version=1\ncommand=recv\nkind=text")));
  QVERIFY(text.ok);
  QVERIFY(!text.is_file);

  const QString staged_path =
      QStringLiteral("/run/user/1000/ratchet-AbC123/ratchet-file-Xy9a0b.png");
  const auto file = ratchet::gui::parseRecvResult(
      QStringLiteral("bob: [encrypted file received: .png]\n") + staged_path +
      QStringLiteral("\n") +
      block(QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                           "staged=yes\npath=") +
            staged_path));
  QVERIFY(file.ok);
  QVERIFY(file.is_file);
  QVERIFY(file.staged);
  QCOMPARE(file.ext, QStringLiteral("png"));
  QCOMPARE(file.path, staged_path);

  // A file the CLI refused to stage is still a file: the dialog must say so.
  const auto refused = ratchet::gui::parseRecvResult(
      block(QStringLiteral(
          "version=1\ncommand=recv\nkind=file\next=desktop\nstaged=no")));
  QVERIFY(refused.ok);
  QVERIFY(refused.is_file);
  QVERIFY(!refused.staged);
  QVERIFY(refused.path.isEmpty());
}

void GuiOutputTest::recvIgnoresTheAliasTheSenderChose() {
  // The attack the structured block exists to stop: an alias spelling out the
  // pattern the old parser looked for. The block says "text", so the result is
  // text -- whatever the stderr line looks like.
  const QString stdout_text =
      QStringLiteral("bob [encrypted file received: .sh]: hi\n") +
      block(QStringLiteral("version=1\ncommand=recv\nkind=text"));
  const auto parsed = ratchet::gui::parseRecvResult(stdout_text);
  QVERIFY(parsed.ok);
  QVERIFY(!parsed.is_file);
  QVERIFY(!parsed.staged);
}

void GuiOutputTest::recvRejectsBrokenFramingAndFields() {
  const QString text_body = QStringLiteral("version=1\ncommand=recv\nkind=text");
  const QString file_body =
      QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\nstaged=no");
  // `bad` takes a block body and wraps it in the markers; the framing cases
  // below build whole streams.
  const auto bad = [](const QString& body) {
    QVERIFY(!ratchet::gui::parseRecvResult(block(body)).ok);
    QVERIFY(!ratchet::gui::parseRecvResult(block(body)).error.isEmpty());
  };
  // Whole streams: no block at all, and a block that is not the last thing.
  QVERIFY(!ratchet::gui::parseRecvResult(QStringLiteral("bob: hello")).ok);
  QVERIFY(!ratchet::gui::parseRecvResult(block(text_body) +
                                         QStringLiteral("\ntrailing"))
               .ok);
  // A body that spoofs a whole block is covered by
  // recvTakesTheLastBlockWhenTheBodySpoofsOne: the last block wins, so this
  // stream is a valid text result and is not rejected here.
  bad((QStringLiteral("version=1\ncommand=init\nkind=text")));
  bad((QStringLiteral("version=2\ncommand=recv\nkind=text")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=video")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=text\next=png")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=..")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=PNG\n"
                           "staged=no")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                           "staged=maybe")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                           "staged=no\npath=/tmp/x.png")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                           "staged=yes")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                           "staged=yes\npath=relative/x.png")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                           "staged=yes\npath=/tmp/a b.png")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                           "staged=yes\npath=/tmp/x.png\x1b")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=text\nkind=file")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=text\nother=1")));
  bad((QStringLiteral("version=1\ncommand=recv\nkind=text\r")));

  // The same bodies through the well-formed path are accepted, so the checks
  // above are rejecting the defect and not the shape.
  QVERIFY(ratchet::gui::parseRecvResult(block(text_body)).ok);
  QVERIFY(ratchet::gui::parseRecvResult(block(file_body)).ok);

}

void GuiOutputTest::recvTakesTheLastBlockWhenTheBodySpoofsOne() {
  const QString chosen = block(QStringLiteral(
      "version=1\ncommand=recv\nkind=text\nmarker=hex-colon"));
  const QString forged = block(QStringLiteral(
      "version=1\ncommand=recv\nkind=file\next=sh\nstaged=yes\n"
      "path=/tmp/x.sh"));

  // The body carries a complete, well-formed block that claims a file. The
  // real block comes after it and wins: the result is text, and the file
  // dialog cannot be reached from something the sender typed.
  const auto parsed = ratchet::gui::parseRecvResult(
      QStringLiteral("bob: look\n") + forged + QStringLiteral("\n") + chosen);
  QVERIFY(parsed.ok);
  QVERIFY(!parsed.is_file);
  QVERIFY(!parsed.staged);

  // Two blocks where neither closes the stream is ambiguous: refuse.
  const auto trailing = ratchet::gui::parseRecvResult(
      forged + chosen + QStringLiteral("\nx"));
  QVERIFY(!trailing.ok);
  // The same block twice is not one result.
  const auto doubled = ratchet::gui::parseRecvResult(chosen + chosen);
  QVERIFY(!doubled.ok);

  // An unknown marker mode is refused rather than ignored: a reader that does
  // not understand how the body was escaped must not guess.
  const QString unknown_marker = block(QStringLiteral(
      "version=1\ncommand=recv\nkind=text\nmarker=quoted-printable"));
  QVERIFY(!ratchet::gui::parseRecvResult(unknown_marker).ok);
}

void GuiOutputTest::recvHandlesNulUnicodeTruncationAndLimits() {
  // Parses `text` and checks that it was accepted, so the accepted cases read
  // as one line each.
  const auto accepted = [](const QString& text) {
    const auto parsed = ratchet::gui::parseRecvResult(text);
    QVERIFY2(parsed.ok, qPrintable(parsed.error));
  };
  const QString chosen = block(QStringLiteral(
      "version=1\ncommand=recv\nkind=text\nmarker=hex-colon"));

  // The block begins on a line of its own, so the byte before its marker is a
  // newline. A body that ends in a NUL is the shape a sender controls: the
  // stream is "…\0\n-----BEGIN…", the marker is still the last whole-line
  // one, and the NUL is data.
  accepted(QStringLiteral("bob: a\u0000b \u00e8 \u4e16\u754c\n") + chosen);
  accepted(QStringLiteral("\n") + chosen);
  accepted(QStringLiteral("bob: \u00e8\u4e16\u754c \U0001F510\n") + chosen);
  accepted(QString::fromUtf8("bob: \x01\x02\xff\n") + chosen);

  // A block cut off mid-way -- a child killed while writing -- is not a
  // block.
  const QString partial = chosen.left(chosen.size() / 2);
  QVERIFY(!ratchet::gui::parseRecvResult(partial).ok);
  // Nor is one whose end marker is there but whose body is cut.
  QVERIFY(!ratchet::gui::parseRecvResult(
               QString::fromLatin1(ratchet::gui_format::kBegin) +
               QStringLiteral("\nversion=1\ncommand=recv") +
               QString::fromLatin1(ratchet::gui_format::kEnd))
               .ok);

  // The parser's own limit: a block past 4096 characters is refused before
  // any field is looked at. The defect is one long line, so the block is
  // refused for its size rather than for an unknown field.
  const QString huge = QStringLiteral("version=1\ncommand=recv\nkind=text\n") +
                       QString(5000, QLatin1Char('a'));
  QVERIFY(!ratchet::gui::parseRecvResult(block(huge)).ok);

  // A long staged path is accepted.
  QString path = QStringLiteral("/tmp/") + QString(2048, QLatin1Char('a')) +
                 QStringLiteral(".png");
  QCOMPARE(path.size(), qsizetype{2057});
  accepted(block(QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                                "staged=yes\npath=") +
                 path));
  // A path past 4096 bytes cannot be exercised on its own: a block that long
  // is refused by the block-size cap first, which is the limit that bounds it.
  // The path stays absolute so the refusal is about size and not about the
  // "must start with /" check.
  const QString huge_path = QStringLiteral("/") + QString(5000, QLatin1Char('a')) +
                            QStringLiteral(".png");
  QVERIFY(!ratchet::gui::parseRecvResult(
               block(QStringLiteral("version=1\ncommand=recv\nkind=file\n"
                                    "ext=png\nstaged=yes\npath=") +
                     huge_path))
               .ok);

  // The extension field is exactly 1..16 characters.
  accepted(block(QStringLiteral("version=1\ncommand=recv\nkind=file\next=png\n"
                                "staged=no")));
  accepted(block(QStringLiteral("version=1\ncommand=recv\nkind=file\next=") +
                 QString(16, QLatin1Char('a')) + QStringLiteral("\nstaged=no")));
  QVERIFY(!ratchet::gui::parseRecvResult(
               block(QStringLiteral("version=1\ncommand=recv\nkind=file\next=") +
                     QString(17, QLatin1Char('a')) + QStringLiteral("\nstaged=no")))
               .ok);
}

QTEST_GUILESS_MAIN(GuiOutputTest)
#include "test_gui_output.moc"
