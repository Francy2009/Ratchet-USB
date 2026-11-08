#include <QtTest>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QLabel>
#include <QFileInfo>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalSpy>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QTimer>
#include <QToolButton>

#include "cli_runner.hpp"
#include "main_window.hpp"

// Drives the real MainWindow against a fake CLI that records its argv and its
// stdin. This is the check that matters for the memory hardening: the message
// must reach the child as bytes on a pipe, never as a process argument that
// /proc/<pid>/cmdline exposes to every process of the same user.
//
// The fake CLI does not touch a vault. The window is put into the "unlocked"
// state by enabling the tabs directly, because this test is about the transport
// and not about unlocking; the CLI side is covered by the end-to-end smoke
// test.

namespace {

QString makeScript(const QString& directory, const QString& name,
                   const QByteArray& body) {
  const QString path = directory + QLatin1Char('/') + name;
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    return {};
  }
  if (file.write(body) != body.size()) {
    return {};
  }
  file.close();
  if (!QFile::setPermissions(
          path, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                    QFileDevice::ExeOwner)) {
    return {};
  }
  return path;
}

}  // namespace

class GuiLaunchTest : public QObject {
  Q_OBJECT

 private slots:
  void sendKeepsPlaintextOutOfArgv();
  void groupSendUsesRecipientChips();
  void successClearsConsumedInputs();
  void ephemeralSendAddsTtlFlags();
  void recvEphemeralShowsNotice();
  void recvFileDialogRemovesStagedFolderOnClose();
  void composeShowsRecipientCountAndSize();
  void passphraseUsesStructuredOutput();
  void cliRunnerReportsExitCodeAndStdin();
  void cliRunnerReportsUnexpectedTermination();
  void trustShowsFingerprintBeforeConfirming();
  void recvMarkerInAliasDoesNotOpenTheFileDialog();
};

void GuiLaunchTest::sendKeepsPlaintextOutOfArgv() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  const QString script = dir.path() + QStringLiteral("/fake-cli.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(
        "#!/bin/sh\n"
        "out=\"${RATCHET_TEST_OUT:?}\"\n"
        ": > \"$out/argv\"\n"
        "for arg in \"$@\"; do\n"
        "  printf '%s\\n' \"$arg\" >> \"$out/argv\"\n"
        "done\n"
        "cat > \"$out/stdin\"\n"
        "exit 0\n");
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));

  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));
  QVERIFY(qputenv("RATCHET_TEST_OUT", dir.path().toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* alias =
      window.findChild<QComboBox*>(QStringLiteral("sendAliasCombo"));
  auto* message =
      window.findChild<QPlainTextEdit*>(QStringLiteral("sendMessageEdit"));
  auto* send = window.findChild<QPushButton*>(QStringLiteral("sendButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(passphrase != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(alias != nullptr);
  QVERIFY(message != nullptr);
  QVERIFY(send != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  // The tabs are disabled while the window believes the vault is locked. The
  // transport does not depend on that state; enabling them keeps the test on
  // the send path without faking a whole unlock.
  tabs->setEnabled(true);
  alias->addItem(QStringLiteral("bob"));
  alias->setCurrentText(QStringLiteral("bob"));

  const QString text =
      QString::fromUtf8("città 🚀\nseconda riga\n\nultima riga");
  message->setPlainText(text);

  // onFinished shows a modal result dialog. Close whichever dialog is up so
  // the event loop can continue and the test can inspect the recorded files.
  QTimer closer;
  connect(&closer, &QTimer::timeout, [] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      modal->close();
    }
  });
  closer.start(20);

  send->click();

  QTRY_VERIFY_WITH_TIMEOUT(
      QFileInfo(dir.path() + QStringLiteral("/stdin")).exists(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(message->toPlainText().isEmpty(), 5000);
  // onFinished shows its result dialog after clearing the compose box; do not
  // leave a nested event loop running when the test function returns.
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();

  QFile argv_file(dir.path() + QStringLiteral("/argv"));
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QStringList argv = QString::fromUtf8(argv_file.readAll())
                               .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
  QVERIFY(argv.contains(QStringLiteral("send")));
  QVERIFY(argv.contains(QStringLiteral("--usb-path")));
  QVERIFY(argv.contains(QStringLiteral("--stdin-payload")));
  QVERIFY(argv.contains(QStringLiteral("bob")));
  // The plaintext, in whole or in part, must not be among the arguments.
  QVERIFY(!argv.contains(QStringLiteral("città 🚀")));
  QVERIFY(!argv.contains(QStringLiteral("seconda riga")));

  const qsizetype flag = argv.indexOf(QStringLiteral("--stdin-payload"));
  QVERIFY(flag >= 0);
  QCOMPARE(argv.at(flag + 1),
           QString::number(static_cast<qulonglong>(text.toUtf8().size())));

  QFile stdin_file(dir.path() + QStringLiteral("/stdin"));
  QVERIFY(stdin_file.open(QIODevice::ReadOnly));
  const QByteArray received = stdin_file.readAll();
  const QByteArray expected =
      text.toUtf8() + QByteArray("parola uno due\n\n");
  QCOMPARE(received, expected);
}

void GuiLaunchTest::passphraseUsesStructuredOutput() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());
  QVERIFY(qputenv("RATCHET_TEST_OUT", dir.path().toUtf8()));

  const QString script = makeScript(
      dir.path(), QStringLiteral("structured.sh"),
      QByteArray(
          "#!/bin/sh\n"
          "out=\"${RATCHET_TEST_OUT:?}\"\n"
          ": > \"$out/argv\"\n"
          "for arg in \"$@\"; do\n"
          "  printf '%s\\n' \"$arg\" >> \"$out/argv\"\n"
          "done\n"
          "cat > \"$out/stdin\"\n"
          "cat <<'EOF'\n"
          "-----BEGIN RATCHET GUI RESULT-----\n"
          "version=1\n"
          "command=passphrase\n"
          "status=ok\n"
          "passphrase_words=6\n"
          "passphrase=abandon ability able about above absent\n"
          "-----END RATCHET GUI RESULT-----\n"
          "EOF\n"
          "exit 0\n"));
  QVERIFY(!script.isEmpty());
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();
  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* rekey = window.findChild<QPushButton*>(QStringLiteral("rekeyButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(passphrase != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(rekey != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);

  QTimer closer;
  connect(&closer, &QTimer::timeout, [] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      modal->close();
    }
  });
  closer.start(20);
  rekey->click();

  QTRY_VERIFY_WITH_TIMEOUT(
      QFileInfo(dir.path() + QStringLiteral("/stdin")).exists(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(passphrase->text().isEmpty(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();

  QFile argv_file(dir.path() + QStringLiteral("/argv"));
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QStringList argv = QString::fromUtf8(argv_file.readAll())
                               .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
  QVERIFY(argv.contains(QStringLiteral("passphrase")));
  QVERIFY(argv.contains(QStringLiteral("--structured-output")));
  QVERIFY(!argv.contains(QStringLiteral("parola uno due")));

  QFile stdin_file(dir.path() + QStringLiteral("/stdin"));
  QVERIFY(stdin_file.open(QIODevice::ReadOnly));
  QCOMPARE(stdin_file.readAll(), QByteArray("parola uno due\n\n\n"));
}

void GuiLaunchTest::cliRunnerReportsExitCodeAndStdin() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());
  QVERIFY(qputenv("RATCHET_TEST_OUT", dir.path().toUtf8()));

  const QString script = makeScript(
      dir.path(), QStringLiteral("record.sh"),
      QByteArray(
          "#!/bin/sh\n"
          "out=\"${RATCHET_TEST_OUT:?}\"\n"
          ": > \"$out/argv\"\n"
          "for arg in \"$@\"; do\n"
          "  printf '%s\\n' \"$arg\" >> \"$out/argv\"\n"
          "done\n"
          "cat > \"$out/stdin\"\n"
          "exit 0\n"));
  QVERIFY(!script.isEmpty());

  CliRunner runner;
  runner.setBinary(script);
  QSignalSpy finished(&runner, &CliRunner::finished);
  const QByteArray input("input\0bytes", 11);
  QVERIFY(runner.run({QStringLiteral("one"),
                      QStringLiteral("value with spaces")},
                     input));
  QTRY_COMPARE(finished.count(), 1);
  QCOMPARE(finished.at(0).at(0).toInt(), 0);
  QCOMPARE(finished.at(0).at(1).toBool(), true);

  QFile argv_file(dir.path() + QStringLiteral("/argv"));
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QStringList argv = QString::fromUtf8(argv_file.readAll())
                               .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
  QCOMPARE(argv, (QStringList{QStringLiteral("one"),
                              QStringLiteral("value with spaces")}));

  QFile stdin_file(dir.path() + QStringLiteral("/stdin"));
  QVERIFY(stdin_file.open(QIODevice::ReadOnly));
  QCOMPARE(stdin_file.readAll(), input);
}

void GuiLaunchTest::cliRunnerReportsUnexpectedTermination() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  const QString script = makeScript(dir.path(), QStringLiteral("crash.sh"),
                                    QByteArray("#!/bin/sh\n"
                                               "kill -TERM $$\n"));
  QVERIFY(!script.isEmpty());

  CliRunner runner;
  runner.setBinary(script);
  QSignalSpy finished(&runner, &CliRunner::finished);
  QVERIFY(runner.run({}, QByteArray()));
  QTRY_COMPARE(finished.count(), 1);
  // The exit code is platform-dependent for a signal; the boolean is not.
  QCOMPARE(finished.at(0).at(1).toBool(), false);

  const QString failing = makeScript(dir.path(), QStringLiteral("fail.sh"),
                                     QByteArray("#!/bin/sh\nexit 7\n"));
  QVERIFY(!failing.isEmpty());
  CliRunner failing_runner;
  failing_runner.setBinary(failing);
  QSignalSpy failing_finished(&failing_runner, &CliRunner::finished);
  QVERIFY(failing_runner.run({}, QByteArray()));
  QTRY_COMPARE(failing_finished.count(), 1);
  QCOMPARE(failing_finished.at(0).at(0).toInt(), 7);
  QCOMPARE(failing_finished.at(0).at(1).toBool(), true);
}

void GuiLaunchTest::recvMarkerInAliasDoesNotOpenTheFileDialog() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  // A real message from a contact whose alias spells out the text the old GUI
  // searched its stderr for. The CLI escapes the alias for the terminal but
  // "[", "." and "]" are printable, so that line reaches stderr unchanged. The
  // structured block says "text", and that is what the window must believe.
  const QString marker_alias =
      QStringLiteral("mallory [encrypted file received: .sh]");
  const QString script = dir.path() + QStringLiteral("/fake-recv.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    const QByteArray body =
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$0.argv\"\n"
        "cat >/dev/null\n"
        "printf '%s: just a normal message\\n' 'mallory [encrypted file "
        "received: .sh]'\n"
        "printf '%s\\n' '-----BEGIN RATCHET GUI RESULT-----'\n"
        "printf '%s\\n' 'version=1' 'command=recv' 'kind=text'\n"
        "printf '%s\\n' '-----END RATCHET GUI RESULT-----'\n"
        "printf '%s: [encrypted file received: .sh]\\n' 'mallory [encrypted "
        "file received: .sh]' >&2\n"
        "exit 0\n";
    file.write(body);
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* block =
      window.findChild<QPlainTextEdit*>(QStringLiteral("recvBlockEdit"));
  auto* recv = window.findChild<QPushButton*>(QStringLiteral("recvButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(block != nullptr);
  QVERIFY(recv != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);
  block->setPlainText(QStringLiteral("-----BEGIN RATCHET MESSAGE-----\n...."));

  QString last_dialog;
  QTimer closer;
  connect(&closer, &QTimer::timeout, this, [&] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      last_dialog = modal->windowTitle();
      modal->close();
    }
  });
  closer.start(10);

  recv->click();
  QTRY_VERIFY_WITH_TIMEOUT(!recv->isEnabled(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(recv->isEnabled(), 10000);
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();

  // Whatever dialog was shown, it was not the received-file one: that title is
  // what the window puts on showFileDialog, and it can only be reached from a
  // parsed "kind=file".
  QVERIFY2(last_dialog != QStringLiteral("File ricevuto"),
           "an alias that spells the old marker opened the file dialog");
  QVERIFY2(!last_dialog.isEmpty(), "recv showed no dialog at all");
  (void)marker_alias;

  // The window reads the result from the structured block, so it has to ask
  // the CLI for one. Without this flag the block is never written and a
  // received file is silently never staged.
  QFile argv_file(script + QStringLiteral(".argv"));
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QString argv = QString::fromUtf8(argv_file.readAll());
  QVERIFY2(argv.contains(QStringLiteral("--structured-output")),
           "recv did not ask the CLI for the structured result block");
}

void GuiLaunchTest::groupSendUsesRecipientChips() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  const QString script = dir.path() + QStringLiteral("/fake-group.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(
        "#!/bin/sh\n"
        "out=\"${RATCHET_TEST_OUT:?}\"\n"
        ": > \"$out/argv\"\n"
        "for arg in \"$@\"; do\n"
        "  printf '%s\\n' \"$arg\" >> \"$out/argv\"\n"
        "done\n"
        "cat > \"$out/stdin\"\n"
        "exit 0\n");
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));
  QVERIFY(qputenv("RATCHET_TEST_OUT", dir.path().toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* alias = window.findChild<QComboBox*>(QStringLiteral("sendAliasCombo"));
  auto* add = window.findChild<QPushButton*>(QStringLiteral("addRecipientButton"));
  auto* chips = window.findChild<QWidget*>(QStringLiteral("sendRecipients"));
  auto* message = window.findChild<QPlainTextEdit*>(QStringLiteral("sendMessageEdit"));
  auto* send = window.findChild<QPushButton*>(QStringLiteral("sendButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(passphrase != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(alias != nullptr);
  QVERIFY(add != nullptr);
  QVERIFY(chips != nullptr);
  QVERIFY(message != nullptr);
  QVERIFY(send != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);
  alias->addItem(QStringLiteral("bob"));
  alias->addItem(QStringLiteral("carol"));

  // Chip removal is deferred (the cross deletes its own chip), so count with
  // retries: each pass lets the event loop collect the deferred deletes.
  const auto chipCount = [&] {
    return chips
        ->findChildren<QToolButton*>(
            QStringLiteral("removeRecipientButton"))
        .size();
  };
  // Two contacts become two chips; the cross on one of them takes it back.
  alias->setCurrentText(QStringLiteral("bob"));
  add->click();
  alias->setCurrentText(QStringLiteral("carol"));
  add->click();
  QTRY_COMPARE(chipCount(), 2);
  for (QToolButton* chip : chips->findChildren<QToolButton*>(
           QStringLiteral("removeRecipientButton"))) {
    if (chip->property("recipient").toString() == QStringLiteral("bob")) {
      chip->click();
    }
  }
  QTRY_COMPARE(chipCount(), 1);
  // ... and back on, so the send below really goes to two recipients.
  alias->setCurrentText(QStringLiteral("bob"));
  add->click();
  QTRY_COMPARE(chipCount(), 2);

  const QString text = QStringLiteral("ciao a tutti e due");
  message->setPlainText(text);

  QTimer closer;
  connect(&closer, &QTimer::timeout, [] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      modal->close();
    }
  });
  closer.start(20);

  send->click();
  QTRY_VERIFY_WITH_TIMEOUT(
      QFileInfo(dir.path() + QStringLiteral("/stdin")).exists(), 5000);
  // The chips and the compose box are consumed by the successful send.
  QTRY_VERIFY_WITH_TIMEOUT(
      chips->findChildren<QToolButton*>(
                QStringLiteral("removeRecipientButton"))
          .isEmpty(),
      5000);
  QTRY_VERIFY_WITH_TIMEOUT(message->toPlainText().isEmpty(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();

  QFile argv_file(dir.path() + QStringLiteral("/argv"));
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QStringList argv = QString::fromUtf8(argv_file.readAll())
                               .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
  // Two recipients take the group command, one --to each, and the message
  // still travels on stdin, never in argv.
  QCOMPARE(argv.first(), QStringLiteral("group-send"));
  QVERIFY(argv.contains(QStringLiteral("--to")));
  QVERIFY(argv.contains(QStringLiteral("bob")));
  QVERIFY(argv.contains(QStringLiteral("carol")));
  QVERIFY(!argv.contains(text));

  QFile stdin_file(dir.path() + QStringLiteral("/stdin"));
  QVERIFY(stdin_file.open(QIODevice::ReadOnly));
  QVERIFY(stdin_file.readAll().startsWith(text.toUtf8()));

  // Group files use the same recipients and expiry options, without framing a
  // text payload on stdin. The CLI loads the file after reading the passphrase.
  stdin_file.close();
  QFile::remove(dir.path() + QStringLiteral("/argv"));
  QFile::remove(dir.path() + QStringLiteral("/stdin"));
  alias->setCurrentText(QStringLiteral("bob"));
  add->click();
  alias->setCurrentText(QStringLiteral("carol"));
  add->click();
  auto* file_edit = window.findChild<QLineEdit*>(QStringLiteral("sendFileEdit"));
  auto* ttl = window.findChild<QComboBox*>(QStringLiteral("ttlCombo"));
  auto* burn = window.findChild<QCheckBox*>(QStringLiteral("burnCheck"));
  QVERIFY(file_edit != nullptr);
  QVERIFY(ttl != nullptr);
  QVERIFY(burn != nullptr);
  file_edit->setText(dir.path() + QStringLiteral("/document.pdf"));
  ttl->setCurrentIndex(ttl->findData(QStringLiteral("1h")));
  burn->setChecked(true);
  closer.start(20);
  send->click();
  QTRY_VERIFY_WITH_TIMEOUT(QFileInfo(dir.path() + QStringLiteral("/argv")).exists(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(file_edit->text().isEmpty(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();
  argv_file.close();
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QStringList file_argv = QString::fromUtf8(argv_file.readAll())
                                    .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
  QCOMPARE(file_argv.first(), QStringLiteral("group-send"));
  QCOMPARE(file_argv.count(QStringLiteral("--to")), 2);
  QVERIFY(file_argv.contains(QStringLiteral("bob")));
  QVERIFY(file_argv.contains(QStringLiteral("carol")));
  QVERIFY(file_argv.contains(QStringLiteral("--file")));
  QVERIFY(file_argv.contains(dir.path() + QStringLiteral("/document.pdf")));
  QVERIFY(file_argv.contains(QStringLiteral("--ttl")));
  QVERIFY(file_argv.contains(QStringLiteral("1h")));
  QVERIFY(file_argv.contains(QStringLiteral("--burn")));
  QVERIFY(!file_argv.contains(QStringLiteral("--stdin-payload")));
}

void GuiLaunchTest::successClearsConsumedInputs() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  const QString script = dir.path() + QStringLiteral("/fake-clear.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(
        "#!/bin/sh\n"
        "cat >/dev/null\n"
        "case \"$*\" in\n"
        "  *recv*)\n"
        "    printf '%s\\n' '-----BEGIN RATCHET GUI RESULT-----' 'version=1' "
        "'command=recv' 'kind=text' 'ttl=off' 'burn=no' "
        "'-----END RATCHET GUI RESULT-----'\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n");
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* add_alias = window.findChild<QLineEdit*>(QStringLiteral("addAliasEdit"));
  auto* add_card = window.findChild<QPlainTextEdit*>(QStringLiteral("addCardEdit"));
  auto* add = window.findChild<QPushButton*>(QStringLiteral("addContactButton"));
  auto* block = window.findChild<QPlainTextEdit*>(QStringLiteral("recvBlockEdit"));
  auto* recv = window.findChild<QPushButton*>(QStringLiteral("recvButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(passphrase != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(add_alias != nullptr);
  QVERIFY(add_card != nullptr);
  QVERIFY(add != nullptr);
  QVERIFY(block != nullptr);
  QVERIFY(recv != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);

  QTimer closer;
  connect(&closer, &QTimer::timeout, [] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      modal->close();
    }
  });
  closer.start(20);

  // A consumed add leaves neither the alias nor the pasted card behind.
  add_alias->setText(QStringLiteral("dave"));
  add_card->setPlainText(QStringLiteral("-----BEGIN RATCHET CARD-----\nfake"));
  add->click();
  QTRY_VERIFY_WITH_TIMEOUT(add_alias->text().isEmpty(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(add_card->toPlainText().isEmpty(), 5000);

  // Same for a consumed block: the next paste starts from nothing.
  block->setPlainText(QStringLiteral("-----BEGIN RATCHET MESSAGE-----\nfake"));
  recv->click();
  QTRY_VERIFY_WITH_TIMEOUT(block->toPlainText().isEmpty(), 5000);

  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();
}

void GuiLaunchTest::ephemeralSendAddsTtlFlags() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  const QString script = dir.path() + QStringLiteral("/fake-eph.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(
        "#!/bin/sh\n"
        "out=\"${RATCHET_TEST_OUT:?}\"\n"
        ": > \"$out/argv\"\n"
        "for arg in \"$@\"; do\n"
        "  printf '%s\\n' \"$arg\" >> \"$out/argv\"\n"
        "done\n"
        "cat > \"$out/stdin\"\n"
        "exit 0\n");
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));
  QVERIFY(qputenv("RATCHET_TEST_OUT", dir.path().toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* alias = window.findChild<QComboBox*>(QStringLiteral("sendAliasCombo"));
  auto* ttl = window.findChild<QComboBox*>(QStringLiteral("ttlCombo"));
  auto* burn = window.findChild<QCheckBox*>(QStringLiteral("burnCheck"));
  auto* message = window.findChild<QPlainTextEdit*>(QStringLiteral("sendMessageEdit"));
  auto* send = window.findChild<QPushButton*>(QStringLiteral("sendButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(alias != nullptr);
  QVERIFY(ttl != nullptr);
  QVERIFY(burn != nullptr);
  QVERIFY(message != nullptr);
  QVERIFY(send != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);
  alias->addItem(QStringLiteral("bob"));
  alias->setCurrentText(QStringLiteral("bob"));
  ttl->setCurrentIndex(ttl->findData(QStringLiteral("24h")));
  burn->setChecked(true);
  message->setPlainText(QStringLiteral("segreto"));

  QTimer closer;
  connect(&closer, &QTimer::timeout, [] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      modal->close();
    }
  });
  closer.start(20);

  send->click();
  QTRY_VERIFY_WITH_TIMEOUT(
      QFileInfo(dir.path() + QStringLiteral("/stdin")).exists(), 5000);
  // The retrying forms matter: only the finished signal (an event-loop
  // delivery) runs the clearing and the dialog, so plain QCOMPAREs could
  // read the widgets before the child is even reaped.
  QTRY_COMPARE(ttl->currentData().toString(), QStringLiteral("off"));
  QTRY_VERIFY(!burn->isChecked());
  // The result dialog is up by now; the closer (still running) takes it down.
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();

  QFile argv_file(dir.path() + QStringLiteral("/argv"));
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QStringList argv = QString::fromUtf8(argv_file.readAll())
                               .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
  // The buckets ride in argv (they are the sender's choice, not a secret)
  // while the message itself stays on stdin.
  QCOMPARE(argv.first(), QStringLiteral("send"));
  const int ttl_at = argv.indexOf(QStringLiteral("--ttl"));
  QVERIFY(ttl_at >= 0);
  QCOMPARE(argv.at(ttl_at + 1), QStringLiteral("24h"));
  QVERIFY(argv.contains(QStringLiteral("--burn")));
  QVERIFY(!argv.contains(QStringLiteral("segreto")));
}

void GuiLaunchTest::recvEphemeralShowsNotice() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  const QString script = dir.path() + QStringLiteral("/fake-eph-recv.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    file.write(
        "#!/bin/sh\n"
        "cat >/dev/null\n"
        "printf '%s\\n' '-----BEGIN RATCHET GUI RESULT-----' 'version=1' "
        "'command=recv' 'kind=text' 'ttl=24h' 'burn=yes' "
        "'-----END RATCHET GUI RESULT-----'\n"
        "exit 0\n");
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* block = window.findChild<QPlainTextEdit*>(QStringLiteral("recvBlockEdit"));
  auto* recv = window.findChild<QPushButton*>(QStringLiteral("recvButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(block != nullptr);
  QVERIFY(recv != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);
  block->setPlainText(QStringLiteral("-----BEGIN RATCHET MESSAGE-----\nfake"));

  // The dialog names the sender's expiry choice; only then is it closed.
  // A 24h timer never fires inside this test, so the close below is the
  // burn path: whatever the dialog showed is wiped on the way out.
  QString notice;
  QTimer closer;
  connect(&closer, &QTimer::timeout, [&] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      for (QLabel* label : modal->findChildren<QLabel*>()) {
        if (label->text().contains(QStringLiteral("effimero"))) {
          notice = label->text();
        }
      }
      modal->close();
    }
  });
  closer.start(20);

  recv->click();
  QTRY_VERIFY_WITH_TIMEOUT(!notice.isEmpty(), 5000);
  QVERIFY(notice.contains(QStringLiteral("24h")));
  QTRY_VERIFY_WITH_TIMEOUT(block->toPlainText().isEmpty(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();
}

void GuiLaunchTest::recvFileDialogRemovesStagedFolderOnClose() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  // The CLI's staging folder has this shape; the dialog is allowed to remove
  // it only when the name starts with "ratchet-".
  const QString staging =
      dir.path() + QStringLiteral("/ratchet-TEST/ratchet-file-x9.png");
  QVERIFY(QDir().mkpath(QFileInfo(staging).absolutePath()));
  {
    QFile file(staging);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write("decrypted bytes");
  }
  QVERIFY(QFileInfo(staging).exists());

  const QString script = dir.path() + QStringLiteral("/fake-recv-file.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    const QByteArray body =
        "#!/bin/sh\n"
        "cat >/dev/null\n"
        "printf '%s\\n' '-----BEGIN RATCHET GUI RESULT-----' 'version=1' "
        "'command=recv' 'kind=file' 'ext=png' 'staged=yes' "
        "'path=" + staging.toUtf8() +
        "' 'ttl=off' 'burn=no' '-----END RATCHET GUI RESULT-----'\n"
        "exit 0\n";
    file.write(body);
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* block = window.findChild<QPlainTextEdit*>(QStringLiteral("recvBlockEdit"));
  auto* recv = window.findChild<QPushButton*>(QStringLiteral("recvButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(block != nullptr);
  QVERIFY(recv != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);
  block->setPlainText(QStringLiteral("-----BEGIN RATCHET MESSAGE-----\nfake"));

  // The file dialog is a ConfirmOnlyDialog: it ignores close() and Escape on
  // purpose, so the only way out is Chiudi or the ephemeral timer's accept().
  // accept() is what the timer calls, so this exercises the same finished()
  // path that must remove the staged folder.
  QTimer closer;
  connect(&closer, &QTimer::timeout, [] {
    if (auto* dialog =
            qobject_cast<QDialog*>(QApplication::activeModalWidget())) {
      dialog->accept();
    }
  });
  closer.start(20);

  recv->click();
  QTRY_VERIFY_WITH_TIMEOUT(!QFileInfo(staging).exists(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  closer.stop();
}

void GuiLaunchTest::composeShowsRecipientCountAndSize() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  // The window warns -- with a modal dialog -- from its constructor when it
  // cannot find the CLI, so RATCHET_BIN has to point somewhere valid before
  // the window exists. The CI job builds only the test targets, so relying on
  // an installed ratchet-usb would hang here instead of failing.
  const QString script = makeScript(dir.path(), QStringLiteral("fake-cli.sh"),
                                    "#!/bin/sh\ncat >/dev/null\nexit 0\n");
  QVERIFY(!script.isEmpty());
  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));

  // A closer from the start: any unexpected warning dialog is closed instead
  // of hanging the test until the watchdog fires, and the assertions below
  // turn it into a readable failure. It has to be running before the window
  // is constructed for the same reason as above.
  QTimer closer;
  connect(&closer, &QTimer::timeout, [] {
    if (QWidget* modal = QApplication::activeModalWidget()) {
      modal->close();
    }
  });
  closer.start(20);

  MainWindow window;
  window.show();

  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* alias = window.findChild<QComboBox*>(QStringLiteral("sendAliasCombo"));
  auto* add = window.findChild<QPushButton*>(QStringLiteral("addRecipientButton"));
  auto* message = window.findChild<QPlainTextEdit*>(QStringLiteral("sendMessageEdit"));
  auto* count = window.findChild<QLabel*>(QStringLiteral("recipientCountLabel"));
  auto* size = window.findChild<QLabel*>(QStringLiteral("messageSizeLabel"));
  QVERIFY(tabs != nullptr);
  QVERIFY(alias != nullptr);
  QVERIFY(add != nullptr);
  QVERIFY(message != nullptr);
  QVERIFY(count != nullptr);
  QVERIFY(size != nullptr);
  tabs->setEnabled(true);

  // No chips: the combo is the single recipient.
  QVERIFY(count->text().contains(QStringLiteral("tendina")));
  message->setPlainText(QStringLiteral("ciao"));
  QTRY_COMPARE(size->text(), QStringLiteral("4 / 4194304 byte"));

  // Two chips: the compose box says group. The current text is asserted
  // before each click so a combo that did not take the value fails here
  // instead of hanging inside a warning dialog.
  alias->addItem(QStringLiteral("bob"));
  alias->addItem(QStringLiteral("carol"));
  alias->setCurrentText(QStringLiteral("bob"));
  QCOMPARE(alias->currentText(), QStringLiteral("bob"));
  add->click();
  alias->setCurrentText(QStringLiteral("carol"));
  QCOMPARE(alias->currentText(), QStringLiteral("carol"));
  add->click();
  QTRY_VERIFY(count->text().contains(QStringLiteral("2")));
  QVERIFY(count->text().contains(QStringLiteral("gruppo")));
  closer.stop();
}

QTEST_MAIN(GuiLaunchTest)
#include "test_gui_launch.moc"

void GuiLaunchTest::trustShowsFingerprintBeforeConfirming() {
  QTemporaryDir dir;
  QVERIFY(dir.isValid());

  const QString script = dir.path() + QStringLiteral("/fake-trust.sh");
  {
    QFile file(script);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    // Record every argv, then answer the two-step trust protocol. The
    // fingerprint is fixed text so the test knows what the dialog must show.
    file.write(
        "#!/bin/sh\n"
        "out=\"${RATCHET_TEST_OUT:?}\"\n"
        "printf '%s\\n' \"$*\" >> \"$out/argv\"\n"
        "case \"$*\" in\n"
        "  *--show-fingerprint*)\n"
        "    printf 'alias: bob\\nfingerprint: aaaa bbbb cccc dddd\\n"
        "verified: no\\n'\n"
        "    ;;\n"
        "esac\n"
        "cat >/dev/null\n"
        "exit 0\n");
    file.close();
  }
  QVERIFY(QFile::setPermissions(
      script, QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                  QFileDevice::ExeOwner));

  QVERIFY(qputenv("RATCHET_BIN", script.toUtf8()));
  QVERIFY(qputenv("RATCHET_TEST_OUT", dir.path().toUtf8()));

  const QString usb = dir.path() + QStringLiteral("/usb");
  QVERIFY(QDir().mkpath(usb));

  MainWindow window;
  window.show();

  auto* usb_edit = window.findChild<QLineEdit*>(QStringLiteral("usbPathEdit"));
  auto* passphrase =
      window.findChild<QLineEdit*>(QStringLiteral("passphraseEdit"));
  auto* tabs = window.findChild<QTabWidget*>(QStringLiteral("tabs"));
  auto* alias = window.findChild<QComboBox*>(QStringLiteral("trustAliasCombo"));
  auto* trust = window.findChild<QPushButton*>(QStringLiteral("trustButton"));
  QVERIFY(usb_edit != nullptr);
  QVERIFY(passphrase != nullptr);
  QVERIFY(tabs != nullptr);
  QVERIFY(alias != nullptr);
  QVERIFY(trust != nullptr);

  usb_edit->setText(usb);
  passphrase->setText(QStringLiteral("parola uno due"));
  tabs->setEnabled(true);
  alias->addItem(QStringLiteral("bob"));
  alias->setCurrentText(QStringLiteral("bob"));

  // The confirm dialog is modal and needs a person, so the timer acts as one:
  // it checks that the OK button stays disabled until the confirmation box is
  // ticked, that ticking it enables the button, and that the fingerprint on
  // screen is the one the CLI printed. Any other dialog is closed so the
  // command can finish.
  QTimer dialog_driver;
  bool saw_fingerprint = false;
  bool ok_disabled_before_tick = false;
  bool ok_enabled_after_tick = false;
  connect(&dialog_driver, &QTimer::timeout, this, [&] {
    QWidget* modal = QApplication::activeModalWidget();
    if (modal == nullptr) {
      return;
    }
    auto* view =
        modal->findChild<QPlainTextEdit*>(QStringLiteral("trustFingerprint"));
    auto* consent = modal->findChild<QCheckBox*>(QStringLiteral("trustConsent"));
    auto* ok = modal->findChild<QPushButton*>(
        QStringLiteral("trustConfirmButton"));
    if (view != nullptr && consent != nullptr && ok != nullptr) {
      saw_fingerprint = view->toPlainText().contains(
          QStringLiteral("aaaa bbbb cccc dddd"));
      ok_disabled_before_tick = !ok->isEnabled();
      consent->setChecked(true);
      ok_enabled_after_tick = ok->isEnabled();
      ok->click();
      return;
    }
    modal->close();
  });
  dialog_driver.start(10);

  trust->click();

  // Two invocations: the fingerprint step, then the confirmed one.
  QTRY_VERIFY_WITH_TIMEOUT(
      QFileInfo(dir.path() + QStringLiteral("/argv")).exists(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(!trust->isEnabled(), 5000);
  QTRY_VERIFY_WITH_TIMEOUT(trust->isEnabled(), 10000);
  QTRY_VERIFY_WITH_TIMEOUT(QApplication::activeModalWidget() == nullptr, 5000);
  dialog_driver.stop();

  QVERIFY2(saw_fingerprint, "the dialog did not show the CLI's fingerprint");
  QVERIFY2(ok_disabled_before_tick,
           "confirm was possible before the box was ticked");
  QVERIFY2(ok_enabled_after_tick,
           "ticking the box did not enable the confirmation");

  QFile argv_file(dir.path() + QStringLiteral("/argv"));
  QVERIFY(argv_file.open(QIODevice::ReadOnly));
  const QStringList lines =
      QString::fromUtf8(argv_file.readAll()).split(QLatin1Char('\n'),
                                                   Qt::SkipEmptyParts);
  QCOMPARE(lines.size(), qsizetype{2});
  QVERIFY(lines.at(0).contains(QStringLiteral("trust")));
  QVERIFY(lines.at(0).contains(QStringLiteral("--show-fingerprint")));
  QVERIFY(!lines.at(0).contains(QStringLiteral("--confirmed")));
  QVERIFY(lines.at(1).contains(QStringLiteral("--confirmed")));
  QVERIFY(!lines.at(1).contains(QStringLiteral("--show-fingerprint")));
}
