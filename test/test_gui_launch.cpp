#include <QtTest>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalSpy>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QTimer>

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
