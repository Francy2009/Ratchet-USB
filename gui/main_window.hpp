#ifndef RATCHET_GUI_MAIN_WINDOW_HPP
#define RATCHET_GUI_MAIN_WINDOW_HPP

#include <QByteArray>
#include <QIcon>
#include <QList>
#include <QMainWindow>
#include <QString>
#include <QStringList>
#include <QTemporaryFile>

#include <memory>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTabWidget;
class QToolButton;

class CliRunner;

// A desktop front-end over the ratchet-usb CLI.
//
// Every action is a CLI invocation launched as a child process, so the
// cryptographic core, the vault format and the tests are untouched. There is no
// terminal-style output pane: a command's result comes back as a dialog that
// says whether it worked, and any payload (a card, a message block, the
// contacts list, a fingerprint) is shown in a scrollable area with a Copy
// button. The window itself stays small: unlock the vault, then the operations
// that need it are in their tabs.
class MainWindow : public QMainWindow {
  Q_OBJECT

 public:
  explicit MainWindow(QWidget* parent = nullptr);

 private:
  void buildUi();
  QWidget* buildAccessPanel();
  QWidget* buildVaultTab();
  QWidget* buildContactsTab();
  QWidget* buildMessagesTab();

  void chooseBinary();
  void chooseUsbPath();
  void detectUsbDrive();
  void chooseCardFile();
  void chooseSendFile();

  void doUnlock();
  void doLock();
  void updateVaultPathLabel();
  void showInitDialog();

  void refreshContacts();
  void parseContacts(const QString& text);
  QComboBox* makeAliasCombo(const QString& placeholder);

  // `flags` and `positionals` are kept apart on purpose. The CLI re-parses
  // anything that starts with "-" as an option, so a message, a block or an
  // alias that happens to begin with a dash would otherwise be swallowed as a
  // flag -- "-h" prints the help and exits 0, which looks like success while
  // nothing was encrypted. launch() therefore emits every flag first, then a
  // literal "--" (which src/cli.cpp honours), then the positional values.
  bool launch(const QString& command, const QStringList& flags,
              const QStringList& positionals, const QByteArray& stdin_data,
              bool silent = false);
  void launchWithPassphrase(const QString& command, const QStringList& flags,
                            const QStringList& positionals,
                            bool confirm_extra_newline = false,
                            bool silent = false);
  void setBusy(bool busy);
  void setUnlocked(bool unlocked);

  QByteArray passphraseInput(bool confirm_extra_newline) const;
  QString usbPath() const;

  void onOutput(const QString& text);
  void onLog(const QString& text);
  void onFinished(int exit_code, bool normal_exit);

  QString stageAddCardFile();

  QIcon eyeIcon(bool open) const;
  void togglePassphraseReveal();
  void warn(const QString& message);

  // The one place a command's result is shown. `detail` (when not empty) goes
  // into a scrollable read-only box with a Copy button, so a large block never
  // stretches the window.
  void showResultDialog(bool ok, const QString& title, const QString& message,
                        const QString& detail);
  QString extractPhrase(const QString& text, const QString& heading,
                        const QString& end_marker) const;
  QString extractError(const QString& text) const;
  QString commandTitle(const QString& command) const;

  // A received file: says what arrived and, when it was staged, offers to open
  // its folder in the file manager (the same staging ratchet-usb uses).
  void showFileDialog(const QString& ext, const QString& path,
                      const QString& detail);

  // Opens `dir` in the host file manager. Host programs are launched with a
  // cleaned environment so they do not load this process's bundled libraries.
  bool openFolder(const QString& dir);

  CliRunner* runner_ = nullptr;

  QLineEdit* usbEdit_ = nullptr;
  QLabel* vaultPathLabel_ = nullptr;
  QLineEdit* passphraseEdit_ = nullptr;
  QToolButton* revealButton_ = nullptr;
  QLabel* statusLabel_ = nullptr;
  QPushButton* unlockButton_ = nullptr;
  QPushButton* lockButton_ = nullptr;
  QLabel* binaryLabel_ = nullptr;

  QPlainTextEdit* addCardEdit_ = nullptr;
  QLineEdit* addCardFileEdit_ = nullptr;
  QLineEdit* addAliasEdit_ = nullptr;
  QComboBox* trustAliasCombo_ = nullptr;
  QComboBox* resetAliasCombo_ = nullptr;
  QComboBox* removeAliasCombo_ = nullptr;

  QComboBox* sendAliasCombo_ = nullptr;
  QPlainTextEdit* sendMessageEdit_ = nullptr;
  QLineEdit* sendFileEdit_ = nullptr;
  QPlainTextEdit* recvBlockEdit_ = nullptr;

  QTabWidget* tabs_ = nullptr;
  QList<QPushButton*> actionButtons_;

  std::unique_ptr<QTemporaryFile> stagedCard_;
  QString lastCommand_;
  QString commandStdout_;
  QString commandStderr_;
  bool silentCommand_ = false;
  bool unlocked_ = false;
};

#endif  // RATCHET_GUI_MAIN_WINDOW_HPP
