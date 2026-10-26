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
class QCloseEvent;
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
  // anything that starts with "-" as an option, so an alias that happens to
  // begin with a dash would otherwise be swallowed as a flag -- "-h" prints the
  // help and exits 0, which looks like success while nothing happened. launch()
  // therefore emits every flag first, then a literal "--" (which src/cli.cpp
  // honours), then the positional values.
  //
  // Message text and received blocks are *not* passed this way: they are
  // plaintext and would be visible in /proc/<pid>/cmdline. launchWithPayload()
  // writes them to stdin instead.
  bool launch(const QString& command, const QStringList& flags,
              const QStringList& positionals, const QByteArray& stdin_data,
              bool silent = false);
  void launchWithPassphrase(const QString& command, const QStringList& flags,
                            const QStringList& positionals,
                            bool confirm_extra_newline = false,
                            bool silent = false);
  // Sends `payload` to the CLI on stdin, followed by the passphrase, and adds
  // --stdin-payload so the child knows where one ends and the other begins.
  void launchWithPayload(const QString& command, const QStringList& flags,
                         const QStringList& positionals,
                         const QByteArray& payload, bool silent = false);
  void setBusy(bool busy);
  void setUnlocked(bool unlocked);

  QByteArray passphraseInput(bool confirm_extra_newline) const;
  QString usbPath() const;

  void onOutput(const QString& text);
  void onLog(const QString& text);
  void onFinished(int exit_code, bool normal_exit);
  void handleFinished(int exit_code, bool normal_exit);

  // Drops the raw child output. Called after onFinished() has consumed it.
  void clearCommandBuffers();
  // Clears the passphrase, the child output and the staged-card file. When
  // `include_unsent_input` is true it also clears the compose and paste boxes;
  // a lock keeps those so the user can retry after unlocking, while closing
  // the window drops them too. Qt's implicit copies and its undo buffers are
  // not zeroed by clear(); see main_window.cpp for the exact limits.
  void clearSensitiveState(bool include_unsent_input);

  QString stageAddCardFile();

  QIcon eyeIcon(bool open) const;
  void togglePassphraseReveal();
  void warn(const QString& message);

  // The one place a command's result is shown. `detail` (when not empty) goes
  // into a scrollable read-only box with a Copy button, so a large block never
  // stretches the window.
  void showResultDialog(bool ok, const QString& title, const QString& message,
                        const QString& detail);
  QString extractError(const QString& text) const;
  QString commandTitle(const QString& command) const;

  // A received file: says what arrived and, when it was staged, offers to open
  // its folder in the file manager (the same staging ratchet-usb uses).
  void showFileDialog(const QString& ext, const QString& path,
                      const QString& detail);

  // Opens `dir` in the host file manager. Host programs are launched with a
  // cleaned environment so they do not load this process's bundled libraries.
  bool openFolder(const QString& dir);

 protected:
  // Drops the passphrase, the compose/paste text and the child output before
  // the window goes away.
  void closeEvent(QCloseEvent* event) override;

 private:
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
