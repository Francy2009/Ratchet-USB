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

#include "gui_output.hpp"

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
  // Multi-recipient compose: the combo picks one contact, "Aggiungi" moves
  // it into sendRecipients_, shown as one chip per recipient with a remove
  // button. One recipient sends with `send`, two or more with `group-send`.
  // The list (not a widget index) is what the send handler reads, so a
  // contact list that changed in between cannot redirect the message.
  void addSendRecipient(const QString& alias);
  void removeSendRecipient(const QString& alias);
  void syncRecipientChips();
  // Inputs are consumed by a successful command and must not linger: the
  // compose box held plaintext, and a stale recipient or block invites
  // sending the same thing twice. Failures keep everything for a retry.
  void clearPlainEdit(QPlainTextEdit* edit);
  void clearSendInputs();
  void clearAddInputs();
  void clearRecvInput();

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

  // The two steps of marking a contact verified. The first runs
  // `trust --show-fingerprint`; its output comes back through the normal child
  // reporting and leads here. The second runs `trust --confirmed`, and only
  // after the box has been ticked: the checkbox is disabled until the value is
  // on screen, so a click-through cannot confirm what nobody read.
  void showTrustDialog(const QString& alias, const QString& shown_alias,
                       const QString& fingerprint, bool have_result);
  // The value of a "key: value" line in the CLI's output, or an empty string.
  static QString aliasLine(const QString& text, const QString& key);
  // Same, for the recv block: the message body is everything before it.

  // The warnings the CLI prints about the vault it just opened: rollback
  // protection it could not check, key material it could not lock, an Argon2id
  // cost below the recommendation. Shown in the panel and in a dialog, because
  // a command that succeeded never otherwise shows its stderr.
  static QString vaultWarningsFromLog(const QString& text);
  void setVaultWarnings(const QString& warnings);

  QIcon eyeIcon(bool open) const;
  void togglePassphraseReveal();
  void warn(const QString& message);

  // The one place a command's result is shown. `detail` (when not empty) goes
  // into a scrollable read-only box with a Copy button, so a large block never
  // stretches the window.
  // `auto_close_ms` closes the dialog (wiping what it showed) after that
  // long: the TTL of an ephemeral message, enforced where it can be -- on
  // screen. It stops neither screenshots, copies nor a modified binary.
  void showResultDialog(bool ok, const QString& title, const QString& message,
                        const QString& detail, const QString& command = QString(),
                        int auto_close_ms = 0);
  QString extractError(const QString& text) const;
  QString commandTitle(const QString& command) const;

  // A received file: says what arrived and, when it was staged, offers to open
  // its folder in the file manager (the same staging ratchet-usb uses).
  // `expiry_note`/`auto_close_ms` carry the sender's expiry choice when the
  // message was ephemeral: the note is shown, and the dialog closes itself
  // (wiping what it showed) when the TTL runs out.
  void showFileDialog(const QString& ext, const QString& path,
                      const QString& detail, const QString& expiry_note = {},
                      int auto_close_ms = 0);
  // The dispatch behind both recv paths (a staged file, and a file type the
  // CLI refused to open, which exits non-zero).
  void showRecvFile(const ratchet::gui::ParsedRecvResult& parsed,
                    const QString& stderr_text);
  // Sender-chosen expiry for the *next* send only: the combo holds the TTL
  // bucket ("off" means ordinary) and the box the burn flag. Both ride in
  // argv, which is fine -- they are the sender's choice, not a secret --
  // while the message itself keeps travelling on stdin.
  QString sendTtl() const;
  bool sendBurn() const;
  // Human line for the expiry the CLI reported, or empty for an ordinary
  // message. Built from the parsed block only, never from the sender's text.
  static QString expiryNotice(const ratchet::gui::ParsedRecvResult& parsed);
  // Milliseconds the window keeps an ephemeral message on screen before
  // closing its dialog (0 for ordinary messages and burn-only ones, which
  // the user dismisses). Fits in an int even for the longest bucket.
  static int expiryTimeoutMs(const QString& ttl);

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
  QLabel* vaultWarningLabel_ = nullptr;
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
  QWidget* sendRecipientsBox_ = nullptr;  // chip container, objectName for tests
  QStringList sendRecipients_;  // the recipients the next send goes to
  QComboBox* ttlCombo_ = nullptr;  // per-message expiry: off, 1h, 24h or 7d
  QCheckBox* burnCheck_ = nullptr;  // burn after reading for the next send
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
  // Set when the running `trust` command is the --show-fingerprint step, so
  // its result opens the confirmation dialog instead of the generic one.
  bool trustFingerprintPending_ = false;
  // The alias being confirmed; the follow-up `trust --confirmed` and its
  // contact-list refresh both use it.
  QString confirmTrustedContact_;
};

#endif  // RATCHET_GUI_MAIN_WINDOW_HPP
