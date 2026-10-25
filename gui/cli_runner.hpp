#ifndef RATCHET_GUI_CLI_RUNNER_HPP
#define RATCHET_GUI_CLI_RUNNER_HPP

#include <QByteArray>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

// Runs the compiled ratchet-usb binary as a child process and forwards its two
// streams separately.
//
// The GUI deliberately does not link ratchet_core or re-implement any command:
// it drives the exact CLI that scripts and the tests already exercise. Keeping
// stdout and stderr apart is not cosmetic -- the vault passphrase is printed on
// stderr (a command's stdout is the payload it exists to produce), so the two
// must never be merged or the passphrase would be interleaved with a contact
// card or a message block.
class CliRunner : public QObject {
  Q_OBJECT

 public:
  explicit CliRunner(QObject* parent = nullptr);

  // Resolves the CLI to run: $RATCHET_BIN when set and executable, otherwise
  // ratchet-usb (then ratchet) next to the GUI binary, otherwise the same names
  // on PATH. Empty when nothing usable is found.
  static QString discoverBinary();

  QString binary() const { return binary_; }

  // Overrides the auto-discovered binary, e.g. after a file chooser. A path
  // that is not executable is ignored.
  void setBinary(const QString& path);

  bool busy() const { return process_.state() != QProcess::NotRunning; }

  // Starts the CLI with `args`, writes `stdin_data` to its standard input and
  // closes it. Returns false when a process is already running or the program
  // cannot be started.
  bool run(const QStringList& args, const QByteArray& stdin_data);

 signals:
  void outputChunk(const QString& text);
  void logChunk(const QString& text);
  void finished(int exit_code, bool normal_exit);

 private:
  QString binary_;
  QProcess process_;
};

#endif  // RATCHET_GUI_CLI_RUNNER_HPP
