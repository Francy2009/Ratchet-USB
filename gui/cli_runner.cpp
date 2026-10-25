#include "cli_runner.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

CliRunner::CliRunner(QObject* parent) : QObject(parent) {
  binary_ = discoverBinary();

  connect(&process_, &QProcess::readyReadStandardOutput, this, [this] {
    emit outputChunk(QString::fromLocal8Bit(process_.readAllStandardOutput()));
  });
  connect(&process_, &QProcess::readyReadStandardError, this, [this] {
    emit logChunk(QString::fromLocal8Bit(process_.readAllStandardError()));
  });
  connect(&process_,
          QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
          [this](int exit_code, QProcess::ExitStatus status) {
            emit finished(exit_code, status == QProcess::NormalExit);
          });
}

QString CliRunner::discoverBinary() {
  const QByteArray override_path = qgetenv("RATCHET_BIN");
  if (!override_path.isEmpty()) {
    const QString candidate = QString::fromLocal8Bit(override_path);
    if (QFileInfo(candidate).isExecutable()) {
      return candidate;
    }
  }

  // The install layout puts ratchet-usb in the same bin/ directory as the GUI.
  const QStringList names{QStringLiteral("ratchet-usb"), QStringLiteral("ratchet")};
  const QString app_dir = QCoreApplication::applicationDirPath();
  // "Beside the GUI" also means one level up, which is where the build tree
  // puts the CLI relative to the gui/ subdirectory holding this executable.
  const QStringList dirs{app_dir, app_dir + QStringLiteral("/..")};
  for (const QString& dir : dirs) {
    for (const QString& name : names) {
      const QString candidate = QDir(dir).absoluteFilePath(name);
      if (QFileInfo(candidate).isExecutable()) {
        return candidate;
      }
    }
  }

  for (const QString& name : names) {
    const QString found = QStandardPaths::findExecutable(name);
    if (!found.isEmpty()) {
      return found;
    }
  }
  return {};
}

void CliRunner::setBinary(const QString& path) {
  if (QFileInfo(path).isExecutable()) {
    binary_ = path;
  }
}

bool CliRunner::run(const QStringList& args, const QByteArray& stdin_data) {
  if (binary_.isEmpty() || busy()) {
    return false;
  }

  process_.setProgram(binary_);
  process_.setArguments(args);
  process_.start();
  if (!process_.waitForStarted(5000)) {
    emit logChunk(tr("impossibile avviare %1: %2\n")
                      .arg(binary_, process_.errorString()));
    return false;
  }

  if (!stdin_data.isEmpty()) {
    process_.write(stdin_data);
  }
  process_.closeWriteChannel();
  return true;
}
