#include "main_window.hpp"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QCursor>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QStatusBar>
#include <QStyle>
#include <QTabWidget>
#include <QTemporaryFile>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <unistd.h>

#include "cli_runner.hpp"

namespace {

QGroupBox* makeGroup(const QString& title, QLayout* layout) {
  auto* box = new QGroupBox(title);
  box->setLayout(layout);
  return box;
}

// /proc/mounts escapes characters that would break its field layout.
QString unescapeOctal(const QString& field) {
  QString out;
  for (int i = 0; i < field.size(); ++i) {
    const bool triple =
        i + 3 < field.size() && field.at(i) == QLatin1Char('\\') &&
        field.at(i + 1) >= QLatin1Char('0') &&
        field.at(i + 1) <= QLatin1Char('7') &&
        field.at(i + 2) >= QLatin1Char('0') &&
        field.at(i + 2) <= QLatin1Char('7') &&
        field.at(i + 3) >= QLatin1Char('0') &&
        field.at(i + 3) <= QLatin1Char('7');
    if (triple) {
      const int value = (field.at(i + 1).unicode() - '0') * 64 +
                        (field.at(i + 2).unicode() - '0') * 8 +
                        (field.at(i + 3).unicode() - '0');
      out.append(QChar(value));
      i += 3;
    } else {
      out.append(field.at(i));
    }
  }
  return out;
}

// Mirrors ratchet::media::device_is_removable without linking ratchet_core:
// the "removable" sysfs flag on the block device, or a USB ancestry.
bool deviceIsRemovable(const QString& device) {
  const QString name = QFileInfo(device).fileName();
  if (name.isEmpty()) return false;
  const QString resolved =
      QFileInfo(QStringLiteral("/sys/class/block/") + name).canonicalFilePath();
  if (resolved.isEmpty()) return false;
  const QStringList candidates{resolved, QFileInfo(resolved).absolutePath()};
  for (const QString& candidate : candidates) {
    const QString flag = candidate + QStringLiteral("/removable");
    if (QFileInfo::exists(flag)) {
      QFile file(flag);
      if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return QString::fromLatin1(file.readLine()).trimmed() ==
               QLatin1String("1");
      }
      break;
    }
  }
  return resolved.contains(QLatin1String("/usb"));
}

// The removable drives currently mounted, the same set the CLI offers when
// --usb-path is omitted. A USB stick is usually under /run/media/<user>/<label>
// and does not show up in a file dialog's default view.
//
// /proc/mounts is read whole on purpose: it reports a size of zero, and
// QFile::atEnd() trusts that size, so a line-by-line loop would read nothing.
QStringList removableMountPoints() {
  QStringList drives;
  QFile mounts(QStringLiteral("/proc/mounts"));
  if (!mounts.open(QIODevice::ReadOnly | QIODevice::Text)) return drives;
  const QStringList lines =
      QString::fromLocal8Bit(mounts.readAll())
          .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
  for (const QString& line : lines) {
    const QStringList fields = line.split(QLatin1Char(' '));
    if (fields.size() < 3) continue;
    const QString& device = fields.at(0);
    const QString mount_point = unescapeOctal(fields.at(1));
    if (!device.startsWith(QLatin1String("/dev/"))) continue;
    if (mount_point == QLatin1String("/")) continue;
    if (!QFileInfo(mount_point).isDir()) continue;
    if (::access(mount_point.toLocal8Bit().constData(), W_OK | X_OK) != 0) {
      continue;
    }
    if (!deviceIsRemovable(device)) continue;
    if (!drives.contains(mount_point)) drives << mount_point;
  }
  return drives;
}

// A dialog that can only be dismissed through its own buttons. The title-bar
// close button and Escape are swallowed so the "Chiudi" handler always runs;
// that handler is what removes the temporary folder holding a received file.
class ConfirmOnlyDialog : public QDialog {
 public:
  explicit ConfirmOnlyDialog(QWidget* parent) : QDialog(parent) {
    setWindowFlag(Qt::WindowCloseButtonHint, false);
  }

 protected:
  void closeEvent(QCloseEvent* event) override { event->ignore(); }

  void keyPressEvent(QKeyEvent* event) override {
    if (event->key() == Qt::Key_Escape) {
      event->accept();  // ignore it instead of rejecting the dialog
      return;
    }
    QDialog::keyPressEvent(event);
  }
};

// The environment for a host program (the file manager), not for a bundled
// one. When this GUI runs from the AppImage, AppRun prepends the bundle's
// directories to LD_LIBRARY_PATH. Launching `xdg-open`/`gio` with that path
// makes them load the bundle's libglib/libgio instead of the host's, and they
// die with a symbol error before opening anything -- "Apri cartella" then does
// nothing at all. Drop every search-path entry that points inside $APPDIR and
// let the host tools resolve their own libraries.
QProcessEnvironment hostProcessEnvironment() {
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  const QString appdir = env.value(QStringLiteral("APPDIR"));
  if (appdir.isEmpty()) {
    return env;
  }
  const QStringList path_vars{
      QStringLiteral("LD_LIBRARY_PATH"),
      QStringLiteral("QT_PLUGIN_PATH"),
      QStringLiteral("QML2_IMPORT_PATH"),
      QStringLiteral("XDG_DATA_DIRS"),
  };
  for (const QString& name : path_vars) {
    if (!env.contains(name)) continue;
    QStringList kept;
    for (const QString& part :
         env.value(name).split(QLatin1Char(':'), Qt::SkipEmptyParts)) {
      if (!part.startsWith(appdir)) kept << part;
    }
    if (kept.isEmpty()) {
      env.remove(name);
    } else {
      env.insert(name, kept.join(QLatin1Char(':')));
    }
  }
  // Set by the AppImage's Qt hook on GNOME/XFCE; it should not leak to host
  // applications that happen to use Qt.
  env.remove(QStringLiteral("QT_QPA_PLATFORMTHEME"));
  return env;
}

bool startDetachedWith(const QString& program, const QStringList& arguments,
                       const QProcessEnvironment& environment) {
  QProcess process;
  process.setProcessEnvironment(environment);
  process.setProgram(program);
  process.setArguments(arguments);
  return process.startDetached();
}

}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  runner_ = new CliRunner(this);
  connect(runner_, &CliRunner::outputChunk, this, &MainWindow::onOutput);
  connect(runner_, &CliRunner::logChunk, this, &MainWindow::onLog);
  connect(runner_, &CliRunner::finished, this, &MainWindow::onFinished);
  buildUi();
  setUnlocked(false);
  if (runner_->binary().isEmpty()) {
    warn(tr("Non trovo il binario ratchet-usb.\n\n"
            "Scegli il percorso da Impostazioni > Scegli binario CLI, oppure "
            "imposta la variabile RATCHET_BIN."));
  }
}

void MainWindow::buildUi() {
  setWindowTitle(tr("Ratchet-USB"));

  auto* settings = menuBar()->addMenu(tr("Impostazioni"));
  QAction* choose_bin = settings->addAction(tr("Scegli binario CLI..."));
  connect(choose_bin, &QAction::triggered, this, &MainWindow::chooseBinary);

  auto* central = new QWidget;
  auto* root = new QVBoxLayout(central);
  root->setContentsMargins(14, 12, 14, 12);
  root->setSpacing(10);

  root->addWidget(buildAccessPanel());

  tabs_ = new QTabWidget;
  tabs_->addTab(buildVaultTab(), tr("Vault"));
  tabs_->addTab(buildContactsTab(), tr("Contatti"));
  tabs_->addTab(buildMessagesTab(), tr("Messaggi"));
  root->addWidget(tabs_, 1);

  setCentralWidget(central);

  binaryLabel_ = new QLabel;
  statusBar()->addPermanentWidget(binaryLabel_);
  const QString bin = runner_->binary();
  binaryLabel_->setText(bin.isEmpty() ? tr("CLI: non trovato")
                                      : tr("CLI: %1").arg(bin));
  statusBar()->showMessage(tr("Pronto"));
}

QWidget* MainWindow::buildAccessPanel() {
  auto* layout = new QGridLayout;
  layout->setHorizontalSpacing(8);
  layout->setVerticalSpacing(8);

  layout->addWidget(new QLabel(tr("Cartella del vault (USB):")), 0, 0);
  usbEdit_ = new QLineEdit;
  usbEdit_->setPlaceholderText(
      tr("la cartella che contiene (o conterra') vault.bin"));
  connect(usbEdit_, &QLineEdit::textChanged, this,
          &MainWindow::updateVaultPathLabel);
  layout->addWidget(usbEdit_, 0, 1);

  auto* usb_buttons = new QWidget;
  auto* usb_buttons_layout = new QHBoxLayout(usb_buttons);
  usb_buttons_layout->setContentsMargins(0, 0, 0, 0);
  usb_buttons_layout->setSpacing(6);
  auto* detect_button = new QPushButton(tr("Rileva chiavetta"));
  auto* browse_button = new QPushButton(tr("Sfoglia..."));
  connect(detect_button, &QPushButton::clicked, this,
          &MainWindow::detectUsbDrive);
  connect(browse_button, &QPushButton::clicked, this,
          &MainWindow::chooseUsbPath);
  usb_buttons_layout->addWidget(detect_button);
  usb_buttons_layout->addWidget(browse_button);
  layout->addWidget(usb_buttons, 0, 2);

  vaultPathLabel_ = new QLabel;
  vaultPathLabel_->setTextFormat(Qt::PlainText);
  vaultPathLabel_->setWordWrap(true);
  layout->addWidget(vaultPathLabel_, 1, 0, 1, 3);

  layout->addWidget(new QLabel(tr("Passphrase:")), 2, 0);
  passphraseEdit_ = new QLineEdit;
  passphraseEdit_->setEchoMode(QLineEdit::Password);
  passphraseEdit_->setPlaceholderText(
      tr("le parole della passphrase, separate da spazio"));
  connect(passphraseEdit_, &QLineEdit::returnPressed, this,
          &MainWindow::doUnlock);
  layout->addWidget(passphraseEdit_, 2, 1);

  revealButton_ = new QToolButton;
  revealButton_->setCheckable(true);
  revealButton_->setIcon(eyeIcon(false));
  revealButton_->setToolTip(tr("Mostra/nascondi la passphrase"));
  connect(revealButton_, &QToolButton::toggled, this,
          &MainWindow::togglePassphraseReveal);
  layout->addWidget(revealButton_, 2, 2);

  auto* buttons = new QHBoxLayout;
  buttons->setSpacing(8);
  unlockButton_ = new QPushButton(tr("Accedi"));
  unlockButton_->setDefault(true);
  lockButton_ = new QPushButton(tr("Blocca"));
  auto* init_button = new QPushButton(tr("Crea un nuovo vault..."));
  connect(unlockButton_, &QPushButton::clicked, this, &MainWindow::doUnlock);
  connect(lockButton_, &QPushButton::clicked, this, &MainWindow::doLock);
  connect(init_button, &QPushButton::clicked, this,
          &MainWindow::showInitDialog);
  buttons->addWidget(unlockButton_);
  buttons->addWidget(lockButton_);
  buttons->addStretch(1);
  buttons->addWidget(init_button);
  layout->addLayout(buttons, 3, 0, 1, 3);

  statusLabel_ = new QLabel;
  statusLabel_->setTextFormat(Qt::PlainText);
  layout->addWidget(statusLabel_, 4, 0, 1, 3);

  updateVaultPathLabel();
  return makeGroup(tr("Accesso al vault"), layout);
}

QWidget* MainWindow::buildVaultTab() {
  auto* tab = new QWidget;
  auto* layout = new QGridLayout(tab);
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(10);

  auto* anchor_button = new QPushButton(tr("Registra rollback anchor (anchor)"));
  auto* rekey_button = new QPushButton(tr("Cambia passphrase (passphrase)"));
  actionButtons_ << anchor_button << rekey_button;
  connect(anchor_button, &QPushButton::clicked, this,
          [this] { launchWithPassphrase(QStringLiteral("anchor"), {}, {}); });
  connect(rekey_button, &QPushButton::clicked, this,
          [this] { launchWithPassphrase(QStringLiteral("passphrase"), {}, {}, true); });

  auto* hint = new QLabel(tr(
      "anchor registra lo stato del vault nell'host per la protezione da "
      "rollback. passphrase genera una nuova passphrase (mostrata una sola "
      "volta)."));
  hint->setWordWrap(true);

  layout->addWidget(anchor_button, 0, 0);
  layout->addWidget(rekey_button, 1, 0);
  layout->addWidget(hint, 2, 0);
  layout->setRowStretch(3, 1);
  return tab;
}

QWidget* MainWindow::buildContactsTab() {
  auto* tab = new QWidget;
  auto* layout = new QVBoxLayout(tab);
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(12);

  auto* list_layout = new QGridLayout;
  auto* card_button = new QPushButton(tr("Genera card identita (card)"));
  auto* contacts_button = new QPushButton(tr("Lista contatti (contacts)"));
  auto* refresh_button = new QPushButton(tr("Aggiorna elenco contatti"));
  actionButtons_ << card_button << contacts_button << refresh_button;
  connect(card_button, &QPushButton::clicked, this,
          [this] { launchWithPassphrase(QStringLiteral("card"), {}, {}); });
  connect(contacts_button, &QPushButton::clicked, this,
          [this] { launchWithPassphrase(QStringLiteral("contacts"), {}, {}); });
  connect(refresh_button, &QPushButton::clicked, this,
          &MainWindow::refreshContacts);
  list_layout->addWidget(card_button, 0, 0);
  list_layout->addWidget(contacts_button, 0, 1);
  list_layout->addWidget(refresh_button, 1, 0, 1, 2);
  layout->addWidget(makeGroup(tr("Identita e contatti"), list_layout));

  auto* add_layout = new QGridLayout;
  addAliasEdit_ = new QLineEdit;
  addAliasEdit_->setPlaceholderText(tr("alias del contatto"));
  addCardFileEdit_ = new QLineEdit;
  addCardFileEdit_->setPlaceholderText(
      tr("file card (opzionale; altrimenti incolla sotto)"));
  auto* add_file_button = new QPushButton(tr("Da file..."));
  connect(add_file_button, &QPushButton::clicked, this,
          &MainWindow::chooseCardFile);
  addCardEdit_ = new QPlainTextEdit;
  addCardEdit_->setPlaceholderText(tr("incolla qui la card ricevuta dal contatto"));
  addCardEdit_->setMaximumHeight(100);
  auto* add_button = new QPushButton(tr("Aggiungi contatto (add)"));
  actionButtons_.append(add_button);
  connect(add_button, &QPushButton::clicked, this, [this] {
    const QString alias = addAliasEdit_->text().trimmed();
    if (alias.isEmpty()) {
      warn(tr("Serve un alias per aggiungere un contatto."));
      return;
    }
    const QString alias_arg = addAliasEdit_->text();
    QStringList flags;
    const QString file = addCardFileEdit_->text().trimmed();
    if (!file.isEmpty()) {
      flags << "--card" << file;
    } else {
      const QString staged = stageAddCardFile();
      if (staged.isEmpty()) return;
      flags << "--card" << staged;
    }
    launchWithPassphrase(QStringLiteral("add"), flags, {alias_arg});
  });
  add_layout->addWidget(new QLabel(tr("Alias:")), 0, 0);
  add_layout->addWidget(addAliasEdit_, 0, 1, 1, 2);
  add_layout->addWidget(new QLabel(tr("Card:")), 1, 0);
  add_layout->addWidget(addCardFileEdit_, 1, 1);
  add_layout->addWidget(add_file_button, 1, 2);
  add_layout->addWidget(addCardEdit_, 2, 0, 1, 3);
  add_layout->addWidget(add_button, 3, 0, 1, 3);
  layout->addWidget(makeGroup(tr("Aggiungi contatto (add)"), add_layout));

  auto* manage_layout = new QGridLayout;
  trustAliasCombo_ = makeAliasCombo(tr("alias (dalla lista)"));
  auto* trust_button = new QPushButton(tr("Segna verificato (trust)"));
  resetAliasCombo_ = makeAliasCombo(tr("alias (dalla lista)"));
  auto* reset_button = new QPushButton(tr("Azzera sessione (reset-session)"));
  actionButtons_ << trust_button << reset_button;
  connect(trust_button, &QPushButton::clicked, this, [this] {
    const QString alias = trustAliasCombo_->currentText().trimmed();
    if (alias.isEmpty()) {
      warn(tr("Serve un alias."));
      return;
    }
    launchWithPassphrase(QStringLiteral("trust"), {}, {alias});
  });
  connect(reset_button, &QPushButton::clicked, this, [this] {
    const QString alias = resetAliasCombo_->currentText().trimmed();
    if (alias.isEmpty()) {
      warn(tr("Serve un alias."));
      return;
    }
    launchWithPassphrase(QStringLiteral("reset-session"), {}, {alias});
  });
  manage_layout->addWidget(new QLabel(tr("Alias:")), 0, 0);
  manage_layout->addWidget(trustAliasCombo_, 0, 1);
  manage_layout->addWidget(trust_button, 0, 2);
  manage_layout->addWidget(new QLabel(tr("Alias:")), 1, 0);
  manage_layout->addWidget(resetAliasCombo_, 1, 1);
  manage_layout->addWidget(reset_button, 1, 2);
  layout->addWidget(makeGroup(tr("Gestione contatto"), manage_layout));
  layout->addStretch(1);
  return tab;
}

QWidget* MainWindow::buildMessagesTab() {
  auto* tab = new QWidget;
  auto* layout = new QVBoxLayout(tab);
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(12);

  auto* send_layout = new QGridLayout;
  sendAliasCombo_ = makeAliasCombo(tr("destinatario (dalla lista contatti)"));
  sendFileEdit_ = new QLineEdit;
  sendFileEdit_->setPlaceholderText(tr("file da cifrare (opzionale; --file)"));
  auto* send_file_button = new QPushButton(tr("File..."));
  connect(send_file_button, &QPushButton::clicked, this,
          &MainWindow::chooseSendFile);
  sendMessageEdit_ = new QPlainTextEdit;
  sendMessageEdit_->setPlaceholderText(tr("messaggio in chiaro da cifrare"));
  sendMessageEdit_->setMaximumHeight(100);
  auto* send_button = new QPushButton(tr("Cifra e genera blocco (send)"));
  actionButtons_.append(send_button);
  connect(send_button, &QPushButton::clicked, this, [this] {
    const QString alias = sendAliasCombo_->currentText().trimmed();
    if (alias.isEmpty()) {
      warn(tr("Serve un destinatario."));
      return;
    }
    const QString file = sendFileEdit_->text().trimmed();
    QStringList flags;
    QStringList positionals{alias};
    if (!file.isEmpty()) {
      flags << "--file" << file;
    } else {
      const QString message = sendMessageEdit_->toPlainText();
      if (message.isEmpty()) {
        warn(tr("Scrivi un messaggio oppure scegli un file."));
        return;
      }
      positionals << message;
    }
    launchWithPassphrase(QStringLiteral("send"), flags, positionals);
  });
  send_layout->addWidget(new QLabel(tr("A:")), 0, 0);
  send_layout->addWidget(sendAliasCombo_, 0, 1, 1, 2);
  send_layout->addWidget(new QLabel(tr("File:")), 1, 0);
  send_layout->addWidget(sendFileEdit_, 1, 1);
  send_layout->addWidget(send_file_button, 1, 2);
  send_layout->addWidget(sendMessageEdit_, 2, 0, 1, 3);
  send_layout->addWidget(send_button, 3, 0, 1, 3);
  layout->addWidget(makeGroup(tr("Invia (send)"), send_layout));

  auto* recv_layout = new QVBoxLayout;
  recvBlockEdit_ = new QPlainTextEdit;
  recvBlockEdit_->setPlaceholderText(tr("incolla il blocco ricevuto da decifrare"));
  recvBlockEdit_->setMaximumHeight(130);
  auto* recv_button = new QPushButton(tr("Decifra blocco (recv)"));
  actionButtons_.append(recv_button);
  connect(recv_button, &QPushButton::clicked, this, [this] {
    const QString block = recvBlockEdit_->toPlainText();
    if (block.trimmed().isEmpty()) {
      warn(tr("Incolla un blocco da decifrare."));
      return;
    }
    launchWithPassphrase(QStringLiteral("recv"), {"--stage-file"}, {block});
  });
  recv_layout->addWidget(recvBlockEdit_);
  recv_layout->addWidget(recv_button);
  layout->addWidget(makeGroup(tr("Ricevi (recv)"), recv_layout));
  layout->addStretch(1);
  return tab;
}

void MainWindow::chooseBinary() {
  const QString path = QFileDialog::getOpenFileName(
      this, tr("Seleziona il binario ratchet-usb"));
  if (path.isEmpty()) return;
  runner_->setBinary(path);
  const QString bin = runner_->binary();
  binaryLabel_->setText(bin.isEmpty() ? tr("CLI: non trovato")
                                      : tr("CLI: %1").arg(bin));
}

void MainWindow::chooseUsbPath() {
  QFileDialog dialog(this, tr("Seleziona la cartella del vault"));
  dialog.setFileMode(QFileDialog::Directory);
  dialog.setOption(QFileDialog::ShowDirsOnly, true);
  // A mounted stick lives under /run/media/<user>/<label> and is not in the
  // dialog's default view, so put the detected drives in its sidebar.
  const QStringList drives = removableMountPoints();
  if (!drives.isEmpty()) {
    QList<QUrl> urls;
    for (const QString& drive : drives) urls << QUrl::fromLocalFile(drive);
    dialog.setSidebarUrls(urls + dialog.sidebarUrls());
    dialog.setDirectory(drives.first());
  } else if (!usbPath().isEmpty()) {
    dialog.setDirectory(usbPath());
  }
  if (dialog.exec() == QDialog::Accepted && !dialog.selectedFiles().isEmpty()) {
    usbEdit_->setText(dialog.selectedFiles().first());
  }
}

void MainWindow::detectUsbDrive() {
  const QStringList drives = removableMountPoints();
  if (drives.isEmpty()) {
    warn(tr("Nessuna chiavetta rimovibile rilevata.\n\n"
            "Collega la chiavetta e riprova, oppure scegli la cartella con "
            "Sfoglia..."));
    return;
  }
  if (drives.size() == 1) {
    usbEdit_->setText(drives.first());
    statusBar()->showMessage(
        tr("Chiavetta rilevata: %1").arg(drives.first()), 6000);
    return;
  }
  QMenu menu(this);
  for (const QString& drive : drives) {
    QAction* action = menu.addAction(drive);
    connect(action, &QAction::triggered, this,
            [this, drive] { usbEdit_->setText(drive); });
  }
  menu.exec(QCursor::pos());
}

void MainWindow::chooseCardFile() {
  const QString path = QFileDialog::getOpenFileName(this, tr("Apri una card"));
  if (!path.isEmpty()) addCardFileEdit_->setText(path);
}

void MainWindow::chooseSendFile() {
  const QString path = QFileDialog::getOpenFileName(this, tr("Apri un file"));
  if (!path.isEmpty()) sendFileEdit_->setText(path);
}

void MainWindow::doUnlock() {
  if (usbPath().isEmpty()) {
    warn(tr("Scegli prima la cartella del vault (USB)."));
    return;
  }
  if (passphraseEdit_->text().trimmed().isEmpty()) {
    warn(tr("Inserisci la passphrase del vault."));
    return;
  }
  statusLabel_->setText(tr("Sblocco in corso..."));
  launchWithPassphrase(QStringLiteral("unlock"), {}, {});
}

void MainWindow::doLock() {
  setUnlocked(false);
  passphraseEdit_->clear();
  statusLabel_->setText(tr("Non connesso"));
}

void MainWindow::updateVaultPathLabel() {
  if (vaultPathLabel_ == nullptr) return;
  const QString dir = usbPath();
  if (dir.isEmpty()) {
    vaultPathLabel_->setText(tr("File del vault: (nessuna cartella scelta)"));
    return;
  }
  const QString file =
      QDir(dir).absoluteFilePath(QStringLiteral("vault.bin"));
  vaultPathLabel_->setText(tr("File del vault: %1").arg(file));
}

void MainWindow::showInitDialog() {
  if (usbPath().isEmpty()) {
    warn(tr("Scegli prima la cartella del vault (USB)."));
    return;
  }

  QDialog dialog(this);
  dialog.setWindowTitle(tr("Crea un nuovo vault"));
  auto* layout = new QVBoxLayout(&dialog);
  layout->setContentsMargins(16, 16, 16, 12);
  layout->setSpacing(10);

  auto* form = new QGridLayout;
  auto* force = new QCheckBox(tr("Sovrascrivi un vault esistente (--force)"));
  auto* from_mnemonic =
      new QCheckBox(tr("Ricostruisci da mnemonic di recupero"));
  auto* mnemonic = new QLineEdit;
  mnemonic->setPlaceholderText(tr("12 parole separate da spazio"));
  mnemonic->setEnabled(false);
  connect(from_mnemonic, &QCheckBox::toggled, mnemonic, &QLineEdit::setEnabled);
  auto* otpk = new QSpinBox;
  otpk->setRange(1, 100);
  otpk->setValue(10);
  auto* words = new QSpinBox;
  words->setRange(6, 12);
  words->setValue(6);
  form->addWidget(force, 0, 0, 1, 2);
  form->addWidget(from_mnemonic, 1, 0, 1, 2);
  form->addWidget(mnemonic, 2, 0, 1, 2);
  form->addWidget(new QLabel(tr("One-time prekeys (--otpk-count):")), 3, 0);
  form->addWidget(otpk, 3, 1);
  form->addWidget(new QLabel(tr("Parole passphrase (--passphrase-words):")), 4, 0);
  form->addWidget(words, 4, 1);
  layout->addLayout(form);

  auto* note = new QLabel(tr("Al termine la passphrase e la frase di recupero "
                             "vengono mostrate una sola volta."));
  note->setWordWrap(true);
  layout->addWidget(note);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok |
                                       QDialogButtonBox::Cancel);
  buttons->button(QDialogButtonBox::Ok)->setText(tr("Crea"));
  buttons->button(QDialogButtonBox::Cancel)->setText(tr("Annulla"));
  connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  layout->addWidget(buttons);

  if (dialog.exec() != QDialog::Accepted) return;

  QStringList flags;
  if (force->isChecked()) flags << "--force";
  flags << "--otpk-count" << QString::number(otpk->value());
  flags << "--passphrase-words" << QString::number(words->value());
  QByteArray stdin_data;
  if (from_mnemonic->isChecked()) {
    const QString m = mnemonic->text().trimmed();
    if (m.isEmpty()) {
      warn(tr("Inserisci le 12 parole del mnemonic di recupero."));
      return;
    }
    flags << "--from-mnemonic";
    stdin_data = m.toUtf8() + "\n";
  }
  launch(QStringLiteral("init"), flags, {}, stdin_data);
}

QComboBox* MainWindow::makeAliasCombo(const QString& placeholder) {
  auto* combo = new QComboBox;
  combo->setEditable(true);
  combo->setInsertPolicy(QComboBox::NoInsert);
  combo->lineEdit()->setPlaceholderText(placeholder);
  return combo;
}

void MainWindow::refreshContacts() {
  if (!unlocked_) {
    warn(tr("Sblocca prima il vault: l'elenco dei contatti e' dentro il vault."));
    return;
  }
  launchWithPassphrase(QStringLiteral("contacts"), {}, {}, false, /*silent=*/true);
}

void MainWindow::parseContacts(const QString& text) {
  // `contacts` prints one block per contact: a first line "alias [verified]
  // [session ...]" and then the fingerprint, blocks separated by blank lines.
  QStringList aliases;
  const QStringList blocks =
      text.split(QRegularExpression(QStringLiteral("\\n[ \\t]*\\n")),
                 Qt::SkipEmptyParts);
  for (const QString& block : blocks) {
    const QString first = block.section(QLatin1Char('\n'), 0, 0).trimmed();
    if (first.isEmpty() || first.startsWith(QLatin1String("No contacts"))) {
      continue;
    }
    const qsizetype cut = first.indexOf(QLatin1String(" ["));
    const QString alias = (cut >= 0 ? first.left(cut) : first).trimmed();
    if (!alias.isEmpty()) {
      aliases << alias;
    }
  }
  aliases.removeDuplicates();

  const QList<QComboBox*> combos{sendAliasCombo_, trustAliasCombo_,
                                 resetAliasCombo_};
  for (QComboBox* combo : combos) {
    if (combo == nullptr) continue;
    const QString current = combo->currentText();
    combo->clear();
    combo->addItems(aliases);
    if (!current.isEmpty()) combo->setCurrentText(current);
  }

  statusBar()->showMessage(
      aliases.isEmpty()
          ? tr("Nessun contatto nel vault.")
          : tr("Contatti disponibili: %1").arg(aliases.join(QStringLiteral(", "))),
      6000);
}

QString MainWindow::usbPath() const { return usbEdit_->text().trimmed(); }

QByteArray MainWindow::passphraseInput(bool confirm_extra_newline) const {
  const QString text = passphraseEdit_->text().trimmed();
  if (text.isEmpty()) return {};
  QByteArray data = text.toUtf8();
  // read_word_phrase accepts the phrase on one line and ends at the first empty
  // line, so a single-line field is enough. The extra newline is only for
  // `passphrase`, whose confirm_enter_or_escape reads one more key.
  data += "\n\n";
  if (confirm_extra_newline) data += "\n";
  return data;
}

QString MainWindow::stageAddCardFile() {
  stagedCard_ = std::make_unique<QTemporaryFile>(
      QDir::tempPath() + QStringLiteral("/ratchet-card-XXXXXX"));
  stagedCard_->setAutoRemove(true);
  if (!stagedCard_->open()) {
    warn(tr("Non riesco a creare un file temporaneo per la card."));
    stagedCard_.reset();
    return {};
  }
  stagedCard_->write(addCardEdit_->toPlainText().toUtf8());
  stagedCard_->flush();
  return stagedCard_->fileName();
}

bool MainWindow::launch(const QString& command, const QStringList& flags,
                        const QStringList& positionals,
                        const QByteArray& stdin_data, bool silent) {
  if (runner_->busy()) {
    warn(tr("Un comando e' gia' in esecuzione; attendi che finisca."));
    return false;
  }
  if (runner_->binary().isEmpty()) {
    warn(tr("Binario CLI non impostato.\n\n"
            "Scegli il percorso da Impostazioni > Scegli binario CLI, oppure "
            "imposta la variabile RATCHET_BIN."));
    return false;
  }
  if (usbPath().isEmpty()) {
    warn(tr("Imposta la cartella del vault prima di eseguire un comando."));
    return false;
  }

  lastCommand_ = command;
  silentCommand_ = silent;
  commandStdout_.clear();
  commandStderr_.clear();
  QStringList full;
  // Everything that starts with "-" is an option to the CLI, so the flags go
  // first and a bare "--" ends option parsing: the values after it are taken
  // verbatim, however they start. A trailing "--" with nothing after it is
  // harmless (src/cli.cpp just stops looking for options).
  full << command << "--usb-path" << usbPath() << flags << "--" << positionals;
  if (!runner_->run(full, stdin_data)) {
    stagedCard_.reset();
    return false;
  }
  setBusy(true);
  statusBar()->showMessage(tr("Esecuzione: %1...").arg(command));
  return true;
}

void MainWindow::launchWithPassphrase(const QString& command,
                                      const QStringList& flags,
                                      const QStringList& positionals,
                                      bool confirm_extra_newline,
                                      bool silent) {
  launch(command, flags, positionals, passphraseInput(confirm_extra_newline),
         silent);
}

void MainWindow::setBusy(bool busy) {
  for (QPushButton* button : actionButtons_) {
    button->setEnabled(!busy);
  }
  unlockButton_->setEnabled(!busy);
  statusBar()->showMessage(busy ? tr("Comando in esecuzione...") : tr("Pronto"));
}

void MainWindow::setUnlocked(bool unlocked) {
  unlocked_ = unlocked;
  tabs_->setEnabled(unlocked);
  lockButton_->setEnabled(unlocked);
  statusLabel_->setText(unlocked ? tr("Vault sbloccato")
                                 : tr("Non connesso"));
}

void MainWindow::onOutput(const QString& text) { commandStdout_ += text; }

void MainWindow::onLog(const QString& text) { commandStderr_ += text; }

QString MainWindow::extractError(const QString& text) const {
  const QStringList lines = text.split(QLatin1Char('\n'));
  for (const QString& line : lines) {
    if (line.trimmed().startsWith(QLatin1String("error:"))) {
      return line.trimmed();
    }
  }
  const QString trimmed = text.trimmed();
  return trimmed.isEmpty() ? tr("Nessun dettaglio disponibile.") : trimmed;
}

QString MainWindow::extractPhrase(const QString& text, const QString& heading,
                                  const QString& end_marker) const {
  const qsizetype start = text.indexOf(heading);
  if (start < 0) return {};
  qsizetype end = text.indexOf(end_marker, start);
  if (end < 0) end = text.size();
  const QString region = text.mid(start, end - start);
  static const QRegularExpression re(QStringLiteral("([0-9]+)\\.\\s+([a-z]+)"));
  QStringList words;
  auto it = re.globalMatch(region);
  while (it.hasNext()) {
    words << it.next().captured(2);
  }
  return words.join(QLatin1Char(' '));
}

QString MainWindow::commandTitle(const QString& command) const {
  if (command == QLatin1String("unlock")) return tr("Vault sbloccato");
  if (command == QLatin1String("card")) return tr("Card identita");
  if (command == QLatin1String("contacts")) return tr("Contatti");
  if (command == QLatin1String("add")) return tr("Contatto aggiunto");
  if (command == QLatin1String("trust")) return tr("Contatto verificato");
  if (command == QLatin1String("reset-session")) return tr("Sessione azzerata");
  if (command == QLatin1String("send")) return tr("Blocco cifrato");
  if (command == QLatin1String("recv")) return tr("Messaggio ricevuto");
  if (command == QLatin1String("anchor")) return tr("Rollback anchor");
  return tr("Risultato");
}

void MainWindow::showResultDialog(bool ok, const QString& title,
                                  const QString& message,
                                  const QString& detail) {
  QDialog dialog(this);
  dialog.setWindowTitle(title);
  auto* layout = new QVBoxLayout(&dialog);
  layout->setContentsMargins(16, 16, 16, 12);
  layout->setSpacing(12);

  auto* header = new QHBoxLayout;
  header->setSpacing(12);
  auto* icon = new QLabel;
  icon->setPixmap(style()
                      ->standardIcon(ok ? QStyle::SP_MessageBoxInformation
                                        : QStyle::SP_MessageBoxCritical)
                      .pixmap(32, 32));
  icon->setFixedSize(36, 36);
  icon->setAlignment(Qt::AlignTop);
  header->addWidget(icon);
  auto* msg = new QLabel(message);
  msg->setWordWrap(true);
  msg->setTextFormat(Qt::PlainText);
  msg->setAlignment(Qt::AlignTop);
  header->addWidget(msg, 1);
  layout->addLayout(header);

  QPlainTextEdit* view = nullptr;
  if (!detail.trimmed().isEmpty()) {
    view = new QPlainTextEdit(detail);
    view->setReadOnly(true);
    view->setLineWrapMode(QPlainTextEdit::NoWrap);
    view->setMinimumSize(560, 300);
    layout->addWidget(view, 1);
  }

  auto* buttons = new QHBoxLayout;
  buttons->addStretch(1);
  if (view != nullptr) {
    auto* copy = new QPushButton(tr("Copia"));
    connect(copy, &QPushButton::clicked, this, [this, view] {
      QApplication::clipboard()->setText(view->toPlainText());
      statusBar()->showMessage(tr("Copiato negli appunti."), 4000);
    });
    buttons->addWidget(copy);
  }
  auto* close = new QPushButton(tr("Chiudi"));
  close->setDefault(true);
  connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
  buttons->addWidget(close);
  layout->addLayout(buttons);

  dialog.resize(620, view != nullptr ? 440 : 190);
  dialog.exec();
}

bool MainWindow::openFolder(const QString& dir) {
  if (!QFileInfo(dir).isDir()) {
    return false;
  }
  const QProcessEnvironment env = hostProcessEnvironment();
  // xdg-open is the desktop's dispatcher; gio covers systems without
  // xdg-utils. Both run with the host's library path, not the bundle's.
  if (startDetachedWith(QStringLiteral("xdg-open"), {dir}, env)) {
    return true;
  }
  if (startDetachedWith(QStringLiteral("gio"),
                        {QStringLiteral("open"), dir}, env)) {
    return true;
  }
  // Last resort: let Qt try its own dispatch. It may route through the
  // desktop portal, which runs outside this process.
  return QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
}

void MainWindow::showFileDialog(const QString& ext, const QString& path,
                                const QString& detail) {
  ConfirmOnlyDialog dialog(this);
  dialog.setWindowTitle(tr("File ricevuto"));
  auto* layout = new QVBoxLayout(&dialog);
  layout->setContentsMargins(16, 16, 16, 12);
  layout->setSpacing(12);

  auto* header = new QHBoxLayout;
  header->setSpacing(12);
  auto* icon = new QLabel;
  icon->setPixmap(style()
                      ->standardIcon(path.isEmpty()
                                         ? QStyle::SP_MessageBoxWarning
                                         : QStyle::SP_MessageBoxInformation)
                      .pixmap(32, 32));
  icon->setFixedSize(36, 36);
  icon->setAlignment(Qt::AlignTop);
  header->addWidget(icon);

  QString message = tr("E' arrivato un file cifrato di tipo .%1.").arg(ext);
  message += QLatin1Char('\n');
  if (path.isEmpty()) {
    message += tr("Non e' stato preparato automaticamente.");
  } else {
    message += tr("Preparato in una cartella temporanea privata:\n%1").arg(path);
    message += QLatin1Char('\n');
    message += tr("La cartella viene rimossa quando chiudi questa finestra.");
  }
  auto* msg = new QLabel(message);
  msg->setWordWrap(true);
  msg->setTextFormat(Qt::PlainText);
  msg->setTextInteractionFlags(Qt::TextSelectableByMouse);
  msg->setAlignment(Qt::AlignTop);
  header->addWidget(msg, 1);
  layout->addLayout(header);

  auto* feedback = new QLabel;
  feedback->setWordWrap(true);
  feedback->setTextFormat(Qt::PlainText);
  feedback->setTextInteractionFlags(Qt::TextSelectableByMouse);
  feedback->hide();
  layout->addWidget(feedback);

  if (path.isEmpty() && !detail.trimmed().isEmpty()) {
    auto* view = new QPlainTextEdit(detail.trimmed());
    view->setReadOnly(true);
    view->setMinimumSize(520, 140);
    layout->addWidget(view, 1);
  }

  auto* buttons = new QHBoxLayout;
  buttons->addStretch(1);
  if (!path.isEmpty()) {
    auto* open = new QPushButton(tr("Apri cartella"));
    connect(open, &QPushButton::clicked, &dialog,
            [this, &dialog, path, feedback] {
              const QString dir = QFileInfo(path).absolutePath();
              if (openFolder(dir)) {
                feedback->setText(
                    tr("Cartella aperta. Premi Chiudi per rimuoverla."));
              } else {
                feedback->setText(
                    tr("Non riesco ad aprire il gestore di file. La cartella "
                       "e':\n%1").arg(dir));
                QMessageBox::warning(
                    &dialog, tr("Impossibile aprire la cartella"),
                    tr("Non e' stato possibile aprire il gestore di file.\n\n"
                       "La cartella e':\n%1\n\n"
                       "Puoi copiare questo percorso e aprirla a mano.")
                        .arg(dir));
              }
              feedback->show();
              dialog.adjustSize();
            });
    buttons->addWidget(open);
  }
  auto* close = new QPushButton(tr("Chiudi"));
  close->setDefault(true);
  connect(close, &QPushButton::clicked, &dialog, [&dialog, path] {
    if (!path.isEmpty()) {
      // The file was staged in the CLI's private ratchet-XXXXXX folder. Remove
      // that folder now, when the dialog is dismissed, rather than leaving it
      // to the CLI's background reaper. Only a directory that looks like the
      // staging folder is ever touched.
      QDir dir = QFileInfo(path).absoluteDir();
      if (dir.exists() &&
          dir.dirName().startsWith(QStringLiteral("ratchet-"))) {
        dir.removeRecursively();
      }
    }
    dialog.accept();
  });
  buttons->addWidget(close);
  layout->addLayout(buttons);

  dialog.resize(560, path.isEmpty() ? 320 : 220);
  dialog.exec();
}

void MainWindow::onFinished(int exit_code, bool normal_exit) {
  const QString command = lastCommand_;
  const bool silent = silentCommand_;
  const bool ok = normal_exit && exit_code == 0;
  stagedCard_.reset();
  setBusy(false);

  if (silent) {
    if (command == QLatin1String("contacts") && ok) {
      parseContacts(commandStdout_);
    }
    return;
  }

  if (!ok) {
    showResultDialog(false, tr("Operazione non riuscita"),
                     tr("Il comando '%1' e' fallito.").arg(command),
                     extractError(commandStderr_));
    if (command == QLatin1String("unlock")) setUnlocked(false);
    return;
  }

  if (command == QLatin1String("init")) {
    const QString pass =
        extractPhrase(commandStderr_, QStringLiteral("Vault passphrase"),
                      QStringLiteral("These words unlock"));
    const QString recovery =
        extractPhrase(commandStdout_, QStringLiteral("Recovery phrase"),
                      QStringLiteral("Write these words"));
    QString detail;
    if (!pass.isEmpty()) {
      detail += tr("Passphrase del vault (scrivile ora, non e' recuperabile):\n%1\n\n")
                    .arg(pass);
    }
    if (!recovery.isEmpty()) {
      detail += tr("Frase di recupero (12 parole):\n%1\n\n").arg(recovery);
    }
    detail += tr("--- output completo ---\n") + commandStdout_ + commandStderr_;
    showResultDialog(true, tr("Vault creato"),
                     tr("Annota passphrase e frase di recupero: sono mostrate "
                        "solo qui."),
                     detail);
    return;
  }

  if (command == QLatin1String("passphrase")) {
    const QString pass =
        extractPhrase(commandStderr_, QStringLiteral("Vault passphrase"),
                      QStringLiteral("These words unlock"));
    const QString detail =
        pass.isEmpty()
            ? commandStderr_
            : tr("Nuova passphrase del vault (mostrata una sola volta):\n%1")
                  .arg(pass);
    showResultDialog(true, tr("Passphrase cambiata"),
                     tr("La vecchia passphrase non e' piu' valida."), detail);
    return;
  }

  if (command == QLatin1String("unlock")) {
    setUnlocked(true);
    showResultDialog(true, tr("Vault sbloccato"),
                     tr("Ora puoi usare le schede Contatti e Messaggi."),
                     commandStdout_);
    refreshContacts();
    return;
  }

  if (command == QLatin1String("add")) {
    showResultDialog(true, tr("Contatto aggiunto"),
                     tr("Verifica l'impronta con la persona, fuori banda."),
                     commandStdout_);
    refreshContacts();
    return;
  }

  if (command == QLatin1String("recv")) {
    static const QRegularExpression file_re(
        QStringLiteral("\\[encrypted file received: \\.([A-Za-z0-9]+)\\]"));
    const QRegularExpressionMatch match = file_re.match(commandStderr_);
    if (match.hasMatch()) {
      showFileDialog(match.captured(1), commandStdout_.trimmed(),
                     commandStderr_);
      return;
    }
  }

  if (!commandStdout_.trimmed().isEmpty()) {
    showResultDialog(true, commandTitle(command), tr("Operazione completata."),
                     commandStdout_);
  } else {
    showResultDialog(true, commandTitle(command), tr("Operazione completata."),
                     commandStderr_);
  }
}

QIcon MainWindow::eyeIcon(bool open) const {
  const int size = 18;
  QPixmap pixmap(size, size);
  pixmap.fill(Qt::transparent);
  QPainter painter(&pixmap);
  painter.setRenderHint(QPainter::Antialiasing);
  const QColor color = palette().color(QPalette::ButtonText);
  QPen pen(color);
  pen.setWidthF(1.4);
  painter.setPen(pen);
  painter.setBrush(Qt::NoBrush);

  QPainterPath eye;
  const qreal mid = size / 2.0;
  eye.moveTo(1.5, mid);
  eye.quadTo(mid, 2.5, size - 1.5, mid);
  eye.quadTo(mid, size - 2.5, 1.5, mid);
  painter.drawPath(eye);

  painter.setBrush(color);
  painter.drawEllipse(QPointF(mid, mid), 2.6, 2.6);

  if (!open) {
    painter.setBrush(Qt::NoBrush);
    painter.drawLine(QPointF(2.5, size - 2.5), QPointF(size - 2.5, 2.5));
  }
  return QIcon(pixmap);
}

void MainWindow::togglePassphraseReveal() {
  const bool reveal = revealButton_->isChecked();
  passphraseEdit_->setEchoMode(reveal ? QLineEdit::Normal : QLineEdit::Password);
  revealButton_->setIcon(eyeIcon(reveal));
}

void MainWindow::warn(const QString& message) {
  QMessageBox::warning(this, tr("Ratchet-USB"), message);
}
