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
#include <QFrame>
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
#include <QScrollArea>
#include <QSpinBox>
#include <QStatusBar>
#include <QTimer>
#include <QStyle>
#include <QTabWidget>
#include <QTemporaryFile>
#include <QTextDocument>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <unistd.h>

#include "cli_runner.hpp"
#include "gui_output.hpp"
#include "host_env.hpp"
#include "payload_input.hpp"
#include "ratchet/gui_format.hpp"

namespace {

QGroupBox* makeGroup(const QString& title, QLayout* layout) {
  auto* box = new QGroupBox(title);
  box->setLayout(layout);
  return box;
}

// A tab can be taller than the window. Without a scroll area the controls at
// the bottom are laid out past the visible edge and there is no way to reach
// them (the contact-removal block sat under "Azzera sessione").
QWidget* scrollable(QWidget* content) {
  auto* area = new QScrollArea;
  area->setWidgetResizable(true);
  area->setFrameShape(QFrame::NoFrame);
  area->setWidget(content);
  return area;
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
  // Object names are for the headless GUI test: it drives the real widgets
  // instead of duplicating the launch logic.
  tabs_->setObjectName(QStringLiteral("tabs"));
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
  usbEdit_->setObjectName(QStringLiteral("usbPathEdit"));
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
  passphraseEdit_->setObjectName(QStringLiteral("passphraseEdit"));
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
  unlockButton_->setObjectName(QStringLiteral("unlockButton"));
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

  // What the CLI said about the vault state it just opened: rollback
  // protection it could not check, key material it could not lock into RAM, an
  // Argon2id cost below the recommendation. The CLI writes these on stderr so
  // a script sees them too; without this line they would reach only the dialog
  // shown for a failed command, which never appears for a command that
  // succeeded -- and an unlock that succeeded is exactly when they matter.
  vaultWarningLabel_ = new QLabel;
  vaultWarningLabel_->setObjectName(QStringLiteral("vaultWarningLabel"));
  vaultWarningLabel_->setTextFormat(Qt::PlainText);
  vaultWarningLabel_->setWordWrap(true);
  vaultWarningLabel_->setStyleSheet(
      QStringLiteral("QLabel { color: #a04000; }"));
  vaultWarningLabel_->hide();
  layout->addWidget(vaultWarningLabel_, 4, 0, 1, 3);

  statusLabel_ = new QLabel;
  statusLabel_->setTextFormat(Qt::PlainText);
  layout->addWidget(statusLabel_, 5, 0, 1, 3);

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
  rekey_button->setObjectName(QStringLiteral("rekeyButton"));
  actionButtons_ << anchor_button << rekey_button;
  connect(anchor_button, &QPushButton::clicked, this,
          [this] { launchWithPassphrase(QStringLiteral("anchor"), {}, {}); });
  connect(rekey_button, &QPushButton::clicked, this, [this] {
    launchWithPassphrase(QStringLiteral("passphrase"),
                         {QStringLiteral("--structured-output")}, {}, true);
  });

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
  addAliasEdit_->setObjectName(QStringLiteral("addAliasEdit"));
  addAliasEdit_->setPlaceholderText(tr("alias del contatto"));
  addCardFileEdit_ = new QLineEdit;
  addCardFileEdit_->setObjectName(QStringLiteral("addCardFileEdit"));
  addCardFileEdit_->setPlaceholderText(
      tr("file card (opzionale; altrimenti incolla sotto)"));
  auto* add_file_button = new QPushButton(tr("Da file..."));
  connect(add_file_button, &QPushButton::clicked, this,
          &MainWindow::chooseCardFile);
  addCardEdit_ = new QPlainTextEdit;
  addCardEdit_->setObjectName(QStringLiteral("addCardEdit"));
  addCardEdit_->setPlaceholderText(tr("incolla qui la card ricevuta dal contatto"));
  addCardEdit_->setMaximumHeight(100);
  auto* add_button = new QPushButton(tr("Aggiungi contatto (add)"));
  add_button->setObjectName(QStringLiteral("addContactButton"));
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
  trustAliasCombo_->setObjectName(QStringLiteral("trustAliasCombo"));
  auto* trust_button = new QPushButton(tr("Segna verificato (trust)"));
  trust_button->setObjectName(QStringLiteral("trustButton"));
  resetAliasCombo_ = makeAliasCombo(tr("alias (dalla lista)"));
  auto* reset_button = new QPushButton(tr("Azzera sessione (reset-session)"));
  actionButtons_ << trust_button << reset_button;
  connect(trust_button, &QPushButton::clicked, this, [this] {
    const QString alias = trustAliasCombo_->currentText().trimmed();
    if (alias.isEmpty()) {
      warn(tr("Serve un alias."));
      return;
    }
    // Marking a contact verified is what lets the vault accept their
    // messages, so it is never one click. Step one asks the CLI for the
    // fingerprint (it is the CLI that reads the vault), step two shows that
    // value next to the one to compare and waits for an explicit yes. Only
    // then does trust run, with --confirmed in place of the terminal
    // confirmation.
    confirmTrustedContact_ = alias;
    launchWithPassphrase(QStringLiteral("trust"),
                         {QStringLiteral("--show-fingerprint")}, {alias});
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

  auto* remove_layout = new QGridLayout;
  removeAliasCombo_ = makeAliasCombo(tr("alias (dalla lista)"));
  auto* remove_button = new QPushButton(tr("Rimuovi contatto (remove)"));
  actionButtons_ << remove_button;
  connect(remove_button, &QPushButton::clicked, this, [this] {
    const QString alias = removeAliasCombo_->currentText().trimmed();
    if (alias.isEmpty()) {
      warn(tr("Serve un alias."));
      return;
    }
    const auto answer = QMessageBox::warning(
        this, tr("Eliminare il contatto?"),
        tr("Eliminare '%1'?\n\n"
           "Verranno cancellati il contatto e la sua sessione, comprese le "
           "chiavi del ratchet. L'operazione non si puo' annullare: per "
           "riscrivervi servira' una nuova carta.").arg(alias),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (answer != QMessageBox::Yes) return;
    launchWithPassphrase(QStringLiteral("remove"),
                         {QStringLiteral("--yes")}, {alias});
  });
  remove_layout->addWidget(new QLabel(tr("Alias:")), 0, 0);
  remove_layout->addWidget(removeAliasCombo_, 0, 1);
  remove_layout->addWidget(remove_button, 0, 2);
  layout->addWidget(makeGroup(tr("Rimuovi contatto (remove)"), remove_layout));
  layout->addStretch(1);
  return scrollable(tab);
}

QWidget* MainWindow::buildMessagesTab() {
  auto* tab = new QWidget;
  auto* layout = new QVBoxLayout(tab);
  layout->setContentsMargins(14, 14, 14, 14);
  layout->setSpacing(12);

  auto* send_layout = new QGridLayout;
  sendAliasCombo_ = makeAliasCombo(tr("destinatario (dalla lista contatti)"));
  sendAliasCombo_->setObjectName(QStringLiteral("sendAliasCombo"));
  auto* add_recipient_button = new QPushButton(tr("Aggiungi"));
  add_recipient_button->setObjectName(QStringLiteral("addRecipientButton"));
  add_recipient_button->setToolTip(
      tr("Aggiunge il destinatario ai selezionati (per un messaggio di gruppo)"));
  connect(add_recipient_button, &QPushButton::clicked, this, [this] {
    addSendRecipient(sendAliasCombo_->currentText());
  });
  sendRecipientsBox_ = new QWidget;
  sendRecipientsBox_->setObjectName(QStringLiteral("sendRecipients"));
  {
    auto* chips_layout = new QHBoxLayout(sendRecipientsBox_);
    chips_layout->setContentsMargins(0, 0, 0, 0);
    chips_layout->setSpacing(6);
  }
  auto* recipients_scroll = new QScrollArea;
  recipients_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
  recipients_scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  recipients_scroll->setWidgetResizable(true);
  recipients_scroll->setWidget(sendRecipientsBox_);
  recipients_scroll->setFixedHeight(52);
  sendFileEdit_ = new QLineEdit;
  sendFileEdit_->setObjectName(QStringLiteral("sendFileEdit"));
  sendFileEdit_->setPlaceholderText(tr("file da cifrare (opzionale; --file, solo 1 destinatario)"));
  auto* send_file_button = new QPushButton(tr("File..."));
  connect(send_file_button, &QPushButton::clicked, this,
          &MainWindow::chooseSendFile);
  sendMessageEdit_ = new QPlainTextEdit;
  sendMessageEdit_->setObjectName(QStringLiteral("sendMessageEdit"));
  sendMessageEdit_->setPlaceholderText(tr("messaggio in chiaro da cifrare"));
  sendMessageEdit_->setMaximumHeight(100);
  auto* send_button = new QPushButton(tr("Cifra e genera blocco (send / group-send)"));
  send_button->setObjectName(QStringLiteral("sendButton"));
  actionButtons_.append(send_button);
  connect(send_button, &QPushButton::clicked, this, [this] {
    // The chips are the recipients; when none was added, the combo itself is
    // the single recipient, so the old one-contact flow is unchanged.
    QStringList recipients = sendRecipients_;
    if (recipients.isEmpty()) {
      const QString alias = sendAliasCombo_->currentText().trimmed();
      if (alias.isEmpty()) {
        warn(tr("Serve un destinatario: sceglilo e premi Aggiungi, oppure "
                "lascialo nella tendina per un messaggio singolo."));
        return;
      }
      recipients << alias;
    }
    recipients.removeDuplicates();
    const QString file = sendFileEdit_->text().trimmed();
    // The expiry rides inside the encrypted plaintext (see ephemeral.hpp);
    // the flags only name the bucket, which is the sender's choice and no
    // secret, while the message itself keeps travelling on stdin.
    QStringList expiry_flags;
    const QString ttl = sendTtl();
    if (ttl != QStringLiteral("off")) {
      expiry_flags << "--ttl" << ttl;
    }
    if (sendBurn()) {
      expiry_flags << "--burn";
    }
    if (recipients.size() == 1) {
      QStringList flags = expiry_flags;
      const QStringList positionals{recipients.first()};
      if (!file.isEmpty()) {
        flags << "--file" << file;
        launchWithPassphrase(QStringLiteral("send"), flags, positionals);
      } else {
        const QString message = sendMessageEdit_->toPlainText();
        if (message.isEmpty()) {
          warn(tr("Scrivi un messaggio oppure scegli un file."));
          return;
        }
        // The plaintext never enters argv (readable in /proc by every process
        // of this user); it goes on stdin, before the passphrase, framed by
        // its byte count.
        QByteArray payload = message.toUtf8();
        launchWithPayload(QStringLiteral("send"), flags, positionals, payload);
        ratchet::gui::wipeByteArray(payload);
      }
      return;
    }
    // group-send wraps one content key per member through the existing 1:1
    // sessions; the CLI refuses the send when a recipient is unknown or the
    // session cannot move, and nothing is committed before that.
    if (!file.isEmpty()) {
      warn(tr("I messaggi di gruppo accettano solo testo: togli il file "
              "oppure manda a un destinatario alla volta."));
      return;
    }
    const QString message = sendMessageEdit_->toPlainText();
    if (message.isEmpty()) {
      warn(tr("Scrivi un messaggio per il gruppo."));
      return;
    }
    QStringList flags = expiry_flags;
    for (const QString& recipient : recipients) {
      flags << "--to" << recipient;
    }
    QByteArray payload = message.toUtf8();
    launchWithPayload(QStringLiteral("group-send"), flags, {}, payload);
    ratchet::gui::wipeByteArray(payload);
  });
  // A per-message choice, not a setting: the selector goes back to "off"
  // after every successful send (see clearSendInputs), so the next message
  // is ordinary unless the sender says otherwise. The buckets are coarse on
  // purpose -- a free-form duration would fingerprint the message.
  ttlCombo_ = new QComboBox;
  ttlCombo_->setObjectName(QStringLiteral("ttlCombo"));
  ttlCombo_->addItem(tr("Nessuna scadenza"), QStringLiteral("off"));
  ttlCombo_->addItem(tr("1 ora"), QStringLiteral("1h"));
  ttlCombo_->addItem(tr("24 ore"), QStringLiteral("24h"));
  ttlCombo_->addItem(tr("7 giorni"), QStringLiteral("7d"));
  burnCheck_ = new QCheckBox(tr("Distruggi dopo lettura"));
  burnCheck_->setObjectName(QStringLiteral("burnCheck"));
  burnCheck_->setToolTip(
      tr("Il destinatario vede il messaggio una volta sola; chiuderlo lo cancella."));
  send_layout->addWidget(new QLabel(tr("A:")), 0, 0);
  send_layout->addWidget(sendAliasCombo_, 0, 1);
  send_layout->addWidget(add_recipient_button, 0, 2);
  send_layout->addWidget(new QLabel(tr("Destinatari:")), 1, 0);
  send_layout->addWidget(recipients_scroll, 1, 1, 1, 2);
  send_layout->addWidget(new QLabel(tr("Scadenza:")), 2, 0);
  send_layout->addWidget(ttlCombo_, 2, 1);
  send_layout->addWidget(burnCheck_, 2, 2);
  send_layout->addWidget(new QLabel(tr("File:")), 3, 0);
  send_layout->addWidget(sendFileEdit_, 3, 1);
  send_layout->addWidget(send_file_button, 3, 2);
  send_layout->addWidget(sendMessageEdit_, 4, 0, 1, 3);
  send_layout->addWidget(send_button, 5, 0, 1, 3);
  layout->addWidget(makeGroup(tr("Invia (send / group-send)"), send_layout));
  syncRecipientChips();

  auto* recv_layout = new QVBoxLayout;
  recvBlockEdit_ = new QPlainTextEdit;
  recvBlockEdit_->setObjectName(QStringLiteral("recvBlockEdit"));
  recvBlockEdit_->setPlaceholderText(tr("incolla il blocco ricevuto da decifrare"));
  recvBlockEdit_->setMaximumHeight(130);
  auto* recv_button = new QPushButton(tr("Decifra blocco (recv)"));
  recv_button->setObjectName(QStringLiteral("recvButton"));
  actionButtons_.append(recv_button);
  connect(recv_button, &QPushButton::clicked, this, [this] {
    const QString block = recvBlockEdit_->toPlainText();
    if (block.trimmed().isEmpty()) {
      warn(tr("Incolla un blocco da decifrare."));
      return;
    }
    // The block is ciphertext, not plaintext, but it can be large and there is
    // no reason to put it in argv either. The same stdin framing keeps the
    // passphrase and the block on separate, length-delimited parts of the
    // stream.
    QByteArray payload = block.toUtf8();
    // --structured-output is what makes the CLI append the block that says
    // whether what arrived was a file and where it was staged; without it
    // parseRecvResult has nothing to read and a received file is never offered.
    launchWithPayload(QStringLiteral("recv"),
                      {"--stage-file", "--structured-output"}, {}, payload);
    ratchet::gui::wipeByteArray(payload);
  });
  recv_layout->addWidget(recvBlockEdit_);
  recv_layout->addWidget(recv_button);
  layout->addWidget(makeGroup(tr("Ricevi (recv)"), recv_layout));
  layout->addStretch(1);
  return scrollable(tab);
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
  // A lock drops the passphrase and everything the CLI printed, including a
  // decrypted message or a generated phrase. Unsent compose text and a pasted
  // ciphertext block are kept: they are the user's input, not vault output, and
  // dropping them would make a retry after unlocking start from nothing.
  clearSensitiveState(/*include_unsent_input=*/false);
  // The warning described the vault that was open. Leaving it on screen next to
  // "Non connesso" would report a state that no longer exists.
  setVaultWarnings(QString());
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
  words->setValue(12);
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
    // The line edit and the local `m` are Qt strings: clear() releases the
    // visible copy, but Qt's implicit sharing and its own buffers are not
    // zeroed by anything this code can call.
    mnemonic->clear();
  }
  flags << QStringLiteral("--structured-output");
  launch(QStringLiteral("init"), flags, {}, stdin_data);
  ratchet::gui::wipeByteArray(stdin_data);
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
                                 resetAliasCombo_, removeAliasCombo_};
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

  // A contact list that changed since the recipients were picked must not
  // silently redirect a group message: drop whoever is gone. The CLI would
  // refuse the unknown alias anyway; this keeps the chips honest before that.
  QStringList pruned;
  for (auto it = sendRecipients_.begin(); it != sendRecipients_.end();) {
    if (!aliases.contains(*it)) {
      pruned << *it;
      it = sendRecipients_.erase(it);
    } else {
      ++it;
    }
  }
  if (!pruned.isEmpty()) {
    syncRecipientChips();
    statusBar()->showMessage(
        tr("Rimossi dai destinatari (non piu' nei contatti): %1")
            .arg(pruned.join(QStringLiteral(", "))),
        6000);
  }
}

void MainWindow::addSendRecipient(const QString& alias) {
  const QString name = alias.trimmed();
  if (name.isEmpty()) {
    warn(tr("Scegli un destinatario dalla lista e premi Aggiungi."));
    return;
  }
  if (sendRecipients_.contains(name)) {
    warn(tr("'%1' e' gia' tra i destinatari.").arg(name));
    return;
  }
  sendRecipients_ << name;
  syncRecipientChips();
  // The combo fed the chip; clearing it invites picking the next contact
  // instead of adding the same one twice.
  if (sendAliasCombo_ != nullptr && sendAliasCombo_->lineEdit() != nullptr) {
    sendAliasCombo_->lineEdit()->clear();
  }
}

void MainWindow::removeSendRecipient(const QString& alias) {
  sendRecipients_.removeAll(alias);
  syncRecipientChips();
}

void MainWindow::syncRecipientChips() {
  if (sendRecipientsBox_ == nullptr) return;
  if (QLayout* layout = sendRecipientsBox_->layout()) {
    while (QLayoutItem* item = layout->takeAt(0)) {
      if (QWidget* widget = item->widget()) {
        // Hide at once so a removed chip never lingers a frame; the deletion
        // itself stays deferred because this can run from the chip's own
        // remove button.
        widget->hide();
        widget->deleteLater();
      }
      delete item;
    }
    // An empty list reads as empty on purpose: the placeholder says where
    // the recipients go, so no chip means no recipient.
    if (sendRecipients_.isEmpty()) {
      auto* hint = new QLabel(tr("nessun destinatario (la tendina vale come singolo)"));
      hint->setEnabled(false);
      layout->addWidget(hint);
    }
    for (const QString& recipient : sendRecipients_) {
      auto* chip = new QFrame;
      chip->setFrameStyle(QFrame::StyledPanel);
      auto* chip_layout = new QHBoxLayout(chip);
      chip_layout->setContentsMargins(8, 2, 2, 2);
      chip_layout->setSpacing(4);
      auto* label = new QLabel(recipient);
      label->setTextFormat(Qt::PlainText);
      chip_layout->addWidget(label);
      auto* remove = new QToolButton;
      remove->setObjectName(QStringLiteral("removeRecipientButton"));
      remove->setText(QStringLiteral("\u00d7"));
      remove->setToolTip(tr("Togli '%1' dai destinatari").arg(recipient));
      remove->setProperty("recipient", recipient);
      connect(remove, &QToolButton::clicked, this,
              [this, recipient] { removeSendRecipient(recipient); });
      chip_layout->addWidget(remove);
      layout->addWidget(chip);
    }
    static_cast<QHBoxLayout*>(layout)->addStretch(1);
  }
}

QString MainWindow::sendTtl() const {
  if (ttlCombo_ == nullptr) return QStringLiteral("off");
  const QString ttl = ttlCombo_->currentData().toString();
  return ttl.isEmpty() ? QStringLiteral("off") : ttl;
}

bool MainWindow::sendBurn() const {
  return burnCheck_ != nullptr && burnCheck_->isChecked();
}

QString MainWindow::expiryNotice(
    const ratchet::gui::ParsedRecvResult& parsed) {
  if (parsed.ttl == QStringLiteral("off") && !parsed.burn) {
    return {};
  }
  QStringList parts;
  if (parsed.ttl != QStringLiteral("off")) {
    parts << tr("scade tra %1").arg(parsed.ttl);
  }
  if (parsed.burn) {
    parts << tr("distruggi dopo lettura");
  }
  return tr("Messaggio effimero: %1. Alla chiusura non resta nulla.")
      .arg(parts.join(QStringLiteral(", ")));
}

int MainWindow::expiryTimeoutMs(const QString& ttl) {
  if (ttl == QStringLiteral("1h")) return 60 * 60 * 1000;
  if (ttl == QStringLiteral("24h")) return 24 * 60 * 60 * 1000;
  // 604'800'000: the longest bucket, still far from the int limit, so no
  // overflow however long the dialog stays up.
  if (ttl == QStringLiteral("7d")) return 7 * 24 * 60 * 60 * 1000;
  return 0;
}

void MainWindow::clearPlainEdit(QPlainTextEdit* edit) {
  if (edit == nullptr) return;
  edit->clear();
  edit->document()->clearUndoRedoStacks();
}

void MainWindow::clearSendInputs() {
  sendRecipients_.clear();
  syncRecipientChips();
  if (sendAliasCombo_ != nullptr && sendAliasCombo_->lineEdit() != nullptr) {
    sendAliasCombo_->lineEdit()->clear();
  }
  // The expiry was a per-message choice: leaving it on would mark the next
  // message ephemeral by accident. Ordinary is the fail-safe default.
  if (ttlCombo_ != nullptr) {
    ttlCombo_->setCurrentIndex(0);
  }
  if (burnCheck_ != nullptr) {
    burnCheck_->setChecked(false);
  }
  clearPlainEdit(sendMessageEdit_);
  if (sendFileEdit_ != nullptr) {
    sendFileEdit_->clear();
  }
}

void MainWindow::clearAddInputs() {
  if (addAliasEdit_ != nullptr) {
    addAliasEdit_->clear();
  }
  if (addCardFileEdit_ != nullptr) {
    addCardFileEdit_->clear();
  }
  clearPlainEdit(addCardEdit_);
}

void MainWindow::clearRecvInput() { clearPlainEdit(recvBlockEdit_); }

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
  // Read by handleFinished(). `trust --confirmed` is only ever launched from
  // showTrustDialog, after the fingerprint has been shown and accepted; setting
  // the alias here keeps the later refresh, which looks it up by name, pointed
  // at the same contact.
  trustFingerprintPending_ =
      command == QLatin1String("trust") &&
      flags.contains(QStringLiteral("--show-fingerprint"));
  if (command == QLatin1String("trust") &&
      flags.contains(QStringLiteral("--confirmed")) &&
      !positionals.isEmpty()) {
    confirmTrustedContact_ = positionals.first();
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
  QByteArray input = passphraseInput(confirm_extra_newline);
  launch(command, flags, positionals, input, silent);
  // QProcess has copied what it needs into its own write buffer by the time
  // run() returns from write(); this copy can go. The QProcess buffer itself is
  // not reachable (see cli_runner.cpp).
  ratchet::gui::wipeByteArray(input);
}

void MainWindow::launchWithPayload(const QString& command,
                                   const QStringList& flags,
                                   const QStringList& positionals,
                                   const QByteArray& payload, bool silent) {
  QByteArray pass = passphraseInput(false);
  ratchet::gui::PayloadInput framed =
      ratchet::gui::payloadInput(payload, pass);
  ratchet::gui::wipeByteArray(pass);
  QStringList all_flags = flags;
  all_flags << framed.flags;
  launch(command, all_flags, positionals, framed.stdin_data, silent);
  ratchet::gui::wipeByteArray(framed.stdin_data);
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

QString MainWindow::commandTitle(const QString& command) const {
  if (command == QLatin1String("unlock")) return tr("Vault sbloccato");
  if (command == QLatin1String("card")) return tr("Card identita");
  if (command == QLatin1String("contacts")) return tr("Contatti");
  if (command == QLatin1String("add")) return tr("Contatto aggiunto");
  if (command == QLatin1String("trust")) return tr("Contatto verificato");
  if (command == QLatin1String("reset-session")) return tr("Sessione azzerata");
  if (command == QLatin1String("remove")) return tr("Contatto rimosso");
  if (command == QLatin1String("send")) return tr("Blocco cifrato");
  if (command == QLatin1String("group-send")) return tr("Blocco di gruppo");
  if (command == QLatin1String("recv")) return tr("Messaggio ricevuto");
  if (command == QLatin1String("anchor")) return tr("Rollback anchor");
  return tr("Risultato");
}

void MainWindow::showResultDialog(bool ok, const QString& title,
                                  const QString& message,
                                  const QString& detail,
                                  const QString& command,
                                  int auto_close_ms) {
  QDialog dialog(this);
  // An ephemeral TTL closes the dialog when it runs out. accept() runs the
  // same finished handlers as Chiudi, so the visible copy is dropped either
  // way; the single-shot is bound to the dialog, so closing early leaves no
  // firing timer behind.
  if (auto_close_ms > 0) {
    QTimer::singleShot(auto_close_ms, &dialog, &QDialog::accept);
  }
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
    view->setUndoRedoEnabled(false);
    view->setLineWrapMode(QPlainTextEdit::NoWrap);
    view->setMinimumSize(560, 300);
    layout->addWidget(view, 1);
    // Drop the visible copy when the dialog closes. QTextDocument does not
    // zero the allocation, but it does stop the dialog from keeping a
    // decrypted message, a generated passphrase or the recovery words alive
    // after it is gone.
    QObject::connect(&dialog, &QDialog::finished, view, [view](int) {
      view->clear();
      view->document()->clearUndoRedoStacks();
    });
  }

  auto* buttons = new QHBoxLayout;
  buttons->addStretch(1);
  if (view != nullptr) {
    auto* copy = new QPushButton(tr("Copia"));
    connect(copy, &QPushButton::clicked, this, [this, view] {
      // The clipboard belongs to another process (or to the display server).
      // This program cannot wipe it, cannot know how many copies the clipboard
      // manager keeps, and does not claim to. It is offered because a card or a
      // message block has to be pasted somewhere to be useful.
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

  // A card is a wire format, not a secret, and it exists to be pasted
  // somewhere: a button that copies two dozen lines split across screens is a
  // worse way to lose a character than selecting all of it. Starting from the
  // selection costs nothing -- the user can still type over it.
  if (view != nullptr && command == QLatin1String("card")) {
    view->selectAll();
  }

  dialog.resize(620, view != nullptr ? 440 : 190);
  dialog.exec();
}

bool MainWindow::openFolder(const QString& dir) {
  if (!QFileInfo(dir).isDir()) {
    return false;
  }
  const QProcessEnvironment env = ratchet::gui::hostProcessEnvironment();
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
                                const QString& detail, const QString& expiry_note,
                                int auto_close_ms) {
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
  if (!expiry_note.isEmpty()) {
    message += expiry_note;
    message += QLatin1Char('\n');
  }
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

  // Same enforcement as the text dialog: the TTL closes the window, and the
  // Chiudi handler removes the staged folder, so expiry also wipes the
  // staged bytes rather than leaving them to the background reaper.
  if (auto_close_ms > 0) {
    QTimer::singleShot(auto_close_ms, &dialog, &QDialog::accept);
  }
  dialog.resize(560, path.isEmpty() ? 320 : 220);
  dialog.exec();
}

void MainWindow::onFinished(int exit_code, bool normal_exit) {
  // The raw stdout/stderr of the child can contain the decrypted message, a
  // generated passphrase or the recovery words. handleFinished() copies what it
  // needs into a dialog; the buffers are dropped on every path out, including
  // the error and silent ones.
  handleFinished(exit_code, normal_exit);
  clearCommandBuffers();
}

void MainWindow::handleFinished(int exit_code, bool normal_exit) {
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
    // A command that failed after printing something on stdout is the one case
    // where its result is a warning rather than an error: `recv` saves the
    // vault and then finds the message it decrypted is a file it will not
    // open, and exits non-zero so a script sees that. The body is already on
    // screen in that case, so it must not be replaced by a generic failure.
    if (command == QLatin1String("recv") && normal_exit) {
      const ratchet::gui::ParsedRecvResult parsed =
          ratchet::gui::parseRecvResult(commandStdout_);
      if (parsed.ok && parsed.is_file) {
        // The block is consumed even though the command exits non-zero (the
        // vault was already saved); keeping it would invite decrypting it
        // twice.
        clearRecvInput();
        showRecvFile(parsed, commandStderr_);
        return;
      }
    }
    QString detail = extractError(commandStderr_);
    // The new GUI asks for --structured-output. An older CLI rejects the flag
    // at parse time, before it touches a vault. Say that explicitly; do not
    // fall back to scraping headings, which could turn a missing field into a
    // short phrase that looks valid.
    if ((command == QLatin1String("init") ||
         command == QLatin1String("passphrase")) &&
        commandStderr_.contains(QStringLiteral("--structured-output"))) {
      detail = tr("La CLI selezionata non supporta --structured-output, "
                  "richiesto da questa GUI. Aggiorna ratchet-usb oppure scegli "
                  "il binario della stessa versione.");
    }
    showResultDialog(false, tr("Operazione non riuscita"),
                     tr("Il comando '%1' e' fallito.").arg(command), detail);
    if (command == QLatin1String("unlock")) {
      setUnlocked(false);
      // The unlock failed, so whatever the previous vault said about its own
      // protection no longer describes anything on screen.
      setVaultWarnings(QString());
    }
    return;
  }

  if (command == QLatin1String("init")) {
    const ratchet::gui::ParsedGuiResult parsed =
        ratchet::gui::parseGuiResult(commandStdout_, QStringLiteral("init"));
    if (!parsed.ok) {
      showResultDialog(false, tr("Risultato non valido"),
                       tr("La CLI non ha prodotto un risultato strutturato "
                          "valido per init."),
                       parsed.error);
      return;
    }
    QString detail;
    detail += tr("Passphrase del vault (scrivile ora, non e' recuperabile):\n%1\n\n")
                  .arg(parsed.value.passphrase);
    if (!parsed.value.recovery.isEmpty()) {
      detail += tr("Frase di recupero (12 parole):\n%1\n\n")
                    .arg(parsed.value.recovery);
    } else {
      detail += tr("Nessuna nuova frase di recupero: l'identita' e' stata "
                   "ricostruita dalle parole fornite.\n\n");
    }
    showResultDialog(true, tr("Vault creato"),
                     tr("Annota la passphrase: e' mostrata solo qui."), detail);
    return;
  }

  if (command == QLatin1String("passphrase")) {
    const ratchet::gui::ParsedGuiResult parsed =
        ratchet::gui::parseGuiResult(commandStdout_,
                                     QStringLiteral("passphrase"));
    if (!parsed.ok) {
      showResultDialog(false, tr("Risultato non valido"),
                       tr("La CLI non ha prodotto un risultato strutturato "
                          "valido per passphrase."),
                       parsed.error);
      return;
    }
    if (parsed.value.status == ratchet::gui::GuiResult::Status::Cancelled) {
      showResultDialog(true, tr("Passphrase non cambiata"),
                       tr("Il vault non e' stato modificato."), {});
      return;
    }
    showResultDialog(true, tr("Passphrase cambiata"),
                     tr("La vecchia passphrase non e' piu' valida."),
                     tr("Nuova passphrase del vault (mostrata una sola volta):\n%1")
                         .arg(parsed.value.passphrase));
    // The old phrase no longer opens anything; leaving it in the field only
    // keeps a dead secret around and invites a failed unlock.
    passphraseEdit_->clear();
    revealButton_->setChecked(false);
    passphraseEdit_->setEchoMode(QLineEdit::Password);
    return;
  }

  if (command == QLatin1String("trust") && trustFingerprintPending_) {
    trustFingerprintPending_ = false;
    QString alias = confirmTrustedContact_;
    if (alias.isEmpty()) {
      // Fall back to the contacts list when the combo box was edited: the
      // dialog still checks this against what the CLI printed.
      const QString shown = aliasLine(commandStdout_, QStringLiteral("alias"));
      if (!shown.isEmpty()) alias = shown;
    }
    showTrustDialog(alias, aliasLine(commandStdout_, QStringLiteral("alias")),
                    aliasLine(commandStdout_, QStringLiteral("fingerprint")),
                    !commandStdout_.isEmpty());
    return;
  }

  if (command == QLatin1String("unlock")) {
    setUnlocked(true);
    // The warning survives the dialog: it is about the state of the vault that
    // is now open, not about this command having run.
    setVaultWarnings(vaultWarningsFromLog(commandStderr_));
    showResultDialog(true, tr("Vault sbloccato"),
                     tr("Ora puoi usare le schede Contatti e Messaggi."),
                     commandStdout_);
    refreshContacts();
    return;
  }

  if (command == QLatin1String("add")) {
    // The alias and the pasted card are consumed: keeping them would invite
    // adding the same contact twice, and the card is their public key
    // sitting in an editable box.
    clearAddInputs();
    showResultDialog(true, tr("Contatto aggiunto"),
                     tr("Verifica l'impronta con la persona, fuori banda."),
                     commandStdout_);
    refreshContacts();
    return;
  }

  if (command == QLatin1String("trust")) {
    // The --confirmed step, or a trust that failed. Either way the list has
    // to be re-read: the badge differs even when nothing else does.
    showResultDialog(true, tr("Contatto verificato"),
                     tr("Il contatto e' segnato come verificato."),
                     commandStdout_);
    refreshContacts();
    return;
  }

  if (command == QLatin1String("remove")) {
    showResultDialog(true, tr("Contatto rimosso"),
                     tr("Il contatto e la sua sessione sono stati eliminati."),
                     commandStdout_);
    refreshContacts();
    return;
  }

  if (command == QLatin1String("recv")) {
    // What arrived is read from the structured block the CLI appends, never
    // from its human stderr: that text starts with the sender's alias, and an
    // alias is something the sender chooses.
    const ratchet::gui::ParsedRecvResult parsed =
        ratchet::gui::parseRecvResult(commandStdout_);
    if (!parsed.ok) {
      showResultDialog(false, commandTitle(command),
                       tr("La CLI non ha prodotto un risultato strutturato "
                          "valido per recv."),
                       parsed.error);
      return;
    }
    if (parsed.is_file) {
      clearRecvInput();
      showRecvFile(parsed, commandStderr_);
      return;
    }
    clearRecvInput();
    // The notice names the sender's expiry choice; the timer enforces it on
    // screen by closing the dialog. Both come from the parsed block, never
    // from the sender's text.
    const QString notice = expiryNotice(parsed);
    showResultDialog(true, commandTitle(command),
                     notice.isEmpty() ? tr("Operazione completata.") : notice,
                     parsed.body, {}, expiryTimeoutMs(parsed.ttl));
    return;
  }

  if (command == QLatin1String("send") ||
      command == QLatin1String("group-send")) {
    // The plaintext was encrypted and the recipients consumed; keeping any
    // of it would keep a copy on screen and in the undo history, and a stale
    // recipient list invites sending the next message to the wrong people. A
    // failed send returns above, before this point, so everything is still
    // there to retry.
    clearSendInputs();
  }

  if (!commandStdout_.trimmed().isEmpty()) {
    showResultDialog(true, commandTitle(command), tr("Operazione completata."),
                     commandStdout_);
  } else {
    showResultDialog(true, commandTitle(command), tr("Operazione completata."),
                     commandStderr_);
  }
}

void MainWindow::showRecvFile(const ratchet::gui::ParsedRecvResult& parsed,
                              const QString& stderr_text) {
  // A file is always announced, even when it was not staged: the one thing the
  // receiver must never do is mistake a file for a message and carry on. When
  // it was staged, the dialog offers to open the folder -- not the file.
  // Ephemeral files carry the same notice and timer as ephemeral text; the
  // dialog's close path removes the staged folder on expiry too.
  const QString notice = expiryNotice(parsed);
  const int auto_close_ms = expiryTimeoutMs(parsed.ttl);
  QString detail;
  if (parsed.staged) {
    detail = stderr_text;
  } else {
    detail = stderr_text;
    const QString& body = parsed.body;
    if (!body.isEmpty()) {
      if (!detail.isEmpty() && !detail.endsWith(QLatin1Char('\n'))) {
        detail += QLatin1Char('\n');
      }
      detail += tr("Contenuto del messaggio:\n%1").arg(body);
    }
  }
  showFileDialog(parsed.ext, parsed.staged ? parsed.path : QString(), detail,
                 notice, auto_close_ms);
}

QString MainWindow::aliasLine(const QString& text, const QString& key) {
  // A one-line "key: value" field of the CLI's output. The alias and the
  // fingerprint are ASCII (the fingerprint is hex, grouped by spaces), so
  // splitting on the first ':' is enough; anything else is ignored.
  const QString prefix = key + QStringLiteral(": ");
  for (const QString& line : text.split(QLatin1Char('\n'))) {
    if (line.startsWith(prefix)) {
      return line.mid(prefix.size());
    }
  }
  return {};
}

void MainWindow::showTrustDialog(const QString& alias, const QString& shown_alias,
                                 const QString& fingerprint, bool have_result) {
  if (!have_result) {
    // The first step failed. That is a normal command failure and already has
    // its own dialog; the user is simply not asked to confirm anything.
    return;
  }
  if (shown_alias.isEmpty()) {
    // stdout carried something, but not the alias line the first step is
    // supposed to print. Fail closed -- and say so, because the dialog simply
    // not opening is otherwise indistinguishable from a bug.
    if (!alias.isEmpty()) {
      warn(tr("La CLI non ha stampato l'alias di '%1': nessun contatto e' "
              "stato segnato come verificato.")
               .arg(alias));
    }
    return;
  }
  if (shown_alias != alias && !alias.isEmpty()) {
    // The value the CLI printed belongs to a different contact. Confirming it
    // would mark the wrong one verified.
    warn(tr("La CLI ha stampato l'impronta di '%1', non di '%2': "
            "nessun contatto e' stato segnato come verificato.")
             .arg(shown_alias, alias));
    return;
  }
  if (fingerprint.isEmpty()) {
    warn(tr("La CLI non ha stampato l'impronta di '%1': nessun contatto e' "
            "stato segnato come verificato.")
             .arg(alias));
    return;
  }

  QDialog dialog(this);
  dialog.setWindowTitle(tr("Segnare '%1' come verificato?").arg(alias));
  auto* layout = new QVBoxLayout(&dialog);
  layout->setContentsMargins(16, 16, 16, 12);
  layout->setSpacing(10);

  auto* question = new QLabel;
  question->setTextFormat(Qt::PlainText);
  question->setWordWrap(true);
  question->setText(
      tr("Impronta di '%1'. Confrontala con quella che la persona legge su "
         "un altro canale (di persona, al telefono): se non coincide, "
         "interrompi e chiedi una card nuova.")
          .arg(alias));
  layout->addWidget(question);

  auto* fingerprint_view = new QPlainTextEdit(fingerprint);
  fingerprint_view->setObjectName(QStringLiteral("trustFingerprint"));
  fingerprint_view->setReadOnly(true);
  fingerprint_view->setUndoRedoEnabled(false);
  fingerprint_view->setLineWrapMode(QPlainTextEdit::NoWrap);
  fingerprint_view->setFixedHeight(72);
  layout->addWidget(fingerprint_view);

  auto* confirm = new QCheckBox(
      tr("Ho confrontato l'impronta e corrisponde."));
  confirm->setObjectName(QStringLiteral("trustConsent"));
  layout->addWidget(confirm);

  auto* note = new QLabel(tr(
      "Da questo momento il vault accetta i messaggi di '%1'. E' "
      "un'autorizzazione, non una nota: non c'e' un comando che la revochi.")
                             .arg(alias));
  note->setTextFormat(Qt::PlainText);
  note->setWordWrap(true);
  layout->addWidget(note);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok |
                                       QDialogButtonBox::Cancel);
  QPushButton* ok = buttons->button(QDialogButtonBox::Ok);
  ok->setObjectName(QStringLiteral("trustConfirmButton"));
  ok->setText(tr("Segna come verificato"));
  ok->setEnabled(false);
  connect(confirm, &QCheckBox::toggled, ok, &QPushButton::setEnabled);
  connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  layout->addWidget(buttons);

  dialog.resize(520, 300);
  const int answer = dialog.exec();
  // The dialog holds the fingerprint, which is not a secret, but a stale copy
  // serves no purpose once it is closed.
  fingerprint_view->clear();
  if (answer != QDialog::Accepted || !confirm->isChecked()) {
    statusBar()->showMessage(tr("Nessun contatto segnato come verificato."),
                             4000);
    return;
  }

  confirmTrustedContact_ = alias;
  // The fingerprint the dialog showed goes back to the CLI. It recomputes the
  // contact's own fingerprint and refuses when they differ, so a card that
  // changed while the dialog was open cannot inherit this confirmation.
  launchWithPassphrase(QStringLiteral("trust"),
                       {QStringLiteral("--confirmed"),
                        QStringLiteral("--expect-fingerprint"), fingerprint},
                       {alias});
}

QString MainWindow::vaultWarningsFromLog(const QString& text) {
  // The CLI states these itself and does not prefix them with "error:": an
  // unlock that succeeds while one of them holds is exactly the case they exist
  // for. Matching the CLI's own wording is deliberate -- the GUI has no other
  // way to learn it from a version of ratchet-usb that still prints all three.
  static const QStringList kMarkers{
      QStringLiteral("SECURITY WARNING"),
      QStringLiteral("warning: could not lock key material into RAM"),
      QStringLiteral("WARNING: the vault was created with a lower Argon2id"),
  };
  QStringList found;
  for (const QString& line : text.split(QLatin1Char('\n'))) {
    const QString trimmed = line.trimmed();
    for (const QString& marker : kMarkers) {
      if (trimmed.startsWith(marker)) {
        found << trimmed;
        break;
      }
    }
  }
  QString out;
  for (const QString& line : found) {
    if (!out.isEmpty()) out += QLatin1Char('\n');
    out += line;
  }
  return out;
}

void MainWindow::setVaultWarnings(const QString& warnings) {
  if (warnings.isEmpty()) {
    vaultWarningLabel_->setText(QString());
    vaultWarningLabel_->hide();
    return;
  }
  vaultWarningLabel_->setText(warnings);
  vaultWarningLabel_->show();
  // A dialog as well, because a line in a corner is easy to miss and the
  // unlock dialog is on screen at that point.
  QMessageBox::warning(this, tr("Avvisi sul vault"), warnings);
}

void MainWindow::clearCommandBuffers() {
  commandStdout_.clear();
  commandStderr_.clear();
}

// What clear() can and cannot promise.
//
// QLineEdit::clear() and QPlainTextEdit::clear() drop the visible value, but
// they do not zero the allocation that held it: Qt frees or reuses the buffer
// like any other string, and implicit sharing means copies made by tr(), a
// signal, a QLabel or QProcess may still exist. QLineEdit exposes no way to
// disable or clear its internal undo stack; QPlainTextEdit does, and it is
// cleared here after the compose text is dropped. The passphrase field's undo
// history and any implicit copy are therefore a documented limit, not a claim
// of erasure. The safest statement is: the GUI stops displaying the value and
// drops its own reference, and a host that can read its memory can still see
// whatever Qt has not overwritten yet.
void MainWindow::clearSensitiveState(bool include_unsent_input) {
  if (passphraseEdit_ != nullptr) {
    passphraseEdit_->clear();
    passphraseEdit_->setEchoMode(QLineEdit::Password);
  }
  if (revealButton_ != nullptr) {
    revealButton_->setChecked(false);
  }
  clearCommandBuffers();
  stagedCard_.reset();
  if (!include_unsent_input) {
    return;
  }
  if (sendMessageEdit_ != nullptr) {
    sendMessageEdit_->clear();
    sendMessageEdit_->document()->clearUndoRedoStacks();
  }
  if (recvBlockEdit_ != nullptr) {
    recvBlockEdit_->clear();
    recvBlockEdit_->document()->clearUndoRedoStacks();
  }
}

void MainWindow::closeEvent(QCloseEvent* event) {
  clearSensitiveState(/*include_unsent_input=*/true);
  QMainWindow::closeEvent(event);
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
