// For _exit, in the handler that hands the terminal back when the terminal
// itself is going away. Glibc declares it through other headers, so leaving
// this out still compiled on Linux with both compilers; libc++ does not, and
// the macOS build is what said so.
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ratchet/app.hpp"
#include "ratchet/bip39.hpp"
#include "ratchet/cli.hpp"
#include "ratchet/identity.hpp"
#include "ratchet/media.hpp"
#include "ratchet/screen.hpp"
#include "ratchet/session.hpp"
#include "ratchet/terminal.hpp"
#include "ratchet/ui.hpp"
#include "ratchet/x3dh.hpp"

namespace fs = std::filesystem;

namespace ratchet::ui {
namespace {

using i18n::Str;

// Set from signal handlers, read by the loop. Nothing else may happen in a
// handler: the loop is where it is safe to touch a vault.
volatile sig_atomic_t g_resized = 0;
volatile sig_atomic_t g_continued = 0;

extern "C" void on_resize(int) { g_resized = 1; }
extern "C" void on_continue(int) { g_continued = 1; }

// The terminal is going away and the process with it. Put the terminal back
// the way it was found and stop; the vault cannot be wiped from here (nothing
// that could is async-signal-safe), but its pages are locked so they never
// reached swap, and harden_process() already refused a core dump.
extern "C" void on_terminate(int) {
  screen::emergency_restore();
  _exit(1);
}

extern "C" void on_suspend(int) {
  screen::emergency_restore();
  (void)std::signal(SIGTSTP, SIG_DFL);
  (void)std::raise(SIGTSTP);
}

void install_signal_handlers() {
  (void)std::signal(SIGWINCH, on_resize);
  (void)std::signal(SIGTERM, on_terminate);
  (void)std::signal(SIGHUP, on_terminate);
  (void)std::signal(SIGTSTP, on_suspend);
  (void)std::signal(SIGCONT, on_continue);
  // SIGINT is not in this list on purpose: raw mode switches ISIG off, so
  // Ctrl-C arrives as a keystroke and the ordinary quit path -- the one that
  // wipes the vault out of memory -- handles it.
}

// Steps out of the full-screen interface for as long as it exists, so a prompt
// that reads a line the ordinary way can do so.
//
// Every passphrase in this program is read by terminal::read_passphrase, the
// same function the command line has always used, rather than by a field drawn
// in the frame. That is deliberate: a passphrase prompt is the one piece of
// input where a mistake is unrecoverable -- echo left on puts it on the screen
// and into a screenshot -- and the existing one is tested, has an RAII guard
// that restores the terminal even when the read throws, and reads a character
// at a time so no std::string ever holds a copy. Reusing it means the
// interface adds no new code that a passphrase passes through.
class Modal {
 public:
  explicit Modal(std::optional<screen::RawMode>& raw) : raw_(raw) {
    // Bracketed paste off first: otherwise a pasted passphrase arrives with
    // the terminal's markers wrapped around it.
    screen::set_bracketed_paste(false);
    raw_.reset();
    screen::write_all("\033[?25h");
    terminal::clear_screen();
  }

  ~Modal() {
    std::cout.flush();
    raw_.emplace();
    screen::set_bracketed_paste(true);
    screen::write_all("\033[?25l");
  }

  Modal(const Modal&) = delete;
  Modal& operator=(const Modal&) = delete;

 private:
  std::optional<screen::RawMode>& raw_;
};

class Driver {
 public:
  explicit Driver(const Config& config)
      : config_(config), model_(config.lang) {}

  int run();

 private:
  std::string_view t(Str id) const { return i18n::t(config_.lang, id); }

  void redraw();
  void loop();

  void begin();
  void refresh_drives();
  void use_path(const fs::path& path);
  void unlock();
  void after_unlock();
  void lock(Str reason);

  void create_identity(bool from_mnemonic);
  void show_card();
  void import_card();
  void trust_selected();
  void send_message();
  void receive_message();

  void save();
  void go_home();
  // Every operation below runs only with a vault open. value() rather than
  // operator-> so that a bug which got here with the vault closed throws
  // instead of reading through an empty optional.
  app::OpenedVault& vault() {
    if (!vault_.has_value()) {
      throw Error("internal: no vault is open");
    }
    return *vault_;
  }
  const app::OpenedVault& vault() const {
    if (!vault_.has_value()) {
      throw Error("internal: no vault is open");
    }
    return *vault_;
  }
  std::vector<ContactRow> contact_rows() const;
  void report(const std::exception& error);

  Config config_;
  Model model_;
  std::optional<screen::RawMode> raw_;
  std::optional<app::OpenedVault> vault_;
  fs::path drive_;
  fs::path vault_path_;
  std::string fingerprint_;
  bool running_ = true;
};

void Driver::report(const std::exception& error) {
  model_.set_status(std::string(t(Str::ErrorPrefix)) + ": " + error.what());
}

void Driver::redraw() {
  const screen::Size size = screen::size();
  screen::Frame frame(size.width, size.height);
  model_.render(frame);
  screen::write_all(frame.render());
}

std::vector<ContactRow> Driver::contact_rows() const {
  std::vector<ContactRow> rows;
  if (!vault_) {
    return rows;
  }
  const store::VaultStore& store = vault().store;
  rows.reserve(store.contacts.size());
  for (std::size_t i = 0; i < store.contacts.size(); ++i) {
    ContactRow row;
    row.alias = store.contacts[i].alias;
    row.fingerprint = fingerprint(store.contacts[i].identity_pub);
    row.verified = store.contacts[i].verified;
    row.has_session = store.find_session(i) >= 0;
    rows.push_back(std::move(row));
  }
  return rows;
}

void Driver::save() {
  app::save_vault(vault_path_, vault().store, vault().params,
                  vault().passphrase);
}

// --- getting to an open vault ------------------------------------------------

void Driver::refresh_drives() {
  std::vector<DriveEntry> entries;
  auto already_listed = [&entries](const std::string& path) {
    for (const DriveEntry& entry : entries) {
      if (entry.path == path) {
        return true;
      }
    }
    return false;
  };

  // A drive that already holds a vault comes first: it is what somebody
  // opening this is nearly always after.
  for (const fs::path& path : media::drives_with_vault()) {
    entries.push_back(DriveEntry{path.string(), true});
  }
  for (const fs::path& path : media::removable_drives()) {
    if (!already_listed(path.string())) {
      entries.push_back(DriveEntry{path.string(), false});
    }
  }
  // RATCHET_USB_PATH is honoured here as it is everywhere else, so a drive the
  // detection cannot see is still one keypress away.
  if (const char* env = std::getenv("RATCHET_USB_PATH");
      env != nullptr && env[0] != '\0' && !already_listed(env)) {
    std::error_code ec;
    const bool has_vault = fs::exists(vault::vault_path(fs::path(env)), ec);
    entries.insert(entries.begin(), DriveEntry{env, has_vault});
  }

  model_.show_drives(std::move(entries));
}

void Driver::use_path(const fs::path& path) {
  try {
    drive_ = app::validate_usb_path(path);
  } catch (const std::exception& e) {
    report(e);
    return;
  }

  vault_path_ = vault::vault_path(drive_);
  std::error_code ec;
  if (fs::exists(vault_path_, ec)) {
    unlock();
  } else {
    model_.show_setup(drive_.string());
  }
  if (app::is_on_host_filesystem(drive_)) {
    model_.set_status(std::string(t(Str::HostDiskWarning)));
  }
}

void Driver::unlock() {
  try {
    const app::VaultFile file = app::read_vault(vault_path_);
    SecureString passphrase;
    {
      Modal modal(raw_);
      std::cout << "\n  " << drive_.string() << "\n\n";
      passphrase = terminal::read_passphrase(std::string(t(Str::PassphrasePrompt)));
      std::cout << "\n  " << t(Str::DerivingKey) << "\n";
      std::cout.flush();
      vault_ = app::open_vault(file, std::move(passphrase));
    }
  } catch (const std::exception&) {
    // Deliberately not the underlying message: a wrong passphrase and a
    // tampered file are indistinguishable by design, and saying which is
    // which here would undo that.
    vault_.reset();
    model_.set_status(std::string(t(Str::WrongPassphrase)));
    return;
  }
  after_unlock();
}

void Driver::after_unlock() {
  IdentitySigningSecretKey identity_sk;
  IdentitySigningPublicKey identity_pk;
  derive_identity(vault().store.seed, identity_sk, identity_pk);

  // The same maintenance `unlock` has always run: rotate a signed prekey past
  // its age, top the one-time pool back up, drop skipped keys nobody claimed.
  const app::MaintenanceReport report =
      app::maintain_prekeys(vault().store, identity_pk, identity_sk);
  identity_sk.wipe();
  const bool swept = app::expire_skipped_keys(vault().store) > 0;
  if (report.changed() || swept) {
    save();
  }

  fingerprint_ = fingerprint(identity_pk);
  go_home();
}

void Driver::go_home() {
  model_.show_home(drive_.string(), fingerprint_, contact_rows());
}

void Driver::lock(Str reason) {
  // Dropping the OpenedVault runs the destructors that wipe the seed, the
  // session keys and the passphrase; forget() takes what they produced off the
  // screen.
  vault_.reset();
  fingerprint_.clear();
  model_.forget();
  refresh_drives();
  model_.set_status(std::string(t(reason)));
}

// --- setting up a vault -------------------------------------------------------

void Driver::create_identity(bool from_mnemonic) {
  Modal modal(raw_);
  try {
    std::cout << "\n  " << t(from_mnemonic ? Str::RestoringIdentity
                                           : Str::SettingUp)
              << " " << drive_.string() << "\n";

    bip39::Entropy entropy;
    if (from_mnemonic) {
      SecureString mnemonic =
          terminal::read_passphrase(std::string(t(Str::RecoveryWordsPrompt)));
      bip39::decode(std::string_view(mnemonic.data(), mnemonic.size()), entropy);
      mnemonic.clear();
      std::cout << "\n  " << t(Str::RestoreNote) << "\n\n";
    } else {
      bip39::generate_entropy(entropy);
      SecureString mnemonic;
      bip39::encode(entropy, mnemonic);
      // Written straight to the stream, never into a line of the frame: a
      // frame line is an ordinary std::string on unlocked pages, and putting
      // the recovery words there would be handing them to the swap file.
      app::print_mnemonic(mnemonic, std::cout, t(Str::RecoveryHeading),
                          t(Str::RecoveryNote));
      mnemonic.clear();
      terminal::wait_for_enter(std::string(t(Str::WroteDownWords)));
      terminal::clear_screen();
    }

    store::VaultStore store;
    derive_master_seed(entropy, store.seed);
    entropy.wipe();

    IdentitySigningSecretKey identity_sk;
    IdentitySigningPublicKey identity_pk;
    derive_identity(store.seed, identity_sk, identity_pk);
    app::rotate_signed_prekey(store, identity_sk);
    app::replenish_one_time_prekeys(store, cli::kDefaultOtpkCount);
    identity_sk.wipe();

    SecureString passphrase = terminal::read_new_passphrase(
        std::string(t(Str::PassphraseNew)), std::string(t(Str::PassphraseAgain)));

    // The Argon2 cost is the default here. Tuning it is a command-line thing
    // (`init --argon2-time`), and a vault made here opens fine with either,
    // since the cost travels in the header.
    const vault::Params params;
    std::cout << "\n  " << t(Str::DerivingKey) << "\n";
      std::cout.flush();
    const SecureBuffer plaintext = store::serialize(store);
    const std::vector<uint8_t> file = vault::seal(plaintext, passphrase, params);
    vault::write_file(vault_path_, file, /*overwrite=*/false);

    app::OpenedVault opened;
    opened.store = std::move(store);
    opened.params = params;
    opened.passphrase = std::move(passphrase);
    vault_ = std::move(opened);
  } catch (const std::exception& e) {
    vault_.reset();
    report(e);
    return;
  }

  after_unlock();
  model_.set_status(std::string(t(Str::VaultCreated)));
}

// --- the everyday operations ---------------------------------------------------

void Driver::show_card() {
  try {
    IdentitySigningSecretKey identity_sk;
    IdentitySigningPublicKey identity_pk;
    derive_identity(vault().store.seed, identity_sk, identity_pk);

    const bool changed =
        app::resign_stale_prekeys(vault().store, identity_pk, identity_sk);
    if (vault().store.signed_prekeys.empty()) {
      identity_sk.wipe();
      throw Error("internal: vault has no signed prekey");
    }
    std::string card = x3dh::export_card(identity_sk, identity_pk,
                                         vault().store.signed_prekeys.back(),
                                         vault().store.one_time_prekeys);
    identity_sk.wipe();
    if (changed) {
      save();
    }
    model_.show_block(t(Str::YourCard), std::move(card));
  } catch (const std::exception& e) {
    report(e);
  }
}

void Driver::import_card() {
  std::string text = model_.text();
  const std::string alias = model_.alias();
  model_.clear_text();

  try {
    const x3dh::ImportedCard imported = x3dh::import_card(text);
    wipe_string(text);

    store::VaultStore& store = vault().store;
    if (store.find_contact(alias) >= 0) {
      throw Error("a contact named '" + alias + "' already exists");
    }
    if (store.find_contact_by_identity(imported.identity_pub) >= 0) {
      throw Error("this identity is already saved under a different alias");
    }

    store::Contact contact;
    contact.alias = alias;
    contact.identity_pub = imported.identity_pub;
    contact.card = imported.card;
    store.contacts.push_back(std::move(contact));
    save();

    go_home();
    model_.set_status(alias + " " + std::string(t(Str::ContactAdded)));
  } catch (const std::exception& e) {
    wipe_string(text);
    go_home();
    report(e);
  }
}

void Driver::trust_selected() {
  const ContactRow* row = model_.selected_contact();
  if (row == nullptr) {
    return;
  }
  const std::string alias = row->alias;
  try {
    const int index = vault().store.find_contact(alias);
    if (index < 0) {
      throw Error("no contact named '" + alias + "'");
    }
    vault().store.contacts[static_cast<std::size_t>(index)].verified = true;
    save();
    model_.show_contacts(contact_rows());
    model_.set_status(alias + " " + std::string(t(Str::MarkedVerified)));
  } catch (const std::exception& e) {
    report(e);
  }
}

void Driver::send_message() {
  const ContactRow* row = model_.selected_contact();
  std::string body = model_.text();
  model_.clear_text();
  if (row == nullptr || body.empty()) {
    wipe_string(body);
    model_.set_status(std::string(t(Str::EmptyMessage)));
    return;
  }

  try {
    const int index = vault().store.find_contact(row->alias);
    if (index < 0) {
      throw Error("no contact named '" + row->alias + "'");
    }

    IdentitySigningSecretKey identity_sk;
    IdentitySigningPublicKey identity_pk;
    derive_identity(vault().store.seed, identity_sk, identity_pk);
    std::string block =
        session::send(vault().store, identity_sk, identity_pk,
                      static_cast<std::size_t>(index), body);
    identity_sk.wipe();
    wipe_string(body);

    save();
    model_.show_contacts(contact_rows());
    model_.show_block(t(Str::MessageBlock), std::move(block));
    model_.set_status(std::string(t(Str::MessageReady)));
  } catch (const std::exception& e) {
    wipe_string(body);
    report(e);
  }
}

void Driver::receive_message() {
  std::string block = model_.text();
  model_.clear_text();
  if (block.empty()) {
    model_.set_status(std::string(t(Str::NothingToRead)));
    return;
  }

  try {
    IdentitySigningSecretKey identity_sk;
    IdentitySigningPublicKey identity_pk;
    derive_identity(vault().store.seed, identity_sk, identity_pk);
    session::ReceiveResult result =
        session::receive(vault().store, identity_sk, identity_pk, block);
    identity_sk.wipe();
    wipe_string(block);

    save();
    const bool unverified =
        !vault().store.contacts[result.contact_index].verified;
    model_.show_contacts(contact_rows());
    model_.show_message(result.alias, std::move(result.plaintext),
                        result.session_established, unverified);
    wipe_string(result.plaintext);
  } catch (const std::exception& e) {
    wipe_string(block);
    report(e);
  }
}

// --- the loop -------------------------------------------------------------------

void Driver::begin() {
  if (!config_.usb_path.empty()) {
    use_path(fs::path(config_.usb_path));
    return;
  }
  refresh_drives();
}

void Driver::loop() {
  using Clock = std::chrono::steady_clock;
  auto last_activity = Clock::now();
  std::string pending;

  redraw();
  while (running_) {
    if (g_resized != 0) {
      g_resized = 0;
      redraw();
    }
    if (g_continued != 0) {
      g_continued = 0;
      // Coming back from a suspend: the terminal has to be set up again, and
      // the vault is closed. Whatever happened while this process was stopped,
      // it did not happen in front of the person who unlocked it.
      raw_.emplace();
      // The suspend handler put SIGTSTP back to its default to let the stop
      // actually happen, so it has to be put back now or a second suspend
      // would leave the terminal in raw mode.
      install_signal_handlers();
      screen::write_all("\033[?1049h\033[?25l");
      screen::set_bracketed_paste(true);
      if (vault_) {
        lock(Str::Locked);
      }
      redraw();
    }

    int timeout_ms = -1;
    if (config_.idle_lock_seconds > 0 && vault_) {
      const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               Clock::now() - last_activity)
                               .count();
      const long limit = static_cast<long>(config_.idle_lock_seconds) * 1000;
      if (elapsed >= limit) {
        lock(Str::IdleLocked);
        redraw();
        continue;
      }
      timeout_ms = static_cast<int>(limit - elapsed);
    }

    if (!screen::read_available(pending, timeout_ms)) {
      break;  // the terminal went away
    }
    if (pending.empty()) {
      continue;  // a timeout, handled at the top of the next turn
    }

    bool dirty = false;
    while (!pending.empty()) {
      screen::Key key;
      std::size_t used = screen::decode_key(pending, false, key);
      if (used == 0) {
        // An incomplete sequence: give the rest of it a moment to arrive, and
        // treat what is there as final if nothing more comes.
        const std::size_t before = pending.size();
        screen::read_available(pending, 30);
        if (pending.size() != before) {
          continue;
        }
        used = screen::decode_key(pending, true, key);
      }
      pending.erase(0, used);

      if (key.code == screen::KeyCode::None) {
        continue;  // not a keypress, and so not activity either
      }
      last_activity = Clock::now();
      dirty = true;

      const ActionKind action = model_.handle_key(key);
      // Everything past Lock in this list needs an open vault. The model only
      // offers those on screens it reaches with one open, so this is a belt on
      // top of braces -- but it is the belt that decides whether a bug in the
      // navigation is a wrong screen or a crash.
      const bool needs_vault =
          action != ActionKind::None && action != ActionKind::Quit &&
          action != ActionKind::Lock && action != ActionKind::UseDrive &&
          action != ActionKind::UseTypedPath &&
          action != ActionKind::CreateIdentity &&
          action != ActionKind::RestoreIdentity;
      if (needs_vault && !vault_) {
        continue;
      }

      switch (action) {
        case ActionKind::None:
          break;
        case ActionKind::Quit:
          running_ = false;
          break;
        case ActionKind::Lock:
          lock(Str::Locked);
          break;
        case ActionKind::UseDrive:
          if (const DriveEntry* drive = model_.selected_drive()) {
            use_path(fs::path(drive->path));
          }
          break;
        case ActionKind::UseTypedPath: {
          const std::string path = model_.text();
          model_.clear_text();
          use_path(fs::path(path));
          break;
        }
        case ActionKind::CreateIdentity:
          create_identity(/*from_mnemonic=*/false);
          break;
        case ActionKind::RestoreIdentity:
          create_identity(/*from_mnemonic=*/true);
          break;
        case ActionKind::ShowCard:
          show_card();
          break;
        case ActionKind::ImportCard:
          import_card();
          break;
        case ActionKind::Trust:
          trust_selected();
          break;
        case ActionKind::Send:
          send_message();
          break;
        case ActionKind::Receive:
          receive_message();
          break;
      }
      if (!running_) {
        break;
      }
    }
    if (dirty) {
      redraw();
    }
  }
}

int Driver::run() {
  screen::AltScreen alt;
  raw_.emplace();
  install_signal_handlers();

  begin();
  loop();

  // Explicit rather than left to the destructor: the vault is wiped before the
  // terminal is handed back, not somewhere in between.
  vault_.reset();
  model_.forget();
  return 0;
}

}  // namespace

int run(const Config& config) {
  if (!screen::usable()) {
    // The caller checks this too. Here it is a backstop: nothing in this file
    // may run when stdin and stdout are not a terminal, because that is the
    // guarantee that every scripted use of this program is on exactly the path
    // it was on before.
    throw Error("the interface needs a terminal");
  }
  Driver driver(config);
  return driver.run();
}

}  // namespace ratchet::ui
