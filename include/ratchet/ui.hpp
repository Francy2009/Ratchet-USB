#ifndef RATCHET_UI_HPP
#define RATCHET_UI_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/i18n.hpp"
#include "ratchet/screen.hpp"

// The terminal interface: a state machine with no input or output in it, and a
// driver that gives it keys and draws what it asks for.
//
// The split is what makes any of this testable. A full-screen interface is
// usually verifiable only by a person sitting in front of it, which for a tool
// like this is not good enough: whether a warning about an unverified contact
// can be pushed off the screen by a long alias is a security question, and it
// deserves a test rather than a careful look. Model has no file handles, no
// terminal and no clock, so a test can drive it through a whole conversation
// and read the frame back.
namespace ratchet::ui {

enum class Screen : uint8_t {
  Drive,      // pick the drive to work from
  DrivePath,  // type a path, when detection found nothing
  Setup,      // the chosen drive holds no vault
  Home,       // fingerprint and contact list
  Contact,    // one contact and what can be done with them
  Compose,    // write a message
  Block,      // show an armoured block to copy out
  Alias,      // name a contact being added
  Paste,      // take a pasted block in
  Message,    // show a message that was decrypted
};

// What the model wants done. The payload is read back off the model, so this
// stays something a test can compare with ==.
enum class ActionKind : uint8_t {
  None,
  Quit,
  Lock,
  UseDrive,         // selected_drive()
  UseTypedPath,     // text()
  CreateIdentity,   // on drive_path()
  RestoreIdentity,  // on drive_path()
  ShowCard,
  ImportCard,  // alias() and text()
  Trust,       // selected_contact()
  Send,        // selected_contact() and text()
  Receive,     // text()
};

struct DriveEntry {
  std::string path;
  bool has_vault = false;
};

struct ContactRow {
  std::string alias;
  std::string fingerprint;
  bool verified = false;
  bool has_session = false;
};

class Model {
 public:
  explicit Model(i18n::Lang lang) : lang_(lang) {}

  // --- what the driver tells the model ------------------------------------
  void show_drives(std::vector<DriveEntry> drives);
  void show_drive_path();
  void show_setup(std::string drive_path);
  void show_home(std::string drive_path, std::string fingerprint,
                 std::vector<ContactRow> contacts);
  void show_contacts(std::vector<ContactRow> contacts);
  void show_block(std::string_view heading, std::string block);
  void show_message(const std::string& from, std::string body, bool session_opened,
                    bool unverified);
  void set_status(std::string text);
  void set_status(i18n::Str id);

  // Drops everything the vault put on screen and goes back to picking a
  // drive. Called when the vault is locked, by hand or by the idle timer: the
  // driver wipes the keys, and this makes sure the screen stops showing what
  // they decrypted.
  void forget();

  // --- what the model tells the driver ------------------------------------
  ActionKind handle_key(const screen::Key& key);
  void render(screen::Frame& frame) const;

  Screen screen() const { return screen_; }
  const std::string& text() const { return text_; }
  const std::string& alias() const { return alias_; }
  const std::string& drive_path() const { return drive_path_; }
  std::size_t selected() const { return selected_; }
  const DriveEntry* selected_drive() const;
  const ContactRow* selected_contact() const;
  bool unlocked() const { return unlocked_; }
  i18n::Lang lang() const { return lang_; }

  // Wipes the editable buffer. The driver calls this once it has taken the
  // text off the model, so a message body or a pasted block does not sit on
  // the heap for the rest of the session.
  void clear_text();

 private:
  void go(Screen next);
  void move_selection(int delta, std::size_t count);
  void insert(std::string_view utf8);
  void backspace();
  ActionKind key_in_list(const screen::Key& key);
  ActionKind key_in_text(const screen::Key& key);
  ActionKind key_in_pager(const screen::Key& key);
  void close_pager();
  void render_header(screen::Frame& frame) const;
  void render_body(screen::Frame& frame, std::size_t rows) const;
  void render_footer(screen::Frame& frame) const;
  std::string_view footer_keys() const;
  std::string_view heading() const;

  i18n::Lang lang_;
  Screen screen_ = Screen::Drive;
  bool unlocked_ = false;

  std::vector<DriveEntry> drives_;
  std::vector<ContactRow> contacts_;
  std::string drive_path_;
  std::string fingerprint_;

  std::size_t selected_ = 0;       // index into drives_ or contacts_
  std::size_t contact_index_ = 0;  // the contact Contact/Compose are about

  std::string text_;   // the editable buffer: an alias, a message, a paste
  std::string alias_;  // the alias of a contact being added
  std::string status_;

  // What Paste is collecting, which decides where Ctrl-D goes.
  bool pasting_card_ = false;
  // True between the terminal's bracketed-paste markers.
  bool in_paste_ = false;

  std::vector<std::string> pager_;  // Block and Message contents, wrapped
  std::string pager_heading_;
  std::size_t pager_top_ = 0;
  std::vector<std::string> pager_notes_;  // warnings shown above a message
};

// Runs the interface until the user leaves it. Returns the process exit code.
//
// Refuses to start unless stdin and stdout are both a terminal, which is what
// keeps every scripted use of this program on exactly the path it was on
// before this file existed.
struct Config {
  std::string usb_path;      // --usb-path, empty to detect
  i18n::Lang lang = i18n::Lang::En;
  int idle_lock_seconds = 180;  // zero disables the idle timer
};

int run(const Config& config);

}  // namespace ratchet::ui

#endif  // RATCHET_UI_HPP
