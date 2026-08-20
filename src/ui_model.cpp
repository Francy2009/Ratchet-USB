#include <algorithm>
#include <string>
#include <utility>

#include "ratchet/cli.hpp"
#include "ratchet/secure.hpp"
#include "ratchet/ui.hpp"

namespace ratchet::ui {
namespace {

using i18n::Str;

// How much of the frame the header and the footer take, leaving the rest for
// whatever the current screen is showing.
constexpr std::size_t kHeaderRows = 2;
constexpr std::size_t kFooterRows = 3;

// Two spaces of margin down the left, so nothing is drawn hard against the
// edge of the window.
constexpr std::string_view kIndent = "  ";

std::string indent(std::string_view text) {
  return std::string(kIndent) + std::string(text);
}

std::string rule(std::size_t width) { return std::string(width, '-'); }

}  // namespace

// --- driver -> model ---------------------------------------------------------

void Model::show_drives(std::vector<DriveEntry> drives) {
  drives_ = std::move(drives);
  selected_ = 0;
  // Even with nothing detected this stays the drive screen rather than
  // dropping into the path field. It is the screen the interface comes to rest
  // on, and a resting screen has to have `q` on it: a text field where every
  // key is a character has no way out but Ctrl-C.
  go(Screen::Drive);
}

void Model::show_drive_path() { go(Screen::DrivePath); }

void Model::show_setup(std::string drive_path) {
  drive_path_ = std::move(drive_path);
  go(Screen::Setup);
}

void Model::show_home(std::string drive_path, std::string fingerprint,
                      std::vector<ContactRow> contacts) {
  drive_path_ = std::move(drive_path);
  fingerprint_ = std::move(fingerprint);
  contacts_ = std::move(contacts);
  selected_ = 0;
  unlocked_ = true;
  go(Screen::Home);
}

void Model::show_contacts(std::vector<ContactRow> contacts) {
  contacts_ = std::move(contacts);
  if (selected_ >= contacts_.size()) {
    selected_ = contacts_.empty() ? 0 : contacts_.size() - 1;
  }
}

void Model::show_block(std::string_view heading, std::string block) {
  pager_heading_ = std::string(heading);
  pager_notes_.clear();
  // A block is already broken into short lines by the armouring, so it is
  // split on newlines and left alone otherwise.
  pager_ = screen::wrap_text(block, 4096);
  pager_top_ = 0;
  wipe_string(block);
  go(Screen::Block);
}

void Model::show_message(const std::string& from, std::string body, bool session_opened,
                         bool unverified) {
  pager_heading_ = std::string(i18n::t(lang_, Str::MessageFrom)) + " " + from;
  pager_notes_.clear();
  if (session_opened) {
    pager_notes_.emplace_back(i18n::t(lang_, Str::SessionOpened));
  }
  if (unverified) {
    pager_notes_.emplace_back(i18n::t(lang_, Str::WarnUnverified));
  }
  // Wrapped here rather than at render time so the body can be wiped straight
  // away; the width is generous and the frame truncates whatever is left over.
  pager_ = screen::wrap_text(body, 76);
  pager_top_ = 0;
  wipe_string(body);
  go(Screen::Message);
}

void Model::set_status(std::string text) { status_ = std::move(text); }

void Model::set_status(Str id) { status_ = std::string(i18n::t(lang_, id)); }

void Model::forget() {
  // Everything the vault produced goes, not just the screen it was on: a
  // locked vault that still had the contact list on the next screen over would
  // be a lock in name only.
  wipe_string(text_);
  for (std::string& line : pager_) {
    wipe_string(line);
  }
  pager_.clear();
  pager_notes_.clear();
  pager_heading_.clear();
  pager_top_ = 0;
  contacts_.clear();
  fingerprint_.clear();
  alias_.clear();
  selected_ = 0;
  contact_index_ = 0;
  in_paste_ = false;
  pasting_card_ = false;
  unlocked_ = false;
  go(Screen::Drive);
}

void Model::clear_text() { wipe_string(text_); }

const DriveEntry* Model::selected_drive() const {
  if (screen_ != Screen::Drive || selected_ >= drives_.size()) {
    return nullptr;
  }
  return &drives_[selected_];
}

const ContactRow* Model::selected_contact() const {
  const std::size_t index =
      (screen_ == Screen::Home) ? selected_ : contact_index_;
  if (index >= contacts_.size()) {
    return nullptr;
  }
  return &contacts_[index];
}

// --- keys --------------------------------------------------------------------

void Model::go(Screen next) {
  screen_ = next;
  if (next == Screen::Alias || next == Screen::Compose ||
      next == Screen::Paste || next == Screen::DrivePath) {
    wipe_string(text_);
  }
  in_paste_ = false;
}

void Model::move_selection(int delta, std::size_t count) {
  if (count == 0) {
    selected_ = 0;
    return;
  }
  if (delta < 0) {
    selected_ = (selected_ == 0) ? count - 1 : selected_ - 1;
  } else {
    selected_ = (selected_ + 1 >= count) ? 0 : selected_ + 1;
  }
}

void Model::insert(std::string_view utf8) { text_.append(utf8); }

void Model::backspace() {
  if (text_.empty()) {
    return;
  }
  // Back over the whole character, not one byte of it.
  std::size_t cut = text_.size() - 1;
  while (cut > 0 && (static_cast<unsigned char>(text_[cut]) & 0xC0) == 0x80) {
    --cut;
  }
  // The tail is zeroed before it is dropped: erase() alone would leave the
  // characters in the string's buffer, and this one holds message text.
  sodium_memzero(text_.data() + cut, text_.size() - cut);
  text_.erase(cut);
}

ActionKind Model::key_in_list(const screen::Key& key) {
  const std::size_t count =
      (screen_ == Screen::Drive) ? drives_.size() : contacts_.size();

  switch (key.code) {
    case screen::KeyCode::Up:
      move_selection(-1, count);
      return ActionKind::None;
    case screen::KeyCode::Down:
      move_selection(1, count);
      return ActionKind::None;
    default:
      break;
  }

  if (screen_ == Screen::Drive) {
    if (key.code == screen::KeyCode::Enter && !drives_.empty()) {
      return ActionKind::UseDrive;
    }
    if (key.code == screen::KeyCode::Char && key.text == "p") {
      go(Screen::DrivePath);
      return ActionKind::None;
    }
    if (key.code == screen::KeyCode::Char && key.text == "q") {
      return ActionKind::Quit;
    }
    return ActionKind::None;
  }

  // Screen::Home
  if (key.code == screen::KeyCode::Enter && !contacts_.empty()) {
    contact_index_ = selected_;
    go(Screen::Contact);
    return ActionKind::None;
  }
  if (key.code != screen::KeyCode::Char) {
    return ActionKind::None;
  }
  if (key.text == "a") {
    go(Screen::Alias);
    return ActionKind::None;
  }
  if (key.text == "c") {
    return ActionKind::ShowCard;
  }
  if (key.text == "r") {
    pasting_card_ = false;
    go(Screen::Paste);
    return ActionKind::None;
  }
  if (key.text == "l") {
    return ActionKind::Lock;
  }
  if (key.text == "q") {
    return ActionKind::Quit;
  }
  return ActionKind::None;
}

ActionKind Model::key_in_text(const screen::Key& key) {
  switch (key.code) {
    case screen::KeyCode::PasteBegin:
      in_paste_ = true;
      return ActionKind::None;
    case screen::KeyCode::PasteEnd:
      in_paste_ = false;
      return ActionKind::None;
    case screen::KeyCode::Char:
      insert(key.text);
      return ActionKind::None;
    case screen::KeyCode::Backspace:
      backspace();
      return ActionKind::None;
    case screen::KeyCode::CtrlU:
      clear_text();
      return ActionKind::None;
    default:
      break;
  }

  if (key.code == screen::KeyCode::Enter) {
    // In a one-line field Enter confirms; where the text may span lines it is
    // a line break, and Ctrl-D is what confirms.
    if (screen_ == Screen::DrivePath) {
      return text_.empty() ? ActionKind::None : ActionKind::UseTypedPath;
    }
    if (screen_ == Screen::Alias) {
      if (text_.empty()) {
        return ActionKind::None;
      }
      alias_ = text_;
      pasting_card_ = true;
      go(Screen::Paste);
      return ActionKind::None;
    }
    insert("\n");
    return ActionKind::None;
  }

  if (key.code == screen::KeyCode::CtrlD) {
    if (screen_ == Screen::Compose) {
      return ActionKind::Send;
    }
    if (screen_ == Screen::Paste) {
      return pasting_card_ ? ActionKind::ImportCard : ActionKind::Receive;
    }
  }

  if (key.code == screen::KeyCode::Escape) {
    clear_text();
    go(unlocked_ ? Screen::Home : Screen::Drive);
  }
  return ActionKind::None;
}

ActionKind Model::key_in_pager(const screen::Key& key) {
  const std::size_t last = pager_.empty() ? 0 : pager_.size() - 1;
  switch (key.code) {
    case screen::KeyCode::Up:
      if (pager_top_ > 0) {
        --pager_top_;
      }
      return ActionKind::None;
    case screen::KeyCode::Down:
      if (pager_top_ < last) {
        ++pager_top_;
      }
      return ActionKind::None;
    case screen::KeyCode::PageUp:
      pager_top_ = (pager_top_ > 10) ? pager_top_ - 10 : 0;
      return ActionKind::None;
    case screen::KeyCode::PageDown:
      pager_top_ = std::min(last, pager_top_ + 10);
      return ActionKind::None;
    case screen::KeyCode::Escape:
    case screen::KeyCode::Enter:
      close_pager();
      return ActionKind::None;
    case screen::KeyCode::Char:
      // `q` closes a pager here as it does in every pager. Without it the
      // only way off this screen is Escape, and a block long enough to scroll
      // is exactly where somebody reaches for `q`.
      if (key.text == "q") {
        close_pager();
      }
      return ActionKind::None;
    default:
      return ActionKind::None;
  }
}

void Model::close_pager() {
  for (std::string& line : pager_) {
    wipe_string(line);
  }
  pager_.clear();
  pager_notes_.clear();
  pager_heading_.clear();
  pager_top_ = 0;
  go(Screen::Home);
}

ActionKind Model::handle_key(const screen::Key& key) {
  // Ctrl-C means the same thing everywhere and cannot be shadowed by a screen.
  // It arrives as a keystroke rather than a signal precisely so that the exit
  // runs through the ordinary path, which wipes the vault out of memory on its
  // way; a signal handler could not do that safely.
  if (key.code == screen::KeyCode::CtrlC) {
    return ActionKind::Quit;
  }
  // A stray byte from a sequence nobody recognised must not count as activity
  // or as a keypress.
  if (key.code == screen::KeyCode::None) {
    return ActionKind::None;
  }

  status_.clear();

  switch (screen_) {
    case Screen::Drive:
    case Screen::Home:
      return key_in_list(key);

    case Screen::DrivePath:
    case Screen::Alias:
    case Screen::Compose:
    case Screen::Paste:
      return key_in_text(key);

    case Screen::Block:
    case Screen::Message:
      return key_in_pager(key);

    case Screen::Setup:
      if (key.code == screen::KeyCode::Escape) {
        go(Screen::Drive);
        return ActionKind::None;
      }
      if (key.code == screen::KeyCode::Char && key.text == "n") {
        return ActionKind::CreateIdentity;
      }
      if (key.code == screen::KeyCode::Char && key.text == "r") {
        return ActionKind::RestoreIdentity;
      }
      return ActionKind::None;

    case Screen::Contact:
      if (key.code == screen::KeyCode::Escape) {
        go(Screen::Home);
        return ActionKind::None;
      }
      if (key.code == screen::KeyCode::Char && key.text == "w") {
        go(Screen::Compose);
        return ActionKind::None;
      }
      if (key.code == screen::KeyCode::Char && key.text == "t") {
        return ActionKind::Trust;
      }
      return ActionKind::None;
  }
  return ActionKind::None;
}

// --- drawing -----------------------------------------------------------------

std::string_view Model::footer_keys() const {
  switch (screen_) {
    case Screen::Drive:
      return i18n::t(lang_, Str::KeysDrive);
    case Screen::DrivePath:
    case Screen::Alias:
      return i18n::t(lang_, Str::KeysText);
    case Screen::Setup:
      return i18n::t(lang_, Str::KeysSetup);
    case Screen::Home:
      return i18n::t(lang_, Str::KeysHome);
    case Screen::Contact:
      return i18n::t(lang_, Str::KeysContact);
    case Screen::Compose:
      return i18n::t(lang_, Str::KeysCompose);
    case Screen::Paste:
      return i18n::t(lang_, Str::KeysPaste);
    case Screen::Block:
    case Screen::Message:
      return i18n::t(lang_, Str::KeysBlock);
  }
  return {};
}

void Model::render_header(screen::Frame& frame) const {
  std::string title = std::string(cli::kProgram) + " " + cli::kVersion;
  if (!drive_path_.empty() && unlocked_) {
    const std::size_t room = frame.width() > title.size() + 4
                                 ? frame.width() - title.size() - 4
                                 : 0;
    const std::string path = screen::truncate_to_width(drive_path_, room);
    const std::size_t used = title.size() + screen::display_width(path) + 4;
    title += std::string(frame.width() > used ? frame.width() - used : 1, ' ');
    title += path;
  } else {
    title += "  -  ";
    title += i18n::t(lang_, Str::Subtitle);
  }
  frame.line(indent(title));
  frame.line(rule(frame.width()));
}

void Model::render_body(screen::Frame& frame, std::size_t rows) const {
  const std::size_t before = frame.lines().size();
  const std::size_t inner =
      frame.width() > kIndent.size() * 2 ? frame.width() - kIndent.size() * 2 : 1;

  switch (screen_) {
    case Screen::Drive: {
      if (drives_.empty()) {
        frame.line(indent(i18n::t(lang_, Str::NoDrivesFound)));
        frame.blank();
        frame.line(indent(i18n::t(lang_, Str::PressPForPath)));
        break;
      }
      frame.line(indent(i18n::t(lang_, Str::ChooseDrive)));
      frame.blank();
      // The window slides with the selection, so a machine with more drives
      // than the frame has rows still shows the one that is highlighted.
      const std::size_t room = rows > 3 ? rows - 3 : 1;
      const std::size_t top = (selected_ >= room) ? selected_ - room + 1 : 0;
      for (std::size_t i = top; i < drives_.size() && i < top + room; ++i) {
        const DriveEntry& drive = drives_[i];
        std::string row = std::string(kIndent) + drive.path + "   [" +
                          std::string(i18n::t(lang_, drive.has_vault
                                                         ? Str::DriveHasVault
                                                         : Str::DriveEmpty)) +
                          "]";
        if (i == selected_) {
          frame.highlight(row);
        } else {
          frame.line(row);
        }
      }
      break;
    }

    case Screen::DrivePath:
      frame.line(indent(i18n::t(lang_, Str::TypePath)));
      frame.blank();
      frame.line(indent("> " + text_));
      break;

    case Screen::Setup:
      frame.line(indent(drive_path_));
      frame.blank();
      frame.line(indent(i18n::t(lang_, Str::NoVaultHere)));
      frame.blank();
      frame.line(indent(i18n::t(lang_, Str::SetupNew)));
      frame.line(indent(i18n::t(lang_, Str::SetupRestore)));
      break;

    case Screen::Home: {
      frame.line(indent(i18n::t(lang_, Str::YourFingerprint)));
      frame.line(indent(fingerprint_));
      frame.blank();
      frame.line(indent(i18n::t(lang_, Str::Contacts)));
      if (contacts_.empty()) {
        frame.blank();
        frame.line(indent(i18n::t(lang_, Str::NoContacts)));
        frame.line(indent(i18n::t(lang_, Str::NoContactsHint)));
        break;
      }
      const std::size_t room = rows > 5 ? rows - 5 : 1;
      const std::size_t top = (selected_ >= room) ? selected_ - room + 1 : 0;
      for (std::size_t i = top; i < contacts_.size() && i < top + room; ++i) {
        const ContactRow& contact = contacts_[i];
        // The badges go first: an alias is chosen by somebody else and can be
        // as long as they like, so anything appended after it is the part that
        // gets truncated away. "NOT verified" has to be the part that stays.
        std::string row = std::string(kIndent) + "[" +
                          std::string(i18n::t(lang_, contact.verified
                                                         ? Str::Verified
                                                         : Str::Unverified)) +
                          "] [" +
                          std::string(i18n::t(lang_, contact.has_session
                                                         ? Str::HasSession
                                                         : Str::NoSession)) +
                          "] " + contact.alias;
        if (i == selected_) {
          frame.highlight(row);
        } else {
          frame.line(row);
        }
      }
      break;
    }

    case Screen::Contact: {
      const ContactRow* contact = selected_contact();
      if (contact == nullptr) {
        break;
      }
      frame.line(indent("[" +
                        std::string(i18n::t(lang_, contact->verified
                                                       ? Str::Verified
                                                       : Str::Unverified)) +
                        "] " + contact->alias));
      frame.blank();
      frame.line(indent(i18n::t(lang_, Str::Fingerprint)));
      for (const std::string& line :
           screen::wrap_text(contact->fingerprint, inner)) {
        frame.line(indent(line));
      }
      frame.blank();
      if (!contact->verified) {
        frame.line(indent(i18n::t(lang_, Str::VerifyHint)));
      }
      break;
    }

    case Screen::Compose: {
      const ContactRow* contact = selected_contact();
      frame.line(indent(std::string(i18n::t(lang_, Str::WritingTo)) + " " +
                        (contact != nullptr ? contact->alias : std::string())));
      frame.line(indent(i18n::t(lang_, Str::ComposeHint)));
      frame.blank();
      const std::vector<std::string> lines = screen::wrap_text(text_, inner);
      const std::size_t room = rows > 3 ? rows - 3 : 1;
      const std::size_t top = lines.size() > room ? lines.size() - room : 0;
      for (std::size_t i = top; i < lines.size(); ++i) {
        frame.line(indent(lines[i]));
      }
      break;
    }

    case Screen::Alias:
      frame.line(indent(i18n::t(lang_, Str::AliasPrompt)));
      frame.blank();
      frame.line(indent("> " + text_));
      break;

    case Screen::Paste:
      frame.line(indent(i18n::t(lang_, pasting_card_ ? Str::PasteCard
                                                     : Str::PasteBlock)));
      frame.blank();
      // What was pasted is deliberately not drawn. A card or a message block
      // is a screenful of base64 that tells the user nothing, and a message
      // being replied to would be sitting there in the clear; the count is
      // what they actually need to know.
      if (text_.empty()) {
        frame.line(indent(i18n::t(lang_, Str::NothingPasted)));
      } else {
        frame.line(indent(std::to_string(text_.size()) + " " +
                          std::string(i18n::t(lang_, Str::CharsReceived))));
      }
      break;

    case Screen::Block:
    case Screen::Message: {
      frame.line(indent(pager_heading_));
      for (const std::string& note : pager_notes_) {
        frame.line(indent(note));
      }
      if (screen_ == Screen::Block) {
        frame.line(indent(i18n::t(lang_, Str::CopyBlock)));
      }
      frame.blank();
      const std::size_t used = frame.lines().size() - before;
      const std::size_t room = rows > used ? rows - used : 1;
      for (std::size_t i = pager_top_; i < pager_.size() && i < pager_top_ + room;
           ++i) {
        frame.line(indent(pager_[i]));
      }
      break;
    }
  }

  // Pad out to the promised height so the footer always lands on the same row.
  for (std::size_t i = frame.lines().size() - before; i < rows; ++i) {
    frame.blank();
  }
}

void Model::render_footer(screen::Frame& frame) const {
  frame.line(rule(frame.width()));
  frame.line(indent(status_));
  frame.line(indent(footer_keys()));
}

void Model::render(screen::Frame& frame) const {
  frame.clear();
  const std::size_t rows = frame.height() > kHeaderRows + kFooterRows
                               ? frame.height() - kHeaderRows - kFooterRows
                               : 1;
  render_header(frame);
  render_body(frame, rows);
  render_footer(frame);

  // The cursor sits at the end of whatever is being typed, and nowhere else:
  // on a list screen there is nothing to type into, so it stays hidden.
  if (screen_ == Screen::DrivePath || screen_ == Screen::Alias) {
    frame.cursor(kHeaderRows + (screen_ == Screen::Alias ? 3 : 4),
                 kIndent.size() + 3 + screen::display_width(text_));
  }
}

}  // namespace ratchet::ui
