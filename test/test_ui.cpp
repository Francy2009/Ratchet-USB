#include <string>
#include <vector>

#include "ratchet/screen.hpp"
#include "ratchet/ui.hpp"
#include "test_support.hpp"

using namespace ratchet;
using ui::ActionKind;
using ui::ContactRow;
using ui::DriveEntry;
using ui::Model;
using ui::Screen;

namespace {

screen::Key ch(const char* text) {
  screen::Key key;
  key.code = screen::KeyCode::Char;
  key.text = text;
  return key;
}

screen::Key code(screen::KeyCode c) {
  screen::Key key;
  key.code = c;
  return key;
}

// The whole frame as one string, which is what a test wants to search.
std::string draw(const Model& model, std::size_t width = 80,
                 std::size_t height = 24) {
  screen::Frame frame(width, height);
  model.render(frame);
  std::string all;
  for (const std::string& line : frame.lines()) {
    all += line;
    all += "\n";
  }
  return all;
}

Model unlocked_model(std::vector<ContactRow> contacts) {
  Model model(i18n::Lang::En);
  model.show_drives({DriveEntry{"/media/usb", true}});
  model.show_home("/media/usb", "AAAA BBBB CCCC DDDD", std::move(contacts));
  return model;
}

ContactRow contact(std::string alias, bool verified = false) {
  ContactRow row;
  row.alias = std::move(alias);
  row.fingerprint = "1111 2222 3333 4444";
  row.verified = verified;
  return row;
}

}  // namespace

// --- what a hostile alias must not be able to do -----------------------------

TEST("an alias cannot smuggle an escape sequence onto the screen") {
  // The alias comes off a card somebody else wrote. An unescaped ESC would let
  // them move the cursor and repaint the warning printed next to their name.
  Model model = unlocked_model({contact("\033[2Ktrusted\033[1;32m")});
  const std::string frame = draw(model);
  CHECK(frame.find('\033') == std::string::npos);
  CHECK(frame.find("\\x1b") != std::string::npos);
}

TEST("a very long alias cannot push the trust badge off its row") {
  // The badge is drawn before the alias for exactly this reason: whatever gets
  // truncated away, it is not the part that says the contact is unverified.
  Model model = unlocked_model({contact(std::string(5000, 'a'))});
  const std::string frame = draw(model);
  CHECK(frame.find("NOT verified") != std::string::npos);
}

TEST("a long alias cannot make the frame taller than the screen") {
  Model model = unlocked_model({contact(std::string(5000, 'a'))});
  screen::Frame frame(80, 24);
  model.render(frame);
  CHECK(frame.lines().size() <= std::size_t{24});
}

TEST("a crowd of contacts cannot push the menu or the hints off the screen") {
  std::vector<ContactRow> many;
  for (int i = 0; i < 500; ++i) {
    many.push_back(contact("contact" + std::to_string(i)));
  }
  Model model = unlocked_model(std::move(many));
  screen::Frame frame(80, 24);
  model.render(frame);
  CHECK(frame.lines().size() <= std::size_t{24});
  // The last line is still the key hints, not the five-hundredth contact,
  // and the way out is still on screen above it.
  CHECK(frame.lines().back().find("Enter choose") != std::string::npos);
  CHECK(draw(model).find("[ Quit ]") != std::string::npos);
}

TEST("a decrypted message cannot repaint the screen either") {
  Model model = unlocked_model({contact("alice")});
  model.show_message("alice", "hello\033[1A\033[2Kdifferent text", false, true);
  const std::string frame = draw(model);
  CHECK(frame.find('\033') == std::string::npos);
  CHECK(frame.find("hello") != std::string::npos);
  // The warning about the sender being unverified is on screen with it.
  CHECK(frame.find("NOT verified") != std::string::npos);
}

// --- navigation ---------------------------------------------------------------

TEST("the arrow keys move through the contact list and wrap around") {
  Model model = unlocked_model({contact("alice"), contact("bob")});
  CHECK_EQ(model.selected(), std::size_t{0});
  model.handle_key(code(screen::KeyCode::Down));
  CHECK_EQ(model.selected(), std::size_t{1});
  model.handle_key(code(screen::KeyCode::Down));
  CHECK_EQ(model.selected(), std::size_t{0});
  model.handle_key(code(screen::KeyCode::Up));
  CHECK_EQ(model.selected(), std::size_t{1});
}

TEST("opening a contact and writing to them reaches Send") {
  Model model = unlocked_model({contact("alice")});
  model.handle_key(code(screen::KeyCode::Enter));
  CHECK(model.screen() == Screen::Contact);
  model.handle_key(ch("w"));
  CHECK(model.screen() == Screen::Compose);
  for (const char* letter : {"h", "i"}) {
    model.handle_key(ch(letter));
  }
  CHECK_EQ(model.text(), std::string("hi"));
  CHECK(model.handle_key(code(screen::KeyCode::CtrlD)) == ActionKind::Send);
}

TEST("Enter is a line break while writing, not a send") {
  Model model = unlocked_model({contact("alice")});
  model.handle_key(code(screen::KeyCode::Enter));
  model.handle_key(ch("w"));
  model.handle_key(ch("a"));
  CHECK(model.handle_key(code(screen::KeyCode::Enter)) == ActionKind::None);
  model.handle_key(ch("b"));
  CHECK_EQ(model.text(), std::string("a\nb"));
}

TEST("adding a contact asks for a name before the card") {
  Model model = unlocked_model({});
  model.handle_key(ch("a"));
  CHECK(model.screen() == Screen::Alias);
  model.handle_key(ch("b"));
  model.handle_key(code(screen::KeyCode::Enter));
  CHECK(model.screen() == Screen::Paste);
  CHECK_EQ(model.alias(), std::string("b"));
  model.handle_key(ch("x"));
  CHECK(model.handle_key(code(screen::KeyCode::CtrlD)) == ActionKind::ImportCard);
}

TEST("reading a message goes straight to the paste screen") {
  Model model = unlocked_model({contact("alice")});
  model.handle_key(ch("r"));
  CHECK(model.screen() == Screen::Paste);
  model.handle_key(ch("x"));
  CHECK(model.handle_key(code(screen::KeyCode::CtrlD)) == ActionKind::Receive);
}

TEST("an empty field does not confirm") {
  Model model = unlocked_model({});
  model.handle_key(ch("a"));
  // Enter on an empty alias stays put rather than creating a nameless contact.
  CHECK(model.handle_key(code(screen::KeyCode::Enter)) == ActionKind::None);
  CHECK(model.screen() == Screen::Alias);
}

TEST("Escape backs out of a screen and takes the typing with it") {
  Model model = unlocked_model({contact("alice")});
  model.handle_key(ch("r"));
  model.handle_key(ch("s"));
  model.handle_key(ch("e"));
  CHECK(!model.text().empty());
  model.handle_key(code(screen::KeyCode::Escape));
  CHECK(model.screen() == Screen::Home);
  CHECK(model.text().empty());
}

TEST("Ctrl-C quits from every screen") {
  // It arrives as a keystroke rather than a signal so the exit runs through
  // the ordinary path, which wipes the keys on the way out.
  const std::vector<const char*> route = {"r", "a", "c", "l"};
  for (const char* first : route) {
    Model model = unlocked_model({contact("alice")});
    model.handle_key(ch(first));
    CHECK(model.handle_key(code(screen::KeyCode::CtrlC)) == ActionKind::Quit);
  }
}

// --- what locking has to take with it ----------------------------------------

TEST("locking clears everything the vault put on screen") {
  Model model = unlocked_model({contact("alice", true)});
  model.handle_key(ch("r"));
  model.handle_key(ch("s"));
  model.show_message("alice", "a secret", false, false);

  model.forget();

  CHECK(!model.unlocked());
  CHECK(model.screen() != Screen::Home);
  const std::string frame = draw(model);
  CHECK(frame.find("alice") == std::string::npos);
  CHECK(frame.find("a secret") == std::string::npos);
  CHECK(frame.find("AAAA") == std::string::npos);  // the fingerprint
  CHECK(model.text().empty());
}

TEST("after locking there is still a way out") {
  // Locking goes back to the drive screen, and with no drive detected that
  // screen used to be a path field -- where `q` typed a `q` and the only exit
  // was Ctrl-C.
  Model model = unlocked_model({contact("alice")});
  model.forget();
  CHECK(model.handle_key(ch("q")) == ActionKind::Quit);
}

TEST("a pager closes on q as well as Escape") {
  Model model = unlocked_model({contact("alice")});
  model.show_block("card", "-----BEGIN-----\nAAAA\n-----END-----");
  CHECK(model.screen() == Screen::Block);
  model.handle_key(ch("q"));
  CHECK(model.screen() == Screen::Home);
}

TEST("locking is reachable from the contact list") {
  Model model = unlocked_model({contact("alice")});
  CHECK(model.handle_key(ch("l")) == ActionKind::Lock);
}

// --- the paste screen ---------------------------------------------------------

TEST("what was pasted is counted, never drawn") {
  // A pasted block is a screenful of base64 that says nothing, and a message
  // being replied to would be sitting there in the clear.
  Model model = unlocked_model({contact("alice")});
  model.handle_key(ch("r"));
  for (const char* letter : {"s", "e", "c", "r", "e", "t"}) {
    model.handle_key(ch(letter));
  }
  const std::string frame = draw(model);
  CHECK(frame.find("secret") == std::string::npos);
  CHECK(frame.find("6 characters received") != std::string::npos);
}

TEST("bracketed paste markers are not text") {
  Model model = unlocked_model({contact("alice")});
  model.handle_key(ch("r"));
  model.handle_key(code(screen::KeyCode::PasteBegin));
  model.handle_key(ch("x"));
  model.handle_key(code(screen::KeyCode::PasteEnd));
  CHECK_EQ(model.text(), std::string("x"));
}

TEST("backspace removes a whole character, not one byte of it") {
  Model model = unlocked_model({contact("alice")});
  model.handle_key(ch("r"));
  model.handle_key(ch("è"));  // two bytes
  CHECK_EQ(model.text().size(), std::size_t{2});
  model.handle_key(code(screen::KeyCode::Backspace));
  CHECK(model.text().empty());
}

// --- picking a drive ----------------------------------------------------------

TEST("a drive with a vault on it is marked as such") {
  Model model(i18n::Lang::En);
  model.show_drives({DriveEntry{"/media/one", true}, DriveEntry{"/media/two", false}});
  CHECK(model.screen() == Screen::Drive);
  const std::string frame = draw(model);
  CHECK(frame.find("/media/one") != std::string::npos);
  CHECK(frame.find("[vault]") != std::string::npos);
  CHECK(frame.find("[empty]") != std::string::npos);
  CHECK(model.handle_key(code(screen::KeyCode::Enter)) == ActionKind::UseDrive);
  CHECK(model.selected_drive() != nullptr);
  CHECK_EQ(model.selected_drive()->path, std::string("/media/one"));
}

TEST("with no drive detected the interface offers to take a path") {
  Model model(i18n::Lang::En);
  model.show_drives({});
  // It rests on the drive screen even with nothing on it, so `q` is still
  // there. A text field where every key is a character has no way out.
  CHECK(model.screen() == Screen::Drive);
  CHECK(draw(model).find("No removable drive") != std::string::npos);
  CHECK(model.handle_key(ch("q")) == ActionKind::Quit);
  model.handle_key(ch("p"));
  CHECK(model.screen() == Screen::DrivePath);
  model.handle_key(ch("/"));
  model.handle_key(ch("m"));
  CHECK(model.handle_key(code(screen::KeyCode::Enter)) == ActionKind::UseTypedPath);
  CHECK_EQ(model.text(), std::string("/m"));
}

TEST("a drive with no vault offers to set one up") {
  Model model(i18n::Lang::En);
  model.show_setup("/media/usb");
  CHECK(model.screen() == Screen::Setup);
  CHECK(model.handle_key(ch("n")) == ActionKind::CreateIdentity);
  CHECK(model.handle_key(ch("r")) == ActionKind::RestoreIdentity);
}

// --- both languages -----------------------------------------------------------

TEST("the interface draws in Italian when asked") {
  Model model(i18n::Lang::It);
  model.show_drives({DriveEntry{"/media/usb", true}});
  const std::string frame = draw(model);
  CHECK(frame.find("Scegli") != std::string::npos);
}

TEST("every string exists in both languages") {
  for (std::size_t i = 0; i < static_cast<std::size_t>(i18n::Str::Count); ++i) {
    const auto id = static_cast<i18n::Str>(i);
    CHECK(!i18n::t(i18n::Lang::En, id).empty());
    CHECK(!i18n::t(i18n::Lang::It, id).empty());
  }
}

TEST("a language is only chosen by an explicit flag or the locale") {
  CHECK(i18n::detect("it") == i18n::Lang::It);
  CHECK(i18n::detect("en") == i18n::Lang::En);
  CHECK(i18n::is_valid_choice("it"));
  CHECK(i18n::is_valid_choice("en"));
  CHECK(!i18n::is_valid_choice("fr"));
  CHECK(!i18n::is_valid_choice(""));
}

// --- the frame stays inside its bounds on any screen --------------------------

TEST("no screen draws outside the frame, however small it is") {
  std::vector<ContactRow> contacts = {contact("alice"), contact("bob", true)};
  for (std::size_t height : {6, 10, 24, 60}) {
    for (std::size_t width : {20, 40, 80}) {
      Model model = unlocked_model(contacts);
      // Walk through every screen the interface has.
      const std::vector<screen::Key> walk = {
          ch("a"), code(screen::KeyCode::Escape), ch("r"),
          code(screen::KeyCode::Escape), code(screen::KeyCode::Enter), ch("w"),
          code(screen::KeyCode::Escape)};
      for (const screen::Key& key : walk) {
        model.handle_key(key);
        screen::Frame frame(width, height);
        model.render(frame);
        CHECK(frame.lines().size() <= height);
        for (const std::string& line : frame.lines()) {
          CHECK(screen::display_width(line) <= width);
        }
      }
    }
  }
}

// --- the menu ------------------------------------------------------------------

TEST("the list screens carry a menu and the typing screens do not") {
  Model model = unlocked_model({contact("alice")});
  CHECK(!model.menu().empty());          // Home
  model.handle_key(code(screen::KeyCode::Enter));
  CHECK(!model.menu().empty());          // Contact
  model.handle_key(ch("w"));
  CHECK(model.screen() == Screen::Compose);
  // Every key here is a character; a row of actions would be something the
  // arrow keys fight over while somebody is trying to type.
  CHECK(model.menu().empty());
}

TEST("left and right steer the menu, up and down the list") {
  Model model = unlocked_model({contact("alice"), contact("bob")});
  CHECK(model.focus() == ui::Focus::Body);
  model.handle_key(code(screen::KeyCode::Right));
  CHECK(model.focus() == ui::Focus::Menu);
  // Up and down always mean the list, so nobody has to remember which half
  // the cursor is in.
  model.handle_key(code(screen::KeyCode::Down));
  CHECK(model.focus() == ui::Focus::Body);
  CHECK_EQ(model.selected(), std::size_t{1});
}

TEST("choosing a menu entry does exactly what its shortcut does") {
  // The menu is a visible spelling of the shortcuts, not a second way in. If
  // the two could drift apart, one of them would eventually be wrong.
  Model reference = unlocked_model({contact("alice")});
  const std::vector<ui::MenuEntry> items = reference.menu();
  CHECK(!items.empty());

  for (std::size_t i = 0; i < items.size(); ++i) {
    // Press the key directly.
    Model by_key = unlocked_model({contact("alice")});
    screen::Key key;
    key.code = items[i].code;
    if (items[i].code == screen::KeyCode::Char) {
      key.text = std::string(1, items[i].shortcut);
    }
    const ActionKind from_key = by_key.handle_key(key);

    // Walk the menu to the same entry and press Enter.
    Model by_menu = unlocked_model({contact("alice")});
    by_menu.handle_key(code(screen::KeyCode::Right));  // focus the menu, entry 0
    for (std::size_t step = 0; step < i; ++step) {
      by_menu.handle_key(code(screen::KeyCode::Right));
    }
    const ActionKind from_menu = by_menu.handle_key(code(screen::KeyCode::Enter));

    CHECK(from_key == from_menu);
    CHECK(by_key.screen() == by_menu.screen());
  }
}

TEST("the menu offers to verify only a contact that is not verified") {
  const auto has_verify = [](const Model& model) {
    for (const ui::MenuEntry& item : model.menu()) {
      if (item.label == i18n::Str::MenuVerify) {
        return true;
      }
    }
    return false;
  };

  Model unverified = unlocked_model({contact("alice", false)});
  unverified.handle_key(code(screen::KeyCode::Enter));
  CHECK(has_verify(unverified));

  Model verified = unlocked_model({contact("alice", true)});
  verified.handle_key(code(screen::KeyCode::Enter));
  CHECK(!has_verify(verified));
}

TEST("a menu cursor left past the end of a shrinking menu still works") {
  // Verifying a contact removes an entry from under the cursor.
  Model model = unlocked_model({contact("alice", false)});
  model.handle_key(code(screen::KeyCode::Enter));
  model.handle_key(code(screen::KeyCode::Left));  // the last entry, Back
  model.show_contacts({contact("alice", true)});  // the menu is one shorter now
  // Whatever it lands on, it must be an entry that exists.
  CHECK(model.handle_key(code(screen::KeyCode::Enter)) != ActionKind::Send);
}

TEST("the menu never draws past the edge, however narrow the screen") {
  Model model = unlocked_model({contact("alice")});
  for (std::size_t width : {24, 40, 60, 80, 120}) {
    screen::Frame frame(width, 24);
    model.render(frame);
    for (const std::string& line : frame.lines()) {
      CHECK(screen::display_width(line) <= width);
    }
    // Wrapped, never truncated: an action cut in half is one nobody can find.
    std::string all;
    for (const std::string& line : frame.lines()) {
      all += line + "\n";
    }
    CHECK(all.find("[ Quit ]") != std::string::npos);
  }
}

// --- the banner ----------------------------------------------------------------

TEST("the banner shows on the way in and gets out of the way afterwards") {
  Model locked(i18n::Lang::En);
  locked.show_drives({DriveEntry{"/media/usb", true}});
  CHECK(draw(locked, 80, 24).find("|_| \\_\\") != std::string::npos);

  // Once a vault is open the space belongs to the contact list, and the header
  // has something more useful to say.
  Model open = unlocked_model({contact("alice")});
  CHECK(draw(open, 80, 24).find("|_| \\_\\") == std::string::npos);
  CHECK(draw(open, 80, 24).find("/media/usb") != std::string::npos);
}

TEST("the banner steps aside on a small terminal") {
  Model model(i18n::Lang::En);
  model.show_drives({DriveEntry{"/media/usb", true}});
  CHECK(draw(model, 50, 24).find("|_| \\_\\") == std::string::npos);  // too narrow
  CHECK(draw(model, 80, 12).find("|_| \\_\\") == std::string::npos);  // too short
  // And the screen still works without it.
  CHECK(draw(model, 50, 24).find("/media/usb") != std::string::npos);
}
