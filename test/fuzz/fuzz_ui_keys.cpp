// Coverage-guided fuzzing over the terminal interface's input path.
//
// Everything this harness feeds in is something a terminal can hand the
// program: keystrokes, escape sequences, and -- the reason this matters --
// whatever somebody pasted into the window. A message block arrives that way,
// and so does a contact card, which means the bytes here are no more trusted
// than the ones fuzz_parsers works on.
//
// Two contracts are being held to, and both are properties the read loop in
// src/ui.cpp depends on to terminate:
//
//   1. decode_key, with flush set, always consumes at least one byte. If it
//      could return zero the loop would spin on the same input forever.
//   2. Model::handle_key never throws and never leaves the frame bigger than
//      the screen it was given, whatever sequence of keys it is handed.
//
// Build and run:
//
//   cmake -S . -B build-fuzz -DRATCHET_BUILD_FUZZERS=ON \
//         -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
//   cmake --build build-fuzz
//   mkdir -p .fuzz-out
//   ./build-fuzz/test/fuzz/fuzz_ui_keys .fuzz-out test/fuzz/corpus_ui \
//       -max_total_time=60

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "ratchet/screen.hpp"
#include "ratchet/ui.hpp"

namespace {

using namespace ratchet;

// A model with something on every screen, so the keys have somewhere to go and
// something to draw.
ui::Model seeded_model() {
  ui::Model model(i18n::Lang::En);
  model.show_drives({ui::DriveEntry{"/media/usb", true}});

  std::vector<ui::ContactRow> contacts;
  ui::ContactRow alice;
  alice.alias = "alice";
  alice.fingerprint = "1111 2222 3333 4444";
  alice.verified = true;
  contacts.push_back(alice);
  ui::ContactRow bob;
  bob.alias = "bob";
  bob.fingerprint = "5555 6666 7777 8888";
  contacts.push_back(bob);

  model.show_home("/media/usb", "AAAA BBBB CCCC DDDD", std::move(contacts));
  return model;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const std::string_view input(reinterpret_cast<const char*>(data), size);

  ui::Model model = seeded_model();

  std::size_t offset = 0;
  while (offset < input.size()) {
    screen::Key key;
    const std::size_t used = screen::decode_key(input.substr(offset), true, key);
    // Contract 1: with flush set there is always progress. Without it the read
    // loop in the driver would never come back.
    if (used == 0) {
      std::abort();
    }
    offset += used;

    model.handle_key(key);

    // Contract 2: whatever state the keys drove it into, the frame fits the
    // screen. A frame taller than the terminal would scroll the key hints --
    // and, on a message, the "not verified" warning -- out of sight.
    screen::Frame frame(40, 12);
    model.render(frame);
    if (frame.lines().size() > frame.height()) {
      std::abort();
    }
    for (const std::string& line : frame.lines()) {
      if (screen::display_width(line) > frame.width()) {
        std::abort();
      }
      // Nothing drawn may carry an escape byte: that is what stops an alias or
      // a message from repainting the screen around itself.
      if (line.find('\033') != std::string::npos) {
        std::abort();
      }
    }

    // Contract 3: the coloured path emits only the escapes the frame chose.
    // No OSC (a window title would show up in the taskbar and in any screen
    // share) and no bell, whatever the keys were.
    screen::Frame painted(40, 12, /*color=*/true);
    model.render(painted);
    const std::string drawn = painted.render();
    if (drawn.find("\033]") != std::string::npos ||
        drawn.find('\007') != std::string::npos) {
      std::abort();
    }
  }
  return 0;
}
