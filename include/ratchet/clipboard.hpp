// clipboard.hpp — put an armoured block on the system clipboard.
//
// The terminal interface copies only the two things that are already public:
// this identity's contact card and the encrypted message block it is about to
// show. A decrypted message body never goes near the clipboard.
//
// The clipboard is reached through an external command (wl-copy, xclip or
// xsel) rather than by emitting OSC 52. Writing a raw escape sequence to set
// the clipboard is exactly the kind of terminal-driving the interface refuses
// to do: OSC 52 is interpreted by the terminal emulator, reaches machines on
// the far side of a multiplexer, and hands whatever this process believes is
// on screen to anything that reads the X/Wayland selection.

#ifndef RATCHET_CLIPBOARD_HPP
#define RATCHET_CLIPBOARD_HPP

#include <cstddef>
#include <string>
#include <string_view>

namespace ratchet::clipboard {

// Upper bound on what paste() will read, so a hostile or runaway clipboard
// cannot make the process allocate without limit.
inline constexpr std::size_t kMaxPasteBytes =
    std::size_t{8} * 1024u * 1024u;

// Places `text` on the system clipboard using the first backend found on PATH,
// trying wl-copy, then xclip, then xsel. Throws ratchet::Error when none is
// available or the chosen one fails.
//
// The command is exec'd directly, never through a shell.
void copy(std::string_view text);

// Reads the system clipboard, trying wl-paste, then xclip, then xsel. Throws
// ratchet::Error when none is available, the chosen one fails, or the content
// is larger than kMaxPasteBytes.
//
// This is what Ctrl-V is bound to in the text fields. The terminal's own paste
// (Ctrl-Shift-V, middle click) keeps working on top of it.
std::string paste();

}  // namespace ratchet::clipboard

#endif  // RATCHET_CLIPBOARD_HPP
