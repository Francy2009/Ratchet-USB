#ifndef RATCHET_GUI_HOST_ENV_HPP
#define RATCHET_GUI_HOST_ENV_HPP

#include <QProcessEnvironment>

namespace ratchet::gui {

// The environment for a host program (the file manager), not for a bundled one.
//
// When the GUI runs from the AppImage, AppRun prepends the bundle's directories
// to LD_LIBRARY_PATH. Launching `xdg-open`/`gio` with that path makes them load
// the bundle's libglib/libgio instead of the host's, and they die with a symbol
// error before opening anything -- "Apri cartella" then does nothing at all.
// Drop every search-path entry that points inside $APPDIR and let the host
// tools resolve their own libraries.
QProcessEnvironment hostProcessEnvironment();

}  // namespace ratchet::gui

#endif  // RATCHET_GUI_HOST_ENV_HPP
