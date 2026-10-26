#include <QApplication>

#include <sys/resource.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#include "main_window.hpp"

namespace {

// The GUI holds the vault passphrase in its widgets and the CLI's decrypted
// output in ordinary Qt strings, so it gets the same two process-wide
// protections as ratchet-usb before any of them exist:
//
//   * RLIMIT_CORE=0: a crash must not write those strings into a core file.
//   * PR_SET_DUMPABLE=0: a same-user process must not attach and read them.
//
// This is best-effort, not a sandbox. Qt keeps implicit copies the program
// cannot see, and a host with enough privilege can still inspect the process.
// The CLI child applies its own copy of the same hardening when it starts.
void harden_gui_process() noexcept {
  const struct rlimit no_core = {0, 0};
  (void)setrlimit(RLIMIT_CORE, &no_core);
#if defined(__linux__)
  (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

}  // namespace

int main(int argc, char** argv) {
  harden_gui_process();
  QApplication app(argc, argv);
  QApplication::setApplicationName(QStringLiteral("ratchet-gui"));
  QApplication::setApplicationDisplayName(QStringLiteral("Ratchet-USB GUI"));

  MainWindow window;
  window.resize(920, 680);
  window.show();
  return app.exec();
}
