#include <QApplication>

#include "main_window.hpp"

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  QApplication::setApplicationName(QStringLiteral("ratchet-gui"));
  QApplication::setApplicationDisplayName(QStringLiteral("Ratchet-USB GUI"));

  MainWindow window;
  window.resize(920, 680);
  window.show();
  return app.exec();
}
