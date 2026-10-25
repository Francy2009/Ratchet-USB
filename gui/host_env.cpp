#include "host_env.hpp"

#include <QStringList>

namespace ratchet::gui {

QProcessEnvironment hostProcessEnvironment() {
  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  const QString appdir = env.value(QStringLiteral("APPDIR"));
  if (appdir.isEmpty()) {
    return env;
  }
  const QStringList path_vars{
      QStringLiteral("LD_LIBRARY_PATH"),
      QStringLiteral("QT_PLUGIN_PATH"),
      QStringLiteral("QML2_IMPORT_PATH"),
      QStringLiteral("XDG_DATA_DIRS"),
  };
  for (const QString& name : path_vars) {
    if (!env.contains(name)) continue;
    QStringList kept;
    for (const QString& part :
         env.value(name).split(QLatin1Char(':'), Qt::SkipEmptyParts)) {
      if (!part.startsWith(appdir)) kept << part;
    }
    if (kept.isEmpty()) {
      env.remove(name);
    } else {
      env.insert(name, kept.join(QLatin1Char(':')));
    }
  }
  // Set by the AppImage's Qt hook on GNOME/XFCE; it should not leak to host
  // applications that happen to use Qt.
  env.remove(QStringLiteral("QT_QPA_PLATFORMTHEME"));
  return env;
}

}  // namespace ratchet::gui
