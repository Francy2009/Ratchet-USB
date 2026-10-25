#include <QtTest>

#include "host_env.hpp"

// The AppImage bug this guards against: xdg-open/gio inherited the bundle's
// LD_LIBRARY_PATH, loaded the bundle's libglib, and died with a symbol error
// before the file manager ever appeared. The fix is entirely in this helper.

class HostEnvTest : public QObject {
  Q_OBJECT

 private slots:
  void stripsBundlePaths();
  void leavesTheEnvironmentAloneWithoutAppDir();
  void removesVariablesThatWereOnlyTheBundle();
  void cleanup();
};

void HostEnvTest::cleanup() {
  for (const char* name :
       {"APPDIR", "LD_LIBRARY_PATH", "QT_PLUGIN_PATH", "QML2_IMPORT_PATH",
        "XDG_DATA_DIRS", "QT_QPA_PLATFORMTHEME"}) {
    qunsetenv(name);
  }
}

void HostEnvTest::stripsBundlePaths() {
  qputenv("APPDIR", "/tmp/ratchet-appdir");
  qputenv("LD_LIBRARY_PATH", "/tmp/ratchet-appdir/usr/lib:/opt/host/lib");
  qputenv("QT_PLUGIN_PATH", "/tmp/ratchet-appdir/usr/plugins:/opt/host/plugins");
  qputenv("XDG_DATA_DIRS",
          "/tmp/ratchet-appdir/usr/share:/usr/local/share:/usr/share");
  qputenv("QML2_IMPORT_PATH", "/tmp/ratchet-appdir/usr/qml");
  qputenv("QT_QPA_PLATFORMTHEME", "gtk2");

  const QProcessEnvironment env = ratchet::gui::hostProcessEnvironment();
  QCOMPARE(env.value("LD_LIBRARY_PATH"), QStringLiteral("/opt/host/lib"));
  QCOMPARE(env.value("QT_PLUGIN_PATH"), QStringLiteral("/opt/host/plugins"));
  QCOMPARE(env.value("XDG_DATA_DIRS"),
           QStringLiteral("/usr/local/share:/usr/share"));
  QVERIFY(!env.contains("QML2_IMPORT_PATH"));
  QVERIFY(!env.contains("QT_QPA_PLATFORMTHEME"));
}

void HostEnvTest::leavesTheEnvironmentAloneWithoutAppDir() {
  qunsetenv("APPDIR");
  qputenv("LD_LIBRARY_PATH", "/opt/host/lib");
  qputenv("QT_QPA_PLATFORMTHEME", "gtk2");

  const QProcessEnvironment env = ratchet::gui::hostProcessEnvironment();
  QCOMPARE(env.value("LD_LIBRARY_PATH"), QStringLiteral("/opt/host/lib"));
  QCOMPARE(env.value("QT_QPA_PLATFORMTHEME"), QStringLiteral("gtk2"));
}

void HostEnvTest::removesVariablesThatWereOnlyTheBundle() {
  qputenv("APPDIR", "/tmp/ratchet-appdir");
  qputenv("LD_LIBRARY_PATH", "/tmp/ratchet-appdir/usr/lib");
  qputenv("QT_PLUGIN_PATH", "/tmp/ratchet-appdir/usr/plugins");
  qputenv("XDG_DATA_DIRS", "/tmp/ratchet-appdir/usr/share");
  qputenv("QT_QPA_PLATFORMTHEME", "gtk2");

  const QProcessEnvironment env = ratchet::gui::hostProcessEnvironment();
  QVERIFY(!env.contains("LD_LIBRARY_PATH"));
  QVERIFY(!env.contains("QT_PLUGIN_PATH"));
  QVERIFY(!env.contains("XDG_DATA_DIRS"));
  QVERIFY(!env.contains("QT_QPA_PLATFORMTHEME"));
}

QTEST_GUILESS_MAIN(HostEnvTest)
#include "test_host_env.moc"
