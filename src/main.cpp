#include <Windows.h>

#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QLocalServer>
#include <QLocalSocket>
#include <QStyleFactory>
#include <QTextStream>

#include "app/Automation.h"
#include "app/DemoData.h"
#include "app/Lang.h"
#include "app/MainWindow.h"
#include "ui/Icons.h"
#include "ui/Theme.h"

namespace {

// Консоли у приложения нет: предупреждения Qt пишутся в файл, иначе
// причина сбоя теряется.
void WriteLog(QtMsgType type, const QMessageLogContext&, const QString& msg) {
    static QFile file(QDir::temp().filePath("ThreatScanner-debug.log"));
    static bool opened = file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
    if (!opened) return;
    const char* tag = type == QtWarningMsg ? "WARN" : type == QtCriticalMsg ? "CRIT"
                    : type == QtFatalMsg ? "FATAL" : "INFO";
    QTextStream out(&file);
    out << QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz") << " [" << tag << "] " << msg << "\n";
}

QString InstanceKey() {
    wchar_t user[256] = {};
    DWORD n = 256;
    GetUserNameW(user, &n);
    return "ThreatScanner-" + QString::fromWCharArray(user);
}

} // namespace

int main(int argc, char* argv[]) {
    qInstallMessageHandler(WriteLog);
    QApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
    QApplication app(argc, argv);
    QApplication::setOrganizationName("ThreatScanner");
    QApplication::setApplicationName("ThreatScanner");
    QApplication::setApplicationVersion(TS_VERSION);
    // Fusion — предсказуемая основа для таблицы стилей: системный стиль
    // Windows 11 рисует часть элементов сам и перебивает наши цвета.
    QApplication::setStyle(QStyleFactory::create("Fusion"));
    QApplication::setFont(Ui::Font::make(Ui::Font::Body));
    QApplication::setWindowIcon(Icons::appIcon());

    const QStringList args = QApplication::arguments();

    // Служебные режимы для разработки.
    const int shotsAt = args.indexOf("--shots");
    if (shotsAt >= 0 && shotsAt + 1 < args.size()) {
        Ui::Theme::instance();
        return DemoData::RunScreenshotTour(args[shotsAt + 1]) > 0 ? 0 : 1;
    }
    const int iconAt = args.indexOf("--render-icon");
    if (iconAt >= 0 && iconAt + 1 < args.size()) {
        QDir().mkpath(args[iconAt + 1]);
        for (int s : { 16, 20, 24, 32, 40, 48, 64, 128, 256 }) {
            QPixmap pm = Icons::logo(s);
            pm.setDevicePixelRatio(1.0);
            pm.scaled(s, s, Qt::IgnoreAspectRatio, Qt::SmoothTransformation)
                .save(QString("%1/logo-%2.png").arg(args[iconAt + 1]).arg(s));
        }
        return 0;
    }

    // Один экземпляр на пользователя: второй запуск (ярлык, автозапуск)
    // показывает уже открытое окно, а не поднимает вторую копию с трей-иконкой.
    const QString key = InstanceKey();
    {
        QLocalSocket probe;
        probe.connectToServer(key);
        if (probe.waitForConnected(300)) {
            probe.write("show\n");
            probe.waitForBytesWritten(300);
            return 0;
        }
    }
    QLocalServer::removeServer(key);
    QLocalServer server;
    server.listen(key);

    Ui::Theme::instance();   // таблица стилей до создания виджетов
    MainWindow window;
    QObject::connect(&server, &QLocalServer::newConnection, &window, [&server, &window]() {
        while (QLocalSocket* s = server.nextPendingConnection()) {
            s->deleteLater();
            window.showNormal();
            window.raise();
            window.activateWindow();
        }
    });

    // Автозапуск стартует свёрнутым в трей. Без трея прятать окно некуда —
    // тогда оно просто открывается свёрнутым в панель задач.
    if (!args.contains("--minimized")) window.show();
    else if (!Automation::trayEnabled()) window.showMinimized();
    return app.exec();
}
