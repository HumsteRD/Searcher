#include <Windows.h>

#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QFile>
#include <QDir>
#include <QIcon>
#include <QTextStream>
#include <QDateTime>

#include "MainWindow.h"
#include "theme.h"
#include "ui/Icons.h"

namespace {

// Приложение собрано как GUI, консоли у него нет, поэтому предупреждения
// и фатальные сообщения Qt иначе теряются вместе с причиной падения.
void writeLog(QtMsgType type, const QMessageLogContext&, const QString& msg) {
    static QFile file(QDir::temp().filePath("ThreatScanner-debug.log"));
    static bool opened = file.open(QIODevice::WriteOnly | QIODevice::Append
                                   | QIODevice::Text);
    if (!opened) return;

    const char* tag = "INFO";
    switch (type) {
        case QtDebugMsg:    tag = "DEBUG"; break;
        case QtWarningMsg:  tag = "WARN";  break;
        case QtCriticalMsg: tag = "CRIT";  break;
        case QtFatalMsg:    tag = "FATAL"; break;
        default: break;
    }

    QTextStream out(&file);
    out << QDateTime::currentDateTime().toString("hh:mm:ss.zzz")
        << " [" << tag << "] " << msg << "\n";
    out.flush();
}

// Windows 11 регистрирует семейство как "Segoe UI Variable Display" —
// без слова Display имя не совпадает и Qt молча уходит в запасной шрифт,
// из-за чего текст выглядит не так, как в макете.
QFont resolveUiFont() {
    const QStringList families = QFontDatabase::families();

    QString family = "Segoe UI";
    if (families.contains(Theme::FONT_UI))  family = Theme::FONT_UI;
    else if (families.contains("Segoe UI Variable")) family = "Segoe UI Variable";

    QFont f(family, -1);
    f.setPixelSize(Theme::Font::BODY);
    f.setHintingPreference(QFont::PreferNoHinting);
    f.setStyleStrategy(QFont::PreferAntialias);
    return f;
}

} // namespace

int main(int argc, char* argv[]) {
    qInstallMessageHandler(writeLog);

    // Приложение запускается от администратора, проводник — нет, и Windows
    // блокирует передачу данных «снизу вверх» (UIPI). Разрешение нужно
    // выставить ДО того, как Qt зарегистрирует OLE-приёмник перетаскивания,
    // то есть до создания QApplication.
    {
        constexpr UINT kCopyGlobalData = 0x0049;   // нет в заголовках
        ChangeWindowMessageFilter(WM_DROPFILES,   MSGFLT_ADD);
        ChangeWindowMessageFilter(WM_COPYDATA,    MSGFLT_ADD);
        ChangeWindowMessageFilter(kCopyGlobalData, MSGFLT_ADD);
    }

    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName("ThreatScanner");
    QCoreApplication::setApplicationName("ThreatScanner");

    app.setFont(resolveUiFont());
    app.setStyleSheet(Theme::GlobalStyleSheet());
    // Из SVG, а не из .ico: чтение ICO с PNG-записями в Qt ненадёжно.
    QIcon appIcon;
    for (int sz : { 16, 24, 32, 48, 64, 128, 256 }) {
        appIcon.addPixmap(Icons::fromResource("icon", sz,
                                              QColor(Theme::ACCENT_TEXT)));
    }
    app.setWindowIcon(appIcon);

    MainWindow window;
    window.show();

    return app.exec();
}
