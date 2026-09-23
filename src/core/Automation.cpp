#include "Automation.h"
#include "Lang.h"

#include <QApplication>
#include <QWidget>
#include <QTimer>
#include <QSettings>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QIcon>
#include "../ui/Icons.h"
#include "Logger.h"
#include "../theme.h"
#include <QDir>

namespace {

constexpr const char* kOrg = "ThreatScanner";
constexpr const char* kApp = "ThreatScanner";

constexpr const char* kKeySchedule = "auto/schedule";
constexpr const char* kKeyHour     = "auto/hour";
constexpr const char* kKeyLastRun  = "auto/lastRun";
constexpr const char* kKeyTray     = "auto/tray";

// Ветка автозагрузки текущего пользователя: прав администратора не требует,
// в отличие от HKLM.
constexpr const char* kRunKey =
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";

QString exePath() {
    return QDir::toNativeSeparators(QApplication::applicationFilePath());
}

} // namespace

Automation* Automation::self_ = nullptr;

Automation* Automation::instance() { return self_; }

Automation::Automation(QWidget* window, QObject* parent)
    : QObject(parent), window_(window)
{
    self_ = this;

    // Раз в минуту достаточно: расписание задаётся с точностью до часа.
    timer_ = new QTimer(this);
    timer_->setInterval(60 * 1000);
    connect(timer_, &QTimer::timeout, this, &Automation::tick);
    timer_->start();

    applyTraySetting();
}

Automation::~Automation() { if (self_ == this) self_ = nullptr; }

// ─────────────── Автозапуск ───────────────

bool Automation::autostartEnabled() {
    QSettings run(kRunKey, QSettings::NativeFormat);
    return !run.value(kApp).toString().isEmpty();
}

void Automation::setAutostartEnabled(bool on) {
    QSettings run(kRunKey, QSettings::NativeFormat);
    if (on) {
        // Кавычки обязательны: путь может содержать пробелы.
        run.setValue(kApp, "\"" + exePath() + "\"");
    } else {
        run.remove(kApp);
    }
    run.sync();
}

// ─────────────── Расписание ───────────────

Automation::Schedule Automation::schedule() {
    QSettings store(kOrg, kApp);
    return static_cast<Schedule>(store.value(kKeySchedule, 0).toInt());
}

void Automation::setSchedule(Schedule s) {
    QSettings store(kOrg, kApp);
    store.setValue(kKeySchedule, static_cast<int>(s));
    store.sync();
}

int Automation::scheduleHour() {
    QSettings store(kOrg, kApp);
    return store.value(kKeyHour, 12).toInt();
}

void Automation::setScheduleHour(int h) {
    QSettings store(kOrg, kApp);
    store.setValue(kKeyHour, qBound(0, h, 23));
    store.sync();
}

QDateTime Automation::lastRun() {
    QSettings store(kOrg, kApp);
    return store.value(kKeyLastRun).toDateTime();
}

void Automation::setLastRun(const QDateTime& dt) {
    QSettings store(kOrg, kApp);
    store.setValue(kKeyLastRun, dt);
    store.sync();
}

QDateTime Automation::nextRun() {
    const Schedule s = schedule();
    if (s == Schedule::Off) return {};

    const int days = (s == Schedule::Weekly) ? 7 : 1;

    QDateTime base = lastRun();
    if (!base.isValid()) {
        // Первый запуск — ближайшее наступление указанного часа.
        QDateTime today = QDateTime(QDate::currentDate(),
                                    QTime(scheduleHour(), 0));
        return today > QDateTime::currentDateTime() ? today
                                                    : today.addDays(days);
    }
    QDateTime next(base.date().addDays(days), QTime(scheduleHour(), 0));
    return next;
}

void Automation::tick() {
    if (schedule() == Schedule::Off) return;

    const QDateTime next = nextRun();
    if (!next.isValid() || QDateTime::currentDateTime() < next) return;

    setLastRun(QDateTime::currentDateTime());
    emit scheduledScanDue();
}

// ─────────────── Трей ───────────────

bool Automation::trayEnabled() {
    QSettings store(kOrg, kApp);
    return store.value(kKeyTray, false).toBool();
}

void Automation::setTrayEnabled(bool on) {
    QSettings store(kOrg, kApp);
    store.setValue(kKeyTray, on);
    store.sync();
}

void Automation::applyTraySetting() {
    if (trayEnabled() && !QSystemTrayIcon::isSystemTrayAvailable()) {
        Logger::Instance().Warn("[Tray] system tray is not available");
    }

    const bool want = trayEnabled() && QSystemTrayIcon::isSystemTrayAvailable();

    if (!want) {
        delete tray_;  tray_ = nullptr;
        delete menu_;  menu_ = nullptr;
        return;
    }
    if (tray_) return;

    menu_ = new QMenu();
    // Без прозрачной подложки скругление в QSS обрезается квадратным окном
    // всплывающего меню, и углы выглядят рваными.
    menu_->setWindowFlags(menu_->windowFlags()
                          | Qt::FramelessWindowHint
                          | Qt::NoDropShadowWindowHint);
    menu_->setAttribute(Qt::WA_TranslucentBackground);

    const QColor iconColor(Theme::TEXT_SECONDARY);

    QAction* open = menu_->addAction(
        QIcon(Icons::fromResource("icon", 16, iconColor)),
        TR("Open Threat Scanner"));
    connect(open, &QAction::triggered, this, &Automation::showWindowRequested);

    QAction* scan = menu_->addAction(
        Icons::icon(Icons::Id::Magnifier, 16, iconColor), TR("Start scan"));
    connect(scan, &QAction::triggered, this, &Automation::scheduledScanDue);

    menu_->addSeparator();

    QAction* quit = menu_->addAction(
        Icons::icon(Icons::Id::Cross, 16, QColor(Theme::SEV_CRIT)), TR("Quit"));
    connect(quit, &QAction::triggered, qApp, &QApplication::quit);

    // Не QIcon(":/app.ico"): Qt-читатель ICO не гарантирует поддержку
    // PNG-упакованных записей, а пустая иконка в трее неотличима от её
    // отсутствия. SVG рисуется тем же путём, что и остальные иконки.
    QIcon trayIcon(Icons::fromResource("icon", 16, QColor("#FFFFFF")));
    trayIcon.addPixmap(Icons::fromResource("icon", 24, QColor("#FFFFFF")));
    trayIcon.addPixmap(Icons::fromResource("icon", 32, QColor("#FFFFFF")));

    tray_ = new QSystemTrayIcon(trayIcon, this);
    tray_->setToolTip("Threat Scanner");
    tray_->setContextMenu(menu_);
    connect(tray_, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason r) {
        if (r == QSystemTrayIcon::Trigger || r == QSystemTrayIcon::DoubleClick) {
            emit showWindowRequested();
        }
    });
    tray_->show();
}

void Automation::notifyScanResult(int threats, int critical) {
    if (!tray_) return;

    if (threats == 0) {
        tray_->showMessage("Threat Scanner",
                           TR("Scan finished — nothing suspicious found."),
                           QSystemTrayIcon::Information, 5000);
        return;
    }

    const QString text = critical > 0
        ? TR("Scan finished — %1 threats, %2 of them critical.")
              .arg(threats).arg(critical)
        : TR("Scan finished — %1 threats found.").arg(threats);

    tray_->showMessage("Threat Scanner", text,
                       QSystemTrayIcon::Warning, 8000);
}
