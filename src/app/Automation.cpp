#include "Automation.h"
#include "Lang.h"

#include "../ui/Icons.h"

#include <QApplication>
#include <QDir>
#include <QMenu>
#include <QSettings>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QWidget>

namespace {

constexpr const char* kRunKey = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr const char* kRunValue = "ThreatScanner";

QString ExePath() { return QDir::toNativeSeparators(QApplication::applicationFilePath()); }

QVariant Get(const char* key, const QVariant& def) {
    QSettings s("ThreatScanner", "ThreatScanner");
    return s.value(key, def);
}

void Set(const char* key, const QVariant& v) {
    QSettings s("ThreatScanner", "ThreatScanner");
    s.setValue(key, v);
}

} // namespace

Automation* Automation::self_ = nullptr;

Automation* Automation::instance() { return self_; }

Automation::Automation(QWidget* window, QObject* parent) : QObject(parent), window_(window) {
    self_ = this;
    timer_ = new QTimer(this);
    timer_->setInterval(60 * 1000);
    connect(timer_, &QTimer::timeout, this, &Automation::tick);
    timer_->start();
    applyTraySetting();

    // Путь в автозапуске обновляем при каждом старте: после обновления
    // или переноса программы старая запись вела бы в пустоту.
    if (autostartEnabled()) setAutostartEnabled(true);
}

Automation::~Automation() {
    if (self_ == this) self_ = nullptr;
    delete menu_;
}

bool Automation::autostartEnabled() {
    QSettings run(kRunKey, QSettings::NativeFormat);
    return !run.value(kRunValue).toString().isEmpty();
}

void Automation::setAutostartEnabled(bool on) {
    QSettings run(kRunKey, QSettings::NativeFormat);
    if (on) run.setValue(kRunValue, "\"" + ExePath() + "\" --minimized");
    else    run.remove(kRunValue);
}

Automation::Schedule Automation::schedule() {
    return static_cast<Schedule>(std::clamp(Get("auto/schedule", 0).toInt(), 0, 2));
}
void Automation::setSchedule(Schedule s) { Set("auto/schedule", static_cast<int>(s)); }
int  Automation::scheduleHour() { return std::clamp(Get("auto/hour", 12).toInt(), 0, 23); }
void Automation::setScheduleHour(int h) { Set("auto/hour", std::clamp(h, 0, 23)); }
QDateTime Automation::lastRun() { return Get("auto/lastRun", QDateTime()).toDateTime(); }
void Automation::setLastRun(const QDateTime& dt) { Set("auto/lastRun", dt); }

QDateTime Automation::nextRun() {
    const Schedule s = schedule();
    if (s == Schedule::Off) return {};
    const int days = s == Schedule::Weekly ? 7 : 1;
    const QDateTime last = lastRun();
    if (!last.isValid()) {
        QDateTime today(QDate::currentDate(), QTime(scheduleHour(), 0));
        return today > QDateTime::currentDateTime() ? today : today.addDays(1);
    }
    return QDateTime(last.date().addDays(days), QTime(scheduleHour(), 0));
}

void Automation::tick() {
    if (schedule() == Schedule::Off) return;
    const QDateTime next = nextRun();
    if (!next.isValid() || QDateTime::currentDateTime() < next) return;
    setLastRun(QDateTime::currentDateTime());
    emit scheduledScanDue();
}

bool Automation::trayEnabled() { return Get("auto/tray", true).toBool(); }
void Automation::setTrayEnabled(bool on) { Set("auto/tray", on); }

void Automation::applyTraySetting() {
    const bool want = trayEnabled() && QSystemTrayIcon::isSystemTrayAvailable();
    if (!want) {
        delete tray_; tray_ = nullptr;
        delete menu_; menu_ = nullptr;
        return;
    }
    if (!tray_) {
        tray_ = new QSystemTrayIcon(Icons::appIcon(), this);
        menu_ = new QMenu();
        tray_->setContextMenu(menu_);
        connect(tray_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason r) {
            if (r == QSystemTrayIcon::Trigger || r == QSystemTrayIcon::DoubleClick)
                emit showWindowRequested();
        });
        connect(tray_, &QSystemTrayIcon::messageClicked, this, &Automation::showWindowRequested);
        tray_->show();
    }
    retranslate();
}

void Automation::retranslate() {
    if (!tray_ || !menu_) return;
    tray_->setToolTip("Threat Scanner");
    menu_->clear();
    menu_->addAction(TR("Open Threat Scanner"), this, &Automation::showWindowRequested);
    menu_->addAction(TR("Quick scan"), this, &Automation::quickScanRequested);
    menu_->addSeparator();
    menu_->addAction(TR("Exit"), this, &Automation::quitRequested);
}

void Automation::notify(const QString& title, const QString& text, bool warning) {
    if (!tray_) return;
    tray_->showMessage(title, text, warning ? QSystemTrayIcon::Warning : QSystemTrayIcon::Information, 8000);
}
