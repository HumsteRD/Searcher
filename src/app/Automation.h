#pragma once

#include <QDateTime>
#include <QObject>
#include <QString>

class QMenu;
class QSystemTrayIcon;
class QTimer;
class QWidget;

// Работа в фоне: значок в трее, автозапуск с Windows, проверка по
// расписанию, всплывающие уведомления.
class Automation : public QObject {
    Q_OBJECT

public:
    enum class Schedule { Off = 0, Daily = 1, Weekly = 2 };

    explicit Automation(QWidget* window, QObject* parent = nullptr);
    ~Automation() override;
    static Automation* instance();

    // Автозапуск: запись в HKCU\...\Run с ключом --minimized.
    static bool autostartEnabled();
    static void setAutostartEnabled(bool on);

    static Schedule schedule();
    static void     setSchedule(Schedule s);
    static int      scheduleHour();
    static void     setScheduleHour(int hour);
    static QDateTime nextRun();

    // Закрытие окна сворачивает в трей.
    static bool trayEnabled();
    static void setTrayEnabled(bool on);
    void applyTraySetting();
    void retranslate();

    // Уведомление в области уведомлений Windows (если трей включён).
    void notify(const QString& title, const QString& text, bool warning);

signals:
    void scheduledScanDue();
    void showWindowRequested();
    void quickScanRequested();
    void quitRequested();

private:
    void tick();
    static QDateTime lastRun();
    static void setLastRun(const QDateTime& dt);

    static Automation* self_;
    QWidget*         window_ = nullptr;
    QTimer*          timer_ = nullptr;
    QSystemTrayIcon* tray_ = nullptr;
    QMenu*           menu_ = nullptr;
};
