#pragma once

#include <QObject>
#include <QDateTime>

class QTimer;
class QSystemTrayIcon;
class QMenu;

// Фоновая работа: автозапуск с Windows, проверка по расписанию
// и значок в трее с уведомлением о находках.
class Automation : public QObject {
    Q_OBJECT

public:
    enum class Schedule { Off = 0, Daily = 1, Weekly = 2 };

    explicit Automation(QWidget* window, QObject* parent = nullptr);

    // Единственный экземпляр: настройкам нужно применить изменение сразу,
    // а не ждать перезапуска приложения.
    static Automation* instance();
    ~Automation() override;

    // ─── Автозапуск: запись в ветке автозагрузки текущего пользователя ───
    static bool autostartEnabled();
    static void setAutostartEnabled(bool on);

    // ─── Расписание ───
    static Schedule schedule();
    static void     setSchedule(Schedule s);
    static int      scheduleHour();          // час запуска, 0..23
    static void     setScheduleHour(int h);

    // Когда расписание сработает в следующий раз; недействительно, если выключено.
    static QDateTime nextRun();

    // ─── Трей ───
    static bool trayEnabled();
    static void setTrayEnabled(bool on);
    void        applyTraySetting();

    // Показать уведомление о результате проверки.
    void notifyScanResult(int threats, int critical);

signals:
    // Расписание требует запустить проверку.
    void scheduledScanDue();
    void showWindowRequested();

private:
    void tick();
    static QDateTime lastRun();
    static void      setLastRun(const QDateTime& dt);

    static Automation* self_;

    QWidget*         window_ = nullptr;
    QTimer*          timer_ = nullptr;
    QSystemTrayIcon* tray_ = nullptr;
    QMenu*           menu_ = nullptr;
};
