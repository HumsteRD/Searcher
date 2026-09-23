#pragma once

#include "ui/FramelessWindow.h"
#include "core/ScanHistory.h"

class QStackedWidget;
class Sidebar;
class TitleBar;
class HomePage;
class ScanPage;
class ThreatsPage;
class QuarantinePage;
class SandboxPage;
class LogsPage;
class SettingsPage;
class HelpPage;
class HistoryPage;
class ScannerBridge;
class Automation;

class MainWindow : public FramelessWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    void changeEvent(QEvent* event) override;
    // Закрытие прячет окно в трей, если это включено.
    void closeEvent(QCloseEvent* event) override;

    // Перетаскивание файла или папки в окно запускает выборочную проверку.
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    void onMaximizeButtonHover(bool hovered) override;

private slots:
    void onPageRequested(int pageId);
    void onScanRequested();

    void onProgress(int percent, QString stage);
    void onStateChanged(int state);
    void onStatsChanged(int total, int critical);
    void onThreatReported(int index, int kind, QString severity, QString name,
                          QString source, QString why, QString evidence);
    void onActionApplied(int index, QString statusText,
                         QString message, bool success);

private:
    void refreshQuarantineCount();
    // Пересобирает страницы: строки задаются в конструкторах,
    // поэтому смена языка требует их пересоздания.
    void buildPages();
    QWidget* pageHost_ = nullptr;

    // Обязательно nullptr: changeEvent() приходит уже во время работы
    // конструктора (его вызывают setWindowFlags и resize), когда поля
    // ещё не присвоены. Неинициализированный указатель делает проверку
    // «if (titleBar_)» бесполезной и роняет окно внутри оконной процедуры.
    Sidebar*        sidebar_ = nullptr;
    TitleBar*       titleBar_ = nullptr;
    QStackedWidget* content_ = nullptr;

    HomePage*       homePage_ = nullptr;
    ScanPage*       scanPage_ = nullptr;
    ThreatsPage*    threatsPage_ = nullptr;
    QuarantinePage* quarantinePage_ = nullptr;
    SandboxPage*    sandboxPage_ = nullptr;
    LogsPage*       logsPage_ = nullptr;
    SettingsPage*   settingsPage_ = nullptr;
    HelpPage*       helpPage_ = nullptr;
    HistoryPage*    historyPage_ = nullptr;

    ScannerBridge*  bridge_ = nullptr;
    Automation*     automation_ = nullptr;

    // Состояние проверки держим у себя: сам Scanner теперь в помощнике,
    // и спросить его напрямую нельзя.
    bool            scanRunning_ = false;

    int             totalThreats_ = 0;
    int             criticalThreats_ = 0;
    qint64          objectsScanned_ = 0;

    // Разовая проверка одного перетащенного файла: на время неё
    // лишние модули выключаются, потом набор восстанавливается.
    bool            singleFileRun_ = false;
    bool            savedModules_[8] = {};
    int             scanElapsedMs_ = 0;
    QVector<ScanRecord::Finding> scanFindings_;
};
