#pragma once

#include "../ui/FramelessWindow.h"

#include <QPointer>
#include <QStringList>

class QStackedWidget;
class ScannerBridge;
class Automation;
class DownloadGuard;
class Page;
namespace Ui { class Sidebar; class TitleBar; }

class MainWindow : public FramelessWindow {
    Q_OBJECT

public:
    enum PageId { Home = 0, Scan, Results, Quarantine, Behavior, History, Log, Settings, Help, PageCount };

    // demo — режим снимков экрана: без помощника и фоновых служб.
    explicit MainWindow(bool demo = false, QWidget* parent = nullptr);
    ~MainWindow() override;

    ScannerBridge* bridge() const { return bridge_; }
    QWidget* overlayHost() const;

    void navigate(int page);
    int  currentPage() const { return current_; }

    // Проверка через помощника. mode — ScanConfig::Mode; paths — для
    // выборочной; filesOnly — только файловый модуль (разовая проверка).
    void startScan(int mode, const QStringList& paths = {}, bool filesOnly = false);
    void cancelScan();

    // Мгновенная проверка файлов в процессе окна (без прав администратора).
    void checkFiles(const QStringList& files);

    // Действие над находкой из общего списка: 0 карантин, 1 удаление,
    // 2 пропустить. Для находок вне проверки — напрямую или через помощник.
    void applyAction(int row, int action);
    void allowItem(int row);           // «Доверять»: в исключения по SHA-256
    void neutralizeAll();              // карантин всех, что ждут решения

    void toast(const QString& tone, const QString& title, const QString& text = {},
               const QString& action = {}, std::function<void()> onAction = {});

    void appendLog(const QString& message, const QString& level);
    const QStringList& logLines() const { return log_; }

    bool demoMode() const { return demo_; }
    void rebuildPages();

    // Настройки поменялись — применить то, что зависит от них.
    void applySettings();
    void refreshBadges();

signals:
    void logAppended(QString line, QString level);
    void quarantineChanged();
    void signaturesChanged();

protected:
    void changeEvent(QEvent* e) override;
    void closeEvent(QCloseEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;
    void dragEnterEvent(QDragEnterEvent* e) override;
    void dropEvent(QDropEvent* e) override;
    void onMaximizeButtonHover(bool hovered) override;

private:
    void buildShell();
    void wireBridge();
    void wireServices();
    void onScanFinished(bool cancelled);
    void offerUpdate(bool manual);
    void updateSidebarFooter();

    Ui::TitleBar*   titleBar_ = nullptr;
    Ui::Sidebar*    sidebar_ = nullptr;
    QStackedWidget* stack_ = nullptr;
    QWidget*        content_ = nullptr;
    QList<Page*>    pages_;
    int             current_ = Home;

    ScannerBridge*  bridge_ = nullptr;
    Automation*     automation_ = nullptr;
    DownloadGuard*  guard_ = nullptr;
    bool            demo_ = false;
    bool            quitting_ = false;
    QStringList     log_;
};
