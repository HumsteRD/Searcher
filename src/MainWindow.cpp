#include "MainWindow.h"
#include "Sidebar.h"
#include "theme.h"
#include "ui/TitleBar.h"
#include "ui/BackgroundWidget.h"
#include "pages/HomePage.h"
#include "pages/ScanPage.h"
#include "pages/ThreatsPage.h"
#include "pages/QuarantinePage.h"
#include "pages/LogsPage.h"
#include "pages/SettingsPage.h"
#include "pages/HelpPage.h"
#include "pages/HistoryPage.h"
#include "pages/SandboxPage.h"
#include "core/ScanHistory.h"
#include "core/Automation.h"
#include "core/ScannerBridge.h"
#include "core/Scanner.h"      // ScanState: сам Scanner теперь в помощнике
#include "core/AppSettings.h"
#include "core/Quarantine.h"
#include "core/VirusTotalClient.h"
#include "core/Lang.h"

#include <QStackedWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QWidget>
#include <QPushButton>   // кнопки тайтлбара приводятся к QWidget*
#include <QEvent>
#include <QDateTime>
#include <QCloseEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QFileInfo>
#include <QMessageBox>
#include <memory>

namespace {

const char* kModeNames[] = { "Quick", "Full", "Folder" };

// Порядок обязан совпадать с Sidebar::Page и с порядком добавления
// страниц в стек: индекс один и тот же для всех трёх.
const char* kPageTitles[] = {
    "Home", "Scan", "Threats", "Quarantine", "Behavior",
    "Logs", "History", "Help", "Settings"
};

constexpr int kPageCount = static_cast<int>(std::size(kPageTitles));

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : FramelessWindow(parent)
{
    setWindowTitle("Threat Scanner");
    resize(Theme::Size::WINDOW_W, Theme::Size::WINDOW_H);
    setMinimumSize(Theme::Size::WINDOW_MIN_W, Theme::Size::WINDOW_MIN_H);
    setAcceptDrops(true);

    // Модули проверки живут в помощнике: интерфейсу их регистрировать
    // нечем и незачем — он работает от обычного пользователя.
    bridge_ = new ScannerBridge(this);

    // Фон рисуется параметрически — четыре радиальных пятна поверх заливки.
    BackgroundWidget* central = new BackgroundWidget(this);
    setCentralWidget(central);

    QHBoxLayout* rootLayout = new QHBoxLayout(central);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    sidebar_ = new Sidebar(central);
    rootLayout->addWidget(sidebar_);
    connect(sidebar_, &Sidebar::pageRequested,
            this, &MainWindow::onPageRequested);

    QWidget* right = new QWidget(central);
    right->setStyleSheet("background: transparent;");

    QVBoxLayout* rightLayout = new QVBoxLayout(right);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(0);

    // ─── Полоса заголовка ───
    titleBar_ = new TitleBar(right);
    rightLayout->addWidget(titleBar_);

    connect(titleBar_, &TitleBar::minimizeRequested, this, &MainWindow::showMinimized);
    connect(titleBar_, &TitleBar::maximizeRequested, this, [this]() {
        if (isMaximized()) showNormal();
        else               showMaximized();
    });
    connect(titleBar_, &TitleBar::closeRequested, this, &MainWindow::close);

    // Окно тащится за полосу, но кнопки внутри неё остаются кликабельными.
    setCaptionWidget(titleBar_);
    addCaptionExclusion(titleBar_->minimizeButton());
    addCaptionExclusion(titleBar_->closeButton());
    setMaximizeButton(titleBar_->maximizeButton());

    pageHost_ = right;
    buildPages();

    rightLayout->addWidget(content_, 1);
    rootLayout->addWidget(right, 1);

    sidebar_->setActivePage(Sidebar::Home);
    content_->setCurrentIndex(Sidebar::Home);
    titleBar_->setPageName(TR(kPageTitles[Sidebar::Home]));

    refreshQuarantineCount();

    // ─── Фоновая работа ───
    automation_ = new Automation(this, this);
    connect(automation_, &Automation::scheduledScanDue, this, [this]() {
        if (scanRunning_) return;
        onPageRequested(Sidebar::Scan);
        sidebar_->setActivePage(Sidebar::Scan);
        onScanRequested();
    });
    connect(automation_, &Automation::showWindowRequested, this, [this]() {
        showNormal();
        raise();
        activateWindow();
    });

    connect(&Lang::instance(), &Lang::languageChanged, this, [this]() {
        const int page = content_->currentIndex();
        auto* lay = qobject_cast<QVBoxLayout*>(pageHost_->layout());
        if (!lay) return;
        lay->removeWidget(content_);
        content_->deleteLater();
        buildPages();
        lay->addWidget(content_, 1);
        content_->setCurrentIndex(page);
        titleBar_->setPageName(TR(kPageTitles[page]));
        sidebar_->retranslate();
        refreshQuarantineCount();
    });
}

void MainWindow::buildPages() {
    // ─── Страницы ───
    content_ = new QStackedWidget(pageHost_);
    content_->setStyleSheet("background: transparent;");

    homePage_       = new HomePage;
    scanPage_       = new ScanPage;
    threatsPage_    = new ThreatsPage;
    quarantinePage_ = new QuarantinePage;
    logsPage_       = new LogsPage;
    settingsPage_   = new SettingsPage;

    content_->addWidget(homePage_);
    content_->addWidget(scanPage_);
    content_->addWidget(threatsPage_);
    content_->addWidget(quarantinePage_);
    sandboxPage_ = new SandboxPage;
    sandboxPage_->setBridge(bridge_);
    settingsPage_->setBridge(bridge_);
    content_->addWidget(sandboxPage_);
    content_->addWidget(logsPage_);
    historyPage_ = new HistoryPage;
    content_->addWidget(historyPage_);
    helpPage_ = new HelpPage;
    content_->addWidget(helpPage_);
    content_->addWidget(settingsPage_);

    // Находка песочницы попадает в тот же список, что и находки проверки:
    // мост увидит её на следующем опросе и покажет на странице угроз,
    // где к ней применимы карантин и удаление. Ключ дедупликации в
    // Scanner — путь к файлу, поэтому повторный прогон того же образца
    // второй строки не добавит.
    connect(sandboxPage_, &SandboxPage::behaviourThreatFound, this,
            [this](const Threat& threat) {
                bridge_->reportThreat(threat);
            });

    connect(historyPage_, &HistoryPage::behaviourReportRequested, this,
            [this](QString path) {
                onPageRequested(Sidebar::Behavior);
                sidebar_->setActivePage(Sidebar::Behavior);
                sandboxPage_->loadReportFile(path);
            });

    connect(homePage_, &HomePage::scanRequested, this, [this]() {
        onPageRequested(Sidebar::Scan);
        sidebar_->setActivePage(Sidebar::Scan);
        onScanRequested();
    });
    connect(scanPage_, &ScanPage::scanRequested,
            this, &MainWindow::onScanRequested);
    connect(scanPage_, &ScanPage::cancelRequested, this, [this]() {
        bridge_->cancelScan();
    });

    // Потеря помощника посреди работы должна быть видна: замерший
    // прогресс без объяснения читается как зависшее приложение.
    connect(bridge_, &ScannerBridge::helperLost, this, [this]() {
        logsPage_->appendLine(
            TR("The helper stopped. Anything that needs administrator "
               "rights will ask for them again."), "ERR");
    });

    connect(bridge_, &ScannerBridge::progressChanged,
            this, &MainWindow::onProgress);
    connect(bridge_, &ScannerBridge::stateChanged,
            this, &MainWindow::onStateChanged);
    connect(bridge_, &ScannerBridge::statsChanged,
            this, &MainWindow::onStatsChanged);

    // Живые детали хода сканирования + счётчик проверенного на главной.
    connect(bridge_, &ScannerBridge::scanDetail, this,
            [this](QString item, qint64 objects, int elapsedMs, int etaMs) {
        scanPage_->setDetail(item, objects, elapsedMs, etaMs);
        objectsScanned_ = objects;
        scanElapsedMs_ = elapsedMs;
        homePage_->setStats(totalThreats_, criticalThreats_,
                            static_cast<int>(objects));
    });
    connect(bridge_, &ScannerBridge::threatReported,
            this, &MainWindow::onThreatReported);
    connect(bridge_, &ScannerBridge::actionApplied,
            this, &MainWindow::onActionApplied);

    // Действия над угрозами: Quarantine / Delete / Ignore
    connect(threatsPage_, &ThreatsPage::actionRequested,
            this, [this](int index, int action) {
        bridge_->applyAction(index, action);
    });

    connect(threatsPage_, &ThreatsPage::scanRequested, this, [this]() {
        onPageRequested(Sidebar::Scan);
        sidebar_->setActivePage(Sidebar::Scan);
        onScanRequested();
    });

    connect(quarantinePage_, &QuarantinePage::changed,
            this, &MainWindow::refreshQuarantineCount);

    // Обе операции над карантином выполняет помощник: интерфейсу не
    // хватает прав ни вернуть файл на место, ни вычистить хранилище.
    connect(quarantinePage_, &QuarantinePage::restoreRequested, this,
            [this](QString id) {
        bridge_->restoreFromQuarantine(id, [this](bool done, QString error) {
            if (!done) {
                QMessageBox::warning(this, TR("Restore failed"),
                    error.isEmpty()
                        ? TR("Could not restore the file. See Logs for details.")
                        : error);
            }
            quarantinePage_->refresh();
            refreshQuarantineCount();
        });
    });

    connect(quarantinePage_, &QuarantinePage::deleteRequested, this,
            [this](QString id) {
        bridge_->deleteFromQuarantine(id, [this](bool done, QString error) {
            if (!done) {
                QMessageBox::warning(this, TR("Delete failed"),
                    error.isEmpty()
                        ? TR("Could not delete the item. See Logs for details.")
                        : error);
            }
            quarantinePage_->refresh();
            refreshQuarantineCount();
        });
    });

    // ─── VirusTotal ───
    connect(threatsPage_, &ThreatsPage::vtCheckRequested,
            this, [this](int index, QString sha256) {
        if (!VirusTotalClient::instance().hasApiKey()) {
            // Без ключа не спамим лог по каждой строке — говорим это в самой ячейке.
            threatsPage_->setVirusTotalResult(index, "No API key", false);
            return;
        }
        threatsPage_->setVirusTotalPending(index);
        VirusTotalClient::instance().lookup(index, sha256);
    });

    connect(&VirusTotalClient::instance(), &VirusTotalClient::lookupFinished,
            this, [this](int index, QString /*sha*/, int malicious, int total,
                         bool found, bool ok, QString error) {
        if (!ok) {
            threatsPage_->setVirusTotalResult(index, "Error", false,
                "The lookup failed: " + error);
            logsPage_->appendLine("[VT] " + error, "ERR");
            return;
        }
        if (!found) {
            threatsPage_->setVirusTotalResult(index, "Unknown", false,
                "VirusTotal has never seen this file. That is normal for "
                "freshly built or rare files, and is not by itself a verdict.");
            return;
        }

        const QString text = malicious == 0
            ? QString("Clean · 0 of %1").arg(total)
            : QString("%1 of %2 flagged").arg(malicious).arg(total);

        const QString tip = malicious == 0
            ? QString("None of the %1 antivirus engines on VirusTotal "
                      "consider this file dangerous.").arg(total)
            : QString("%1 out of %2 antivirus engines on VirusTotal consider "
                      "this file dangerous. A couple of detections can be a "
                      "false positive; many detections almost never are.")
                  .arg(malicious).arg(total);

        threatsPage_->setVirusTotalResult(index, text, malicious > 0, tip);
    });

    // Логируем только начало и конец очереди, а не каждое её изменение.
    connect(&VirusTotalClient::instance(), &VirusTotalClient::queueSizeChanged,
            this, [this, lastPending = 0](int pending) mutable {
        if (lastPending == 0 && pending > 0) {
            logsPage_->appendLine(
                "[VT] lookups queued (free key allows 4 per minute)", "INF");
        } else if (lastPending > 0 && pending == 0) {
            logsPage_->appendLine("[VT] all lookups finished", "INF");
        }
        lastPending = pending;
    });

    connect(bridge_, &ScannerBridge::logLine,
            this, [this](QString message, int level) {
        const char* tag = "INF";
        if      (level == 0) tag = "DBG";
        else if (level == 2) tag = "WRN";
        else if (level >= 3) tag = "ERR";
        logsPage_->appendLine(message, tag);
    });

}

MainWindow::~MainWindow() = default;

void MainWindow::changeEvent(QEvent* event) {
    FramelessWindow::changeEvent(event);
    if (event->type() == QEvent::WindowStateChange && titleBar_) {
        titleBar_->setMaximized(isMaximized());
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    // Принимаем только локальные пути; ссылки и текст игнорируем.
    const QMimeData* mime = event->mimeData();
    if (!mime->hasUrls()) return;

    for (const QUrl& u : mime->urls()) {
        if (u.isLocalFile()) { event->acceptProposedAction(); return; }
    }
}

void MainWindow::dropEvent(QDropEvent* event) {
    QString path;
    for (const QUrl& u : event->mimeData()->urls()) {
        if (u.isLocalFile()) { path = u.toLocalFile(); break; }
    }
    if (path.isEmpty()) return;

    if (scanRunning_) {
        logsPage_->appendLine(
            TR("A scan is already running — drop ignored."), "WRN");
        return;
    }

    const QFileInfo info(path);
    AppSettings::Get().SetCustomPath(path.toStdWString());
    AppSettings::Get().SetMode(AppSettings::ScanMode::Custom);

    // Для одиночного файла остальные модули не имеют смысла: реестр,
    // процессы и сеть к нему отношения не имеют.
    if (info.isFile()) {
        // Проверка одного файла: гонять реестр, процессы, сеть и планировщик
        // бессмысленно — к этому файлу они отношения не имеют, а пользователь
        // ждёт вердикт именно по нему. Прежний набор модулей запоминаем
        // и возвращаем, когда проверка закончится.
        auto& cfg = AppSettings::Get();
        for (int i = 0; i < AppSettings::ModuleCount; ++i) {
            savedModules_[i] = cfg.ModuleEnabled(i);
        }
        singleFileRun_ = true;

        for (int i = 0; i < AppSettings::ModuleCount; ++i) {
            const bool relevant = (i == AppSettings::ModFiles ||
                                   i == AppSettings::ModScripts);
            cfg.SetModuleEnabled(i, relevant);
        }
    }

    logsPage_->appendLine(
        (info.isFile() ? TR("Checking dropped file: ")
                       : TR("Checking dropped folder: ")) + path, "INF");

    onPageRequested(Sidebar::Scan);
    sidebar_->setActivePage(Sidebar::Scan);
    onScanRequested();

    event->acceptProposedAction();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    // При включённом трее закрытие сворачивает окно, а не гасит
    // приложение — иначе фоновые проверки не имели бы смысла.
    if (Automation::trayEnabled()) {
        hide();
        event->ignore();
        return;
    }
    FramelessWindow::closeEvent(event);
}

void MainWindow::onMaximizeButtonHover(bool hovered) {
    if (titleBar_) titleBar_->setMaximizeHovered(hovered);
}

void MainWindow::refreshQuarantineCount() {
    homePage_->setQuarantineCount(
        static_cast<int>(Quarantine::Instance().List().size()));
}

void MainWindow::onPageRequested(int pageId) {
    if (pageId < 0 || pageId >= kPageCount) return;
    content_->setCurrentIndex(pageId);
    titleBar_->setPageName(TR(kPageTitles[pageId]));
}

void MainWindow::onScanRequested() {
    threatsPage_->clearThreats();
    scanPage_->setProgress(0, "Starting scan...");
    scanPage_->setStats(0, 0);
    totalThreats_ = 0;
    criticalThreats_ = 0;
    homePage_->setStats(0, 0, 0);
    objectsScanned_ = 0;
    scanElapsedMs_ = 0;
    scanFindings_.clear();
    sidebar_->setThreatCount(0);
    logsPage_->appendLine(TR("Scan requested by user"), "INF");

    bridge_->startScan();
}

void MainWindow::onProgress(int percent, QString stage) {
    // Имена модулей приходят из ядра на английском.
    scanPage_->setProgress(percent, TR(stage));
}

void MainWindow::onStateChanged(int state) {
    auto st = static_cast<ScanState>(state);
    scanRunning_ = (st == ScanState::Running);

    switch (st) {
        case ScanState::Running:
            scanPage_->setRunning(true);
            break;

        case ScanState::Cancelling:
            logsPage_->appendLine(TR("Scan cancellation requested"), "WRN");
            break;

        case ScanState::Done: {
            // Разовая проверка одного файла закончилась — возвращаем
            // набор модулей, который выбрал пользователь.
            if (singleFileRun_) {
                singleFileRun_ = false;
                for (int i = 0; i < AppSettings::ModuleCount; ++i) {
                    AppSettings::Get().SetModuleEnabled(i, savedModules_[i]);
                }
            }

            scanPage_->setRunning(false);
            scanPage_->setProgress(100, TR("Scan complete"));

            if (totalThreats_ == 0) {
                homePage_->setLastScanText(TR("Last scan: just now — no threats"));
            } else {
                homePage_->setLastScanText(
                    TR("Last scan: just now — threats found: %1")
                        .arg(totalThreats_));
            }

            // Сохраняем результат: до этого он жил только до закрытия окна.
            ScanRecord rec;
            rec.when            = QDateTime::currentDateTime();
            rec.mode            = kModeNames[
                static_cast<int>(AppSettings::Get().Mode())];
            rec.durationMs      = scanElapsedMs_;
            rec.objectsScanned  = objectsScanned_;
            rec.totalThreats    = totalThreats_;
            rec.criticalThreats = criticalThreats_;
            rec.findings        = scanFindings_;
            ScanHistory::instance().add(rec);

            if (automation_) {
                automation_->notifyScanResult(totalThreats_,
                                              criticalThreats_);
            }
            break;
        }

        default:
            break;
    }
}

void MainWindow::onStatsChanged(int total, int critical) {
    totalThreats_ = total;
    criticalThreats_ = critical;
    scanPage_->setStats(total, critical);
    homePage_->setStats(total, critical, static_cast<int>(objectsScanned_));
    sidebar_->setThreatCount(total);
}

void MainWindow::onThreatReported(int index, int kind, QString severity,
                                  QString name, QString source, QString why,
                                  QString evidence)
{
    threatsPage_->addThreat(index, kind, severity, name, source, why, evidence);
    scanFindings_.push_back({ severity, name, source });

    // Авто-карантин критичных угроз, если включён в настройках.
    if (severity == "CRIT" && AppSettings::Get().AutoQuarantine()) {
        logsPage_->appendLine("Auto-quarantine: " + name, "WRN");
        bridge_->applyAction(index, 0);
    }
}

void MainWindow::onActionApplied(int index, QString statusText,
                                 QString message, bool success)
{
    threatsPage_->setThreatStatus(index, statusText, message, success);
    logsPage_->appendLine(message, success ? "INF" : "ERR");

    refreshQuarantineCount();
    if (content_->currentIndex() == Sidebar::Quarantine) {
        quarantinePage_->refresh();
    }
}
