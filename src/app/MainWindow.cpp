#include "MainWindow.h"

#include "AppSettings.h"
#include "AppState.h"
#include "Automation.h"
#include "DownloadGuard.h"
#include "Lang.h"
#include "LocalCheck.h"
#include "ScanHistory.h"
#include "ScannerBridge.h"
#include "SignatureUpdater.h"
#include "Texts.h"
#include "Updater.h"

#include "../core/Logger.h"
#include "../core/Scanner.h"
#include "../core/ThreatJson.h"
#include "../engine/HashDatabase.h"
#include "../pages/BehaviorPage.h"
#include "../pages/HelpPage.h"
#include "../pages/HistoryPage.h"
#include "../pages/HomePage.h"
#include "../pages/LogPage.h"
#include "../pages/QuarantinePage.h"
#include "../pages/ResultsPage.h"
#include "../pages/ScanPage.h"
#include "../pages/SettingsPage.h"
#include "../ui/Shell.h"

#include <Windows.h>
#include <dwmapi.h>

#include <QApplication>
#include <QCloseEvent>
#include <QDate>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QMimeData>
#include <QRegularExpression>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

using namespace Ui;

namespace {

QString LevelTag(int level) {
    switch (level) {
    case 0:  return "DBG";
    case 2:  return "WRN";
    case 3:
    case 4:  return "ERR";
    default: return "INF";
    }
}

} // namespace

MainWindow::MainWindow(bool demo, QWidget* parent) : FramelessWindow(parent), demo_(demo) {
    setWindowTitle("Threat Scanner");
    setWindowIcon(Icons::appIcon());
    setMinimumSize(1000, 680);
    resize(1280, 800);
    setAcceptDrops(true);

    bridge_ = new ScannerBridge(this);
    buildShell();
    rebuildPages();
    wireBridge();
    wireServices();

    const QByteArray geometry = AppSettings::Get().windowGeometry();
    if (!geometry.isEmpty()) restoreGeometry(geometry);

    connect(&Lang::instance(), &Lang::languageChanged, this, [this]() {
        rebuildPages();
        if (automation_) automation_->retranslate();
    });
    connect(&Theme::instance(), &Theme::changed, this, [this]() {
        // Цвет рамки окна, которую рисует Windows 11, — под тему.
        if (HWND hwnd = reinterpret_cast<HWND>(internalWinId())) {
            const QColor b = pal().border;
            const COLORREF color = RGB(b.red(), b.green(), b.blue());
            DwmSetWindowAttribute(hwnd, 34 /* DWMWA_BORDER_COLOR */, &color, sizeof(color));
            const BOOL dark = pal().dark;
            DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));
        }
    });
}

MainWindow::~MainWindow() = default;

QWidget* MainWindow::overlayHost() const { return centralWidget(); }

void MainWindow::buildShell() {
    auto* root = new QWidget(this);
    root->setObjectName("root");
    root->setAttribute(Qt::WA_StyledBackground, true);
    setCentralWidget(root);

    auto* col = new QVBoxLayout(root);
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(0);

    titleBar_ = new TitleBar(root);
    col->addWidget(titleBar_);
    connect(titleBar_, &TitleBar::minimizeRequested, this, &QWidget::showMinimized);
    connect(titleBar_, &TitleBar::maximizeRequested, this, [this]() {
        if (isMaximized()) showNormal(); else showMaximized();
    });
    connect(titleBar_, &TitleBar::closeRequested, this, &QWidget::close);
    setCaptionWidget(titleBar_);
    addCaptionExclusion(titleBar_->minimizeButton());
    addCaptionExclusion(titleBar_->closeButton());
    setMaximizeButton(titleBar_->maximizeButton());

    auto* row = new QHBoxLayout();
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(0);
    sidebar_ = new Sidebar(root);
    row->addWidget(sidebar_);
    stack_ = new QStackedWidget(root);
    row->addWidget(stack_, 1);
    col->addLayout(row, 1);

    connect(sidebar_, &Sidebar::pageRequested, this, &MainWindow::navigate);
}

void MainWindow::rebuildPages() {
    const int current = current_;
    for (Page* p : pages_) {
        stack_->removeWidget(p);
        p->deleteLater();
    }
    pages_.clear();

    pages_ << new HomePage(this) << new ScanPage(this) << new ResultsPage(this) << new QuarantinePage(this)
           << new BehaviorPage(this) << new HistoryPage(this) << new LogPage(this) << new SettingsPage(this)
           << new HelpPage(this);
    for (Page* p : pages_) stack_->addWidget(p);

    auto* history = static_cast<HistoryPage*>(pages_[History]);
    connect(history, &HistoryPage::behaviorReportRequested, this, [this](const QString& path) {
        navigate(Behavior);
        static_cast<BehaviorPage*>(pages_[Behavior])->loadReportFile(path);
    });

    sidebar_->setItems({
        { Home, Icons::Id::Home, TR("Overview") },
        { Scan, Icons::Id::Scan, TR("Scan") },
        { Results, Icons::Id::Alert, TR("Results") },
        { Quarantine, Icons::Id::Quarantine, TR("Quarantine") },
        { Behavior, Icons::Id::Cube, TR("Behavior") },
        { History, Icons::Id::History, TR("History") },
        { Log, Icons::Id::Log, TR("Log") },
        { Settings, Icons::Id::Settings, TR("Settings"), true },
        { Help, Icons::Id::Help, TR("Help"), true },
    });
    current_ = -1;
    navigate(current);
    refreshBadges();
    updateSidebarFooter();
}

void MainWindow::navigate(int page) {
    if (page < 0 || page >= pages_.size()) page = Home;
    current_ = page;
    stack_->setCurrentIndex(page);
    sidebar_->setActive(page);
    pages_[page]->onShown();
}

void MainWindow::refreshBadges() {
    const AppState& st = AppState::instance();
    sidebar_->setBadge(Results, st.pendingCount(), st.criticalCount() ? "CRIT" : "HIGH");
}

void MainWindow::updateSidebarFooter() {
    const uint32_t stamp = HashDatabase::Get().NewestStamp();
    const QString date = stamp ? QDate::fromString(QString::number(stamp), "yyyyMMdd").toString("dd.MM.yyyy")
                               : TR("not loaded");
    sidebar_->setFooter(TR("Databases: %1").arg(date), TR("Version %1").arg(Updater::currentVersion()));
}

void MainWindow::appendLog(const QString& message, const QString& level) {
    const QString line = QTime::currentTime().toString("HH:mm:ss") + " " + level + " " + message;
    log_ << line;
    if (log_.size() > 5000) log_.removeFirst();
    emit logAppended(line, level);
}

void MainWindow::toast(const QString& tone, const QString& title, const QString& text, const QString& action,
                       std::function<void()> onAction)
{
    if (!isVisible()) {
        // Окно в трее: то же самое — системным уведомлением.
        if (automation_) automation_->notify(title, text, tone == "CRIT" || tone == "HIGH");
        return;
    }
    Toast::show(overlayHost(), tone, title, text, action, onAction);
}

// ─── Помощник и проверка ───

void MainWindow::wireBridge() {
    AppState& st = AppState::instance();
    connect(bridge_, &ScannerBridge::progressChanged, this, [&st](int percent, QString stage) {
        st.setProgress(percent, stage);
    });
    connect(bridge_, &ScannerBridge::scanDetail, this, [&st](QString item, qint64 objects, int elapsed, int eta) {
        st.setDetail(item, objects, elapsed, eta);
    });
    connect(bridge_, &ScannerBridge::threatReported, this, [this, &st](int index, QJsonObject payload) {
        st.addThreat(index, payload);
        refreshBadges();
        const Threat t = ThreatJson::FromJson(payload);
        appendLog(TR("Found: %1 (%2)").arg(QString::fromStdWString(t.source), Texts::headline(t)), "WRN");
        if (t.severity == Severity::Critical && AppSettings::Get().autoQuarantine())
            applyAction(st.rowForHelperIndex(index), 0);
    });
    connect(bridge_, &ScannerBridge::stateChanged, this, [this](int state, bool cancelled) {
        if (state == static_cast<int>(ScanState::Done)) onScanFinished(cancelled);
    });
    connect(bridge_, &ScannerBridge::actionApplied, this,
            [this, &st](int index, QString status, QString message, bool ok) {
                st.applyActionResult(index, status, message, ok);
                refreshBadges();
                const int row = st.rowForHelperIndex(index);
                if (row >= 0) {
                    const Threat& t = st.items()[row].threat;
                    appendLog(QString::fromStdWString(t.name) + ": " + Texts::actionResult(message, ok),
                              ok ? "INF" : "ERR");
                    if (!ok) toast("CRIT", TR("Could not apply the action"), Texts::actionResult(message, ok));
                }
                emit quarantineChanged();
            });
    connect(bridge_, &ScannerBridge::logLine, this, [this](QString message, int level) {
        appendLog(message, LevelTag(level));
    });
    connect(bridge_, &ScannerBridge::helperLost, this, [this]() {
        if (quitting_) return;
        appendLog(TR("The helper with administrator rights stopped. The next action will ask for rights again."),
                  "ERR");
    });

    // Журнал собственного процесса: локальные проверки, обновления.
    auto* pump = new QTimer(this);
    pump->setInterval(500);
    connect(pump, &QTimer::timeout, this, [this, seen = Logger::Instance().TotalWritten()]() mutable {
        const size_t total = Logger::Instance().TotalWritten();
        if (total == seen) return;
        for (const LogEntry& e : Logger::Instance().Since(seen))
            appendLog(QString::fromStdString(e.message), LevelTag(static_cast<int>(e.level)));
        seen = total;
    });
    pump->start();
}

void MainWindow::startScan(int mode, const QStringList& paths, bool filesOnly) {
    if (demo_) return;
    AppState& st = AppState::instance();
    if (st.scan().running) {
        toast("MED", TR("A scan is already running"), TR("Wait for it to finish or stop it first."));
        navigate(Scan);
        return;
    }
    const bool single = filesOnly && paths.size() == 1;
    st.beginScan(mode, single, single ? paths.first() : QString());
    refreshBadges();
    navigate(Scan);
    appendLog(TR("Scan started: %1").arg(Texts::modeLabel(mode)), "INF");

    QString error;
    if (!bridge_->startScan(AppSettings::Get().scanArgs(mode, paths, filesOnly), &error)) {
        st.finishScan(true);
        appendLog(error, "ERR");
        toast("MED", TR("The scan did not start"),
              TR("Administrator rights are needed to scan the system. If you declined the Windows prompt, "
                 "start the scan again and allow it."));
    }
}

void MainWindow::cancelScan() {
    bridge_->cancelScan();
    appendLog(TR("Stopping the scan…"), "WRN");
}

void MainWindow::onScanFinished(bool cancelled) {
    AppState& st = AppState::instance();
    if (!st.scan().running) return;
    st.finishScan(cancelled);
    refreshBadges();

    const AppState::Scan& scan = st.scan();
    ScanRecord rec;
    rec.when = scan.finishedAt;
    rec.mode = scan.mode;
    rec.durationMs = scan.elapsedMs;
    rec.objects = scan.objects;
    rec.cancelled = cancelled;
    rec.target = scan.target;
    for (const AppState::Item& it : st.items()) {
        rec.findings.push_back(it.threat);
        ++rec.threats;
        if (it.threat.severity == Severity::Critical) ++rec.critical;
    }
    ScanHistory::instance().add(rec);

    const int pending = st.pendingCount();
    appendLog(TR("Scan finished: %1 objects checked, %2 found.").arg(scan.objects).arg(rec.threats), "INF");
    if (cancelled) {
        toast("MED", TR("The scan was stopped"), TR("Checked before stopping: %1").arg(formatCount(scan.objects)));
    } else if (pending > 0) {
        toast("CRIT", TR("Threats found: %1").arg(pending), TR("Open the results to decide what to do."),
              TR("Open"), [this]() { navigate(Results); });
        if (!isVisible() && automation_)
            automation_->notify(TR("Threats found: %1").arg(pending), TR("Open Threat Scanner to review them."), true);
    } else {
        toast("OK", TR("No threats found"),
              TR("%1 checked in %2.").arg(formatCount(scan.objects), formatDuration(scan.elapsedMs)));
    }
}

// ─── Проверка отдельных файлов ───

void MainWindow::checkFiles(const QStringList& files) {
    QStringList regular, folders;
    for (const QString& f : files) {
        const QFileInfo fi(f);
        if (fi.isDir()) folders << QDir::toNativeSeparators(fi.absoluteFilePath());
        else if (fi.isFile()) regular << QDir::toNativeSeparators(fi.absoluteFilePath());
    }
    if (!folders.isEmpty()) startScan(2, folders);
    if (regular.isEmpty()) return;
    appendLog(TR("Checking %1 %2 locally").arg(regular.size())
                  .arg(TRN(regular.size(), "file", "files", "файл", "файла", "файлов")), "INF");
    toast("ACCENT", regular.size() == 1 ? TR("Checking %1…").arg(QFileInfo(regular.first()).fileName())
                                        : TR("Checking %1 files…").arg(regular.size()));
    LocalCheck::instance().check(regular, "drop");
}

void MainWindow::applyAction(int row, int action) {
    AppState& st = AppState::instance();
    if (row < 0 || row >= st.items().size()) return;
    const AppState::Item& it = st.items()[row];
    if (it.busy || demo_) return;

    if (it.index >= 0) {
        st.setBusy(row, true);
        bridge_->applyAction(it.index, action);
        return;
    }

    // Находка вне проверки (перетащенный файл, загрузки, песочница).
    const Threat t = it.threat;
    auto finish = [this, row](ThreatStatus status, const QString& message, bool ok) {
        AppState& s = AppState::instance();
        if (row >= s.items().size()) return;
        Threat updated = s.items()[row].threat;
        updated.status = status;
        updated.actionMessage = message.toStdWString();
        s.setBusy(row, false);
        s.setThreat(row, updated);
        refreshBadges();
        if (!ok) toast("CRIT", TR("Could not apply the action"), Texts::actionResult(message, ok));
        emit quarantineChanged();
    };

    if (action == 2) {
        finish(ThreatStatus::Ignored, "ignored", true);
    } else if (action == 1) {
        const bool ok = QFile::remove(QString::fromStdWString(t.filePath));
        finish(ok ? ThreatStatus::Deleted : ThreatStatus::Failed, ok ? "deleted" : "denied", ok);
    } else {
        st.setBusy(row, true);
        bridge_->quarantineFile(QString::fromStdWString(t.filePath),
                                QString::fromStdString(t.family.empty() ? Texts::headline(t).toStdString() : t.family),
                                Texts::severityCode(t.severity),
                                [finish](bool ok, const QString&) {
                                    finish(ok ? ThreatStatus::Quarantined : ThreatStatus::Failed,
                                           ok ? "quarantined" : "denied", ok);
                                });
    }
}

void MainWindow::allowItem(int row) {
    AppState& st = AppState::instance();
    if (row < 0 || row >= st.items().size()) return;
    const Threat& t = st.items()[row].threat;
    if (t.sha256.empty()) return;
    AppSettings::Get().addAllowedHash(QString::fromStdString(t.sha256), QString::fromStdWString(t.name));
    Threat updated = t;
    updated.status = ThreatStatus::Ignored;
    updated.actionMessage = L"trusted";
    st.setThreat(row, updated);
    refreshBadges();
    toast("OK", TR("Marked as trusted"), TR("Future scans will skip this file."));
}

void MainWindow::neutralizeAll() {
    AppState& st = AppState::instance();
    QList<int> rows;
    for (int i = 0; i < st.items().size(); ++i) {
        const auto s = st.items()[i].threat.status;
        if ((s == ThreatStatus::Pending || s == ThreatStatus::Failed) && !st.items()[i].busy) rows << i;
    }
    if (rows.isEmpty()) return;
    Modal::confirm(overlayHost(), TR("Neutralize %1 %2?").arg(rows.size())
                                      .arg(TRN(rows.size(), "threat", "threats", "угрозу", "угрозы", "угроз")),
                   TR("Files go to quarantine, startup entries and tasks are removed, services are disabled. "
                      "Anything can be restored from quarantine later."),
                   TR("Neutralize"), false, [this, rows]() {
                       for (int r : rows) applyAction(r, 0);
                       navigate(Results);
                   });
}

// ─── Фоновые службы окна ───

void MainWindow::wireServices() {
    automation_ = new Automation(this, this);
    connect(automation_, &Automation::showWindowRequested, this, [this]() {
        showNormal();
        raise();
        activateWindow();
    });
    connect(automation_, &Automation::quickScanRequested, this, [this]() {
        showNormal();
        raise();
        startScan(0);
    });
    connect(automation_, &Automation::scheduledScanDue, this, [this]() {
        if (!AppState::instance().scan().running) startScan(0);
    });
    connect(automation_, &Automation::quitRequested, this, [this]() {
        quitting_ = true;
        close();
    });

    guard_ = new DownloadGuard(this);

    connect(&LocalCheck::instance(), &LocalCheck::fileChecked, this, [this](QString tag, LocalCheck::Result r) {
        const QString name = QFileInfo(r.path).fileName();
        if (r.clean) {
            if (tag == "drop") {
                if (r.skipped) {
                    toast("MED", TR("Could not check %1").arg(name),
                          r.skipReason == "empty" ? TR("The file is empty.") : TR("The file could not be read."));
                } else {
                    toast("OK", TR("%1: no threats found").arg(name),
                          r.signer.isEmpty() ? TR("Not found in the databases, no signatures matched.")
                                             : TR("Digitally signed by %1.").arg(r.signer));
                }
            }
            ScanRecord rec;
            rec.when = QDateTime::currentDateTime();
            rec.mode = 2;
            rec.objects = 1;
            rec.target = r.path;
            if (tag == "drop") ScanHistory::instance().add(rec);
            return;
        }
        AppState::instance().addLocalThreat(r.threat);
        refreshBadges();
        const QString title = tag == "guard" ? TR("Dangerous download: %1").arg(name) : TR("Threat found: %1").arg(name);
        toast("CRIT", title, Texts::headline(r.threat), TR("Open"), [this]() { navigate(Results); });
        if (tag == "guard" && automation_) automation_->notify(title, Texts::headline(r.threat), true);
        if (tag == "drop") navigate(Results);
        ScanRecord rec;
        rec.when = QDateTime::currentDateTime();
        rec.mode = 2;
        rec.objects = 1;
        rec.threats = 1;
        rec.critical = r.threat.severity == Severity::Critical ? 1 : 0;
        rec.target = r.path;
        rec.findings.push_back(r.threat);
        ScanHistory::instance().add(rec);
    });

    // Обновления программы.
    connect(&Updater::instance(), &Updater::checkFinished, this, [this](bool available, bool manual) {
        if (available) offerUpdate(manual);
        else if (manual) toast("OK", TR("You have the latest version"), Updater::currentVersion());
        static_cast<HomePage*>(pages_[Home])->refresh();
    });
    connect(&Updater::instance(), &Updater::downloadFinished, this, [this](QString) {
        if (AppSettings::Get().autoInstallUpdates() && !AppState::instance().scan().running) {
            quitting_ = true;
            Updater::instance().installAndQuit(true);
        } else {
            toast("ACCENT", TR("The update is downloaded"), TR("Restart the program to install it."),
                  TR("Install"), [this]() {
                      quitting_ = true;
                      Updater::instance().installAndQuit(false);
                  });
        }
    });
    connect(&Updater::instance(), &Updater::downloadFailed, this, [this](QString error) {
        toast("CRIT", TR("Could not download the update"), error);
    });

    connect(&SignatureUpdater::instance(), &SignatureUpdater::finished, this,
            [this](bool changed, QString summary, bool manual) {
                updateSidebarFooter();
                emit signaturesChanged();
                if (changed) {
                    appendLog(TR("Signature databases updated: %1").arg(summary), "INF");
                    if (manual) toast("OK", TR("Signature databases updated"), summary);
                } else if (manual) {
                    toast("OK", TR("Signature databases are up to date"));
                }
            });

    if (demo_) return;
    applySettings();

    // Проверки при запуске — с задержкой: окно сначала должно появиться.
    QTimer::singleShot(4000, this, []() {
        if (AppSettings::Get().checkUpdatesOnStart()) Updater::instance().check(false);
    });
    QTimer::singleShot(8000, this, []() {
        const QDateTime last = AppSettings::Get().lastSignatureUpdate();
        if (AppSettings::Get().autoUpdateSignatures() &&
            (!last.isValid() || last.secsTo(QDateTime::currentDateTime()) > 20 * 3600))
            SignatureUpdater::instance().updateAll(false);
    });
    auto* periodic = new QTimer(this);
    periodic->setInterval(6 * 3600 * 1000);
    connect(periodic, &QTimer::timeout, this, []() {
        if (AppSettings::Get().checkUpdatesOnStart()) Updater::instance().check(false);
        if (AppSettings::Get().autoUpdateSignatures()) SignatureUpdater::instance().updateAll(false);
    });
    periodic->start();
    ScanHistory::instance().importServiceScans();
}

void MainWindow::applySettings() {
    if (guard_) guard_->setEnabled(!demo_ && AppSettings::Get().downloadGuard());
    if (automation_) automation_->applyTraySetting();
    refreshBadges();
}

void MainWindow::offerUpdate(bool manual) {
    Updater& u = Updater::instance();
    const QString version = u.latest().version;
    if (!manual && AppSettings::Get().skippedVersion() == version) return;

    if (AppSettings::Get().autoInstallUpdates() && !manual) {
        appendLog(TR("Downloading version %1…").arg(version), "INF");
        u.download();
        return;
    }
    auto* m = new Modal(overlayHost(), TR("Version %1 is available").arg(version),
                        TR("You have version %1. The update installs over the current version; settings, "
                           "quarantine and history are kept.").arg(Updater::currentVersion()));
    m->setIcon(Icons::Id::ArrowUp, ColorRole::AccentText);
    QString notes = u.latest().notes;
    notes.remove(QRegularExpression("SHA-?256[^\\n]*"));
    notes = notes.trimmed();
    if (!notes.isEmpty()) {
        auto* box = makeLabel(notes.left(900), "muted");
        box->setTextFormat(Qt::MarkdownText);
        m->content()->addWidget(box);
    }
    m->addButton(TR("Skip this version"), Button::Variant::Ghost,
                 [version]() { AppSettings::Get().setSkippedVersion(version); });
    m->addButton(TR("Later"), Button::Variant::Secondary);
    m->addButton(TR("Update"), Button::Variant::Primary, [this]() {
        toast("ACCENT", TR("Downloading the update…"), TR("The program restarts when it is installed."));
        Updater::instance().download();
    });
    if (!isVisible()) {
        if (automation_) automation_->notify(TR("Version %1 is available").arg(version),
                                             TR("Open Threat Scanner to update."), false);
    }
    m->open();
}

// ─── События окна ───

void MainWindow::changeEvent(QEvent* e) {
    FramelessWindow::changeEvent(e);
    if (e->type() == QEvent::WindowStateChange && titleBar_) titleBar_->setMaximized(isMaximized());
}

void MainWindow::resizeEvent(QResizeEvent* e) {
    FramelessWindow::resizeEvent(e);
    // На узком окне — только иконки: так контенту остаётся место.
    if (sidebar_) sidebar_->setCompact(width() < 1120);
}

void MainWindow::closeEvent(QCloseEvent* e) {
    AppSettings::Get().setWindowGeometry(saveGeometry());
    if (!quitting_ && !demo_ && Automation::trayEnabled()) {
        hide();
        e->ignore();
        static bool told = false;
        if (!told && automation_) {
            automation_->notify("Threat Scanner", TR("The program keeps working in the tray. Right-click the icon to exit."),
                                false);
            told = true;
        }
        return;
    }
    if (AppState::instance().scan().running && !quitting_ && !demo_) {
        e->ignore();
        Modal::confirm(overlayHost(), TR("Stop the scan and exit?"),
                       TR("The scan is still running. Its results so far will be lost."),
                       TR("Exit"), true, [this]() {
                           bridge_->cancelScan();
                           quitting_ = true;
                           close();
                       });
        return;
    }
    e->accept();
    QApplication::quit();
}

void MainWindow::dragEnterEvent(QDragEnterEvent* e) {
    if (!e->mimeData()->hasUrls()) return;
    for (const QUrl& u : e->mimeData()->urls())
        if (u.isLocalFile()) { e->acceptProposedAction(); return; }
}

void MainWindow::dropEvent(QDropEvent* e) {
    QStringList files;
    for (const QUrl& u : e->mimeData()->urls())
        if (u.isLocalFile()) files << u.toLocalFile();
    if (files.isEmpty()) return;
    e->acceptProposedAction();
    checkFiles(files);
}

void MainWindow::onMaximizeButtonHover(bool hovered) {
    if (titleBar_) titleBar_->setMaximizeHovered(hovered);
}
