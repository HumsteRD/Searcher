#include "DemoData.h"

#include "AppState.h"
#include "Lang.h"
#include "MainWindow.h"
#include "ScanHistory.h"

#include "../core/Detections.h"
#include "../engine/Verdict.h"
#include "../pages/Page.h"
#include "../ui/Shell.h"
#include "../ui/Theme.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QTextStream>
#include <QThread>

namespace DemoData {
namespace {

Threat MakeThreat(const wchar_t* name, const wchar_t* source, Severity sev, MalwareClass cls,
                  const char* family, ThreatKind kind, std::vector<std::string> reasons)
{
    Threat t;
    t.name = name;
    t.source = source;
    t.filePath = source;
    t.severity = sev;
    t.malwareClass = static_cast<int>(cls);
    t.family = family;
    t.kind = kind;
    t.reasons = std::move(reasons);
    t.sha256 = "3f5a1c9e0b7d42a18e6f4c2b9d0a7e13c5b8f2d6a4e9c1b7f3a0d8e5c2b6f9a1";
    return t;
}

void FillFindings() {
    AppState& st = AppState::instance();
    st.clearItems();
    st.addLocalThreat(MakeThreat(L"invoice_2026.pdf.exe", L"C:\\Users\\Alex\\Downloads\\invoice_2026.pdf.exe",
        Severity::Critical, MalwareClass::Stealer, "AgentTesla", ThreatKind::File,
        { "hash\tAgentTesla\t", "yara\tMALPEDIA_Win_Agent_Tesla_Auto\t75\tDetects Agent Tesla payload\t",
          "deceptive\tdouble-extension:.pdf.exe", "location.risky" }));
    st.addLocalThreat(MakeThreat(L"WindowsUpdater", L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run :: WindowsUpdater",
        Severity::High, MalwareClass::Loader, "", ThreatKind::RegistryValue,
        { "autorun\tHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "cmd.encoded", "cmd.download",
          "runs\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" }));
    st.addLocalThreat(MakeThreat(L"xmrig.exe", L"C:\\ProgramData\\SystemCache\\xmrig.exe",
        Severity::Critical, MalwareClass::Miner, "CoinMiner", ThreatKind::Process,
        { "process\t8412", "hash\tCoinMiner\t", "net.pool\t94.130.12.30:3333" }));
    st.addLocalThreat(MakeThreat(L"steam_unlocker.zip", L"C:\\Users\\Alex\\Desktop\\steam_unlocker.zip",
        Severity::High, MalwareClass::Stealer, "LummaStealer", ThreatKind::File,
        { "yara\tSEKOIA_Infostealer_Win_Lumma_Str_Jan24\t80\tFinds Lumma samples based on strings\tsetup.exe",
          "container\tzip" }));
    st.addLocalThreat(MakeThreat(L"cleanup.ps1", L"C:\\Users\\Alex\\AppData\\Local\\Temp\\cleanup.ps1",
        Severity::Medium, MalwareClass::Suspicious, "", ThreatKind::File,
        { "script.download-exec", "script.hidden-window", "script.defender-exclusion", "location.risky" }));
    Threat done = MakeThreat(L"EICAR.com", L"C:\\Users\\Alex\\Downloads\\eicar.com", Severity::Medium,
                             MalwareClass::TestFile, "EICAR", ThreatKind::File, { "eicar" });
    done.status = ThreatStatus::Quarantined;
    done.actionMessage = L"quarantined";
    st.addLocalThreat(done);
}

void FillHistory() {
    QVector<ScanRecord> recs;
    const QDateTime now = QDateTime::currentDateTime();
    ScanRecord a;
    a.when = now.addSecs(-3600);
    a.mode = 0; a.durationMs = 142000; a.objects = 48213; a.threats = 5; a.critical = 2;
    for (const auto& it : AppState::instance().items()) a.findings.push_back(it.threat);
    recs << a;
    ScanRecord b;
    b.when = now.addDays(-1);
    b.mode = 1; b.durationMs = 1860000; b.objects = 412880;
    recs << b;
    ScanRecord c;
    c.when = now.addDays(-2);
    c.mode = 2; c.durationMs = 1200; c.objects = 1; c.target = "C:\\Users\\Alex\\Downloads\\setup.exe";
    recs << c;
    ScanRecord d;
    d.when = now.addDays(-3);
    d.mode = 0; d.durationMs = 95000; d.objects = 39110; d.cancelled = true; d.bySchedule = true;
    recs << d;
    ScanHistory::instance().setTransient(recs);
}

void Settle(int ms = 120) {
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        // Цикл событий приложения здесь не запущен, и отложенное удаление
        // само не срабатывает — старые виджеты попали бы на снимок.
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QThread::msleep(5);
    }
}

} // namespace

int RunScreenshotTour(const QString& outDir) {
    QDir().mkpath(outDir);
    const auto originalTheme = Ui::Theme::instance().id();
    const auto originalLang = Lang::instance().current();
    Lang::instance().trackMissing(true);

    MainWindow w(true);
    w.setAttribute(Qt::WA_DontShowOnScreen, true);
    w.show();
    Settle(300);

    const char* pageNames[] = { "home", "scan", "results", "quarantine", "behavior", "history", "log",
                                "settings", "help" };
    const QSize sizes[] = { { 1000, 680 }, { 1280, 800 }, { 1920, 1040 } };
    const std::pair<Ui::Theme::Id, const char*> themes[] = {
        { Ui::Theme::Id::Light, "light" }, { Ui::Theme::Id::Dark, "dark" }, { Ui::Theme::Id::Graphite, "graphite" },
    };
    const std::pair<Lang::Id, const char*> langs[] = { { Lang::Id::Ru, "ru" }, { Lang::Id::En, "en" } };

    int shots = 0;
    auto snap = [&](const QString& name) {
        Settle(60);
        const QPixmap pm = w.grab();
        pm.save(outDir + "/" + name + ".png");
        ++shots;
    };

    // Пустое состояние — до демонстрационных данных.
    Ui::Theme::instance().setId(Ui::Theme::Id::Light);
    Lang::instance().setLanguage(Lang::Id::Ru);
    Settle(200);
    w.resize(1280, 800);
    for (int p : { MainWindow::Home, MainWindow::Scan, MainWindow::Results, MainWindow::History }) {
        w.navigate(p);
        snap(QString("empty-light-ru-1280-%1").arg(pageNames[p]));
    }

    w.appendLog("Scan started: Quick scan", "INF");
    w.appendLog("[YARA] 4956 rules ready (core set)", "INF");
    w.appendLog("[Files] Stealer/AgentTesla (hash + signatures): C:\\Users\\Alex\\Downloads\\invoice_2026.pdf.exe", "WRN");
    w.appendLog("[Autoruns] flagged: HKCU\\...\\Run :: WindowsUpdater", "WRN");
    w.appendLog("The helper with administrator rights stopped.", "ERR");

    for (const auto& [themeId, themeName] : themes) {
        Ui::Theme::instance().setId(themeId);
        for (const auto& [langId, langName] : langs) {
            Lang::instance().setLanguage(langId);
            Settle(200);
            for (const QSize& size : sizes) {
                w.resize(size);
                Settle(150);
                const QString prefix = QString("%1-%2-%3").arg(themeName, langName).arg(size.width());

                // Проверка в процессе.
                AppState& st = AppState::instance();
                st.beginScan(0, false, QString(), { 1, 2, 3, 4, 5, 0 });
                st.setProgress(47, "Files");
                st.setDetail("C:\\Users\\Alex\\AppData\\Local\\Programs\\SomeApplication\\resources\\app\\node_modules\\electron\\dist\\electron.exe",
                             48213, 83000, 91000);
                FillFindings();
                w.navigate(MainWindow::Scan);
                snap(prefix + "-scan-running");
                w.navigate(MainWindow::Home);
                snap(prefix + "-home-running");
                if (size.width() == 1280) {
                    // Пауза и карточка отчёта по одному файлу.
                    st.setPaused(true);
                    w.navigate(MainWindow::Scan);
                    snap(prefix + "-scan-paused");
                    st.setPaused(false);
                    w.showFileReport("C:\\Users\\Alex\\Downloads\\obs-studio-31.0-windows-x64-installer.exe", true, false,
                                     QString(), "3f5a1c9e0b7d42a18e6f4c2b9d0a7e13c5b8f2d6a4e9c1b7f3a0d8e5c2b6f9a1",
                                     "OBS Project, LLC", 148'512'768, QString(), QString());
                    snap(prefix + "-file-report");
                    for (Ui::Modal* m : w.findChildren<Ui::Modal*>()) m->close();
                    Settle(60);
                }
                st.finishScan(false);

                // Завершённая проверка с находками.
                st.beginScan(0, false, QString());
                FillFindings();
                st.setDetail(QString(), 48213, 142000, 0);
                st.finishScan(false);
                FillHistory();
                for (int p = 0; p < MainWindow::PageCount; ++p) {
                    w.navigate(p);
                    snap(prefix + "-" + pageNames[p]);
                    // Длинные страницы — экран за экраном, в одном размере
                    // окна на тему и язык: иначе всё, что ниже первого
                    // экрана (половина настроек, справка), никто не видит.
                    if (size.width() != 1280) continue;
                    Page* page = w.page(p);
                    for (int screen = 2; page && screen <= 6 && page->scrollPageDown(); ++screen)
                        snap(prefix + "-" + pageNames[p] + "-" + QString::number(screen));
                    if (page) page->scrollToTop();
                }
            }
        }
    }

    // Пропущенные переводы — в файл: их видно до выпуска.
    QFile missing(outDir + "/missing-ru.txt");
    if (missing.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&missing);
        out.setEncoding(QStringConverter::Utf8);
        QStringList keys = Lang::instance().missing().values();
        keys.sort();
        for (const QString& k : keys) out << k << "\n";
    }

    Ui::Theme::instance().setId(originalTheme);
    Lang::instance().setLanguage(originalLang);
    w.close();
    return shots;
}

} // namespace DemoData
