#include "BehaviorPage.h"

#include "../app/AppState.h"
#include "../app/Lang.h"
#include "../app/MainWindow.h"
#include "../app/ScanHistory.h"
#include "../app/ScannerBridge.h"
#include "../app/Texts.h"
#include "../core/BehaviorVerdict.h"
#include "../core/Logger.h"
#include "../core/SandboxEnvironment.h"
#include "../core/SandboxSession.h"

#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLineEdit>
#include <QStandardPaths>
#include <QTableWidget>
#include <QVBoxLayout>

using namespace Ui;

namespace {

QString SevCode(Severity s) {
    switch (s) {
    case Severity::Critical: return "CRIT";
    case Severity::High:     return "HIGH";
    case Severity::Medium:   return "MED";
    case Severity::Low:      return "LOW";
    default:                 return "INFO";
    }
}

QString EventGroup(BehaviorEventType t) {
    switch (t) {
    case BehaviorEventType::ProcessStarted: return TR("Process started");
    case BehaviorEventType::ProcessExited:  return TR("Process exited");
    case BehaviorEventType::FileCreated:    return TR("File created");
    case BehaviorEventType::FileModified:   return TR("File changed");
    case BehaviorEventType::FileDeleted:    return TR("File deleted");
    case BehaviorEventType::FileRenamed:    return TR("File renamed");
    case BehaviorEventType::RegistryValueSet:     return TR("Registry value added");
    case BehaviorEventType::RegistryValueChanged: return TR("Registry value changed");
    case BehaviorEventType::RegistryValueDeleted: return TR("Registry value deleted");
    case BehaviorEventType::RegistryKeyCreated:   return TR("Registry key created");
    case BehaviorEventType::RegistryKeyDeleted:   return TR("Registry key deleted");
    case BehaviorEventType::NetworkConnection:    return TR("Outgoing connection");
    case BehaviorEventType::NetworkListen:        return TR("Port opened");
    default:                                      return TR("Observer note");
    }
}

// Постоянная часть английской фразы переводится, хвост с путями — нет.
QString TranslatePrefixed(const QString& text) {
    static const char* kPrefixes[] = {
        "Only these directories were watched: ", "Directory could not be watched: ",
    };
    for (const char* p : kPrefixes) {
        const QString prefix = QString::fromLatin1(p);
        if (text.startsWith(prefix)) return TR(prefix.trimmed()) + " " + text.mid(prefix.size());
    }
    return TR(text);
}

QString ReportsFolder() {
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return base.isEmpty() ? QString() : base + "/sandbox/reports";
}

} // namespace

BehaviorPage::BehaviorPage(MainWindow* window)
    : Page(window, TR("Behavior"),
           TR("Run a suspicious file in Windows Sandbox, an isolated copy of Windows that is thrown away "
              "afterwards, and see what it does."))
{
    auto* open = new Button(TR("Open report…"), Button::Variant::Secondary);
    open->setIconId(Icons::Id::File);
    actions()->addWidget(open);
    connect(open, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(this, TR("Open a behavior report"), ReportsFolder(),
                                                          TR("Behavior reports (*.json)"));
        if (!path.isEmpty()) loadReportFile(path);
    });

    availability_ = new Banner("INFO", Icons::Id::Cube, QString(), QString());
    body()->addWidget(availability_);

    // ─── Образец ───
    auto* sample = new Card(this, 22);
    sampleCard_ = sample;
    sample->body()->addWidget(makeLabel(TR("File to observe"), "heading"));
    auto* pathRow = new QHBoxLayout();
    samplePath_ = new QLineEdit();
    samplePath_->setPlaceholderText(TR("Choose a program or script"));
    auto* browse = new Button(TR("Browse…"), Button::Variant::Secondary);
    pathRow->addWidget(samplePath_, 1);
    pathRow->addWidget(browse);
    sample->body()->addLayout(pathRow);
    connect(browse, &QPushButton::clicked, this, [this]() {
        const QString f = QFileDialog::getOpenFileName(this, TR("Choose a file to observe"));
        if (!f.isEmpty()) samplePath_->setText(QDir::toNativeSeparators(f));
    });

    duration_ = new Segmented({ TR("30 s"), TR("1 min"), TR("2 min"), TR("5 min") });
    duration_->setCurrent(1);
    sample->body()->addWidget(new SettingRow(TR("Observation time"),
        TR("How long to watch the file after it starts. Some malware waits before doing anything."), duration_));
    sample->body()->addWidget(makeDivider());
    network_ = new Toggle();
    sample->body()->addWidget(new SettingRow(TR("Allow internet access"),
        TR("Off by default. With the internet on, the file can download more malware or send data, "
           "but you see its network activity."), network_));

    auto* startRow = new QHBoxLayout();
    start_ = new Button(TR("Run in sandbox"), Button::Variant::Primary);
    start_->setIconId(Icons::Id::Play);
    startRow->addWidget(start_);
    startRow->addStretch(1);
    sample->body()->addSpacing(4);
    sample->body()->addLayout(startRow);
    body()->addWidget(sample);
    connect(start_, &QPushButton::clicked, this, &BehaviorPage::start);

    // ─── Ход ───
    auto* prog = new Card(this, 22);
    progressCard_ = prog;
    auto* progRow = new QHBoxLayout();
    spinner_ = new Spinner(20);
    progRow->addWidget(spinner_);
    stage_ = makeLabel(QString(), "subheading");
    progRow->addWidget(stage_, 1);
    auto* cancel = new Button(TR("Stop"), Button::Variant::Secondary);
    progRow->addWidget(cancel);
    prog->body()->addLayout(progRow);
    prog->body()->addWidget(makeLabel(TR("The sandbox window opens separately. When the observation ends it "
                                         "closes by itself, together with everything the file changed."), "muted"));
    connect(cancel, &QPushButton::clicked, this, [window]() { window->bridge()->cancelSandbox(); });
    progressCard_->setVisible(false);
    body()->addWidget(prog);

    // ─── Отчёт ───
    auto* report = new Card(this, 22);
    reportCard_ = report;
    reportLayout_ = report->body();
    reportCard_->setVisible(false);
    body()->addWidget(report);
    body()->addStretch(1);

    connect(window->bridge(), &ScannerBridge::sandboxStage, this, &BehaviorPage::onStage);
    connect(window->bridge(), &ScannerBridge::sandboxFinished, this, &BehaviorPage::onFinished);
    refreshAvailability();
}

void BehaviorPage::onShown() { refreshAvailability(); }

void BehaviorPage::refreshAvailability() {
    const SandboxEnvironment::Info& env = SandboxEnvironment::Get();
    availability_->setClosable(false);
    // Кнопки предыдущего состояния убираем: набор зависит от причины.
    for (auto* b : availability_->findChildren<Button*>()) b->deleteLater();

    switch (env.status) {
    case SandboxEnvironment::Status::Available:
        availability_->setTone("OK");
        availability_->setText(TR("Windows Sandbox is ready"),
                               TR("The file runs in a disposable copy of Windows. Nothing it does reaches this computer."));
        break;
    case SandboxEnvironment::Status::NotOnThisEdition:
        availability_->setTone("INFO");
        availability_->setText(TR("Windows Sandbox is not available on %1").arg(QString::fromStdWString(env.editionName)),
                               TR("Microsoft includes the sandbox only in Pro, Enterprise and Education editions. "
                                  "It cannot be installed on Home. Everything else in this program works as usual: "
                                  "check suspicious files with a scan or on VirusTotal."));
        break;
    case SandboxEnvironment::Status::ComponentMissing: {
        availability_->setTone("MED");
        availability_->setText(TR("Windows Sandbox is not turned on"),
                               TR("Your edition of Windows supports it. Turning it on takes a couple of minutes and "
                                  "needs a restart."));
        auto* enable = availability_->addAction(TR("Turn on Windows Sandbox"), Button::Variant::Primary);
        connect(enable, &QPushButton::clicked, this, [this, enable]() {
            enable->setEnabled(false);
            enable->setText(TR("Turning on…"));
            window()->bridge()->enableSandboxFeature([this, enable](bool ok, int code, const QString& error) {
                if (ok) {
                    availability_->setText(TR("Windows Sandbox is turned on"),
                                           TR("Restart the computer to finish the installation."));
                    availability_->setTone("OK");
                    enable->hide();
                    window()->toast("OK", TR("Windows Sandbox is turned on"), TR("Restart the computer to finish."));
                } else {
                    enable->setEnabled(true);
                    enable->setText(TR("Turn on Windows Sandbox"));
                    window()->toast("CRIT", TR("Could not turn on Windows Sandbox"),
                                    error.isEmpty() ? TR("DISM exit code %1").arg(code) : error);
                }
            });
        });
        break;
    }
    case SandboxEnvironment::Status::NoVirtualization:
        availability_->setTone("MED");
        availability_->setText(TR("Hardware virtualization is turned off"),
                               TR("Windows Sandbox needs Intel VT-x or AMD-V. Turn it on in the UEFI (BIOS) settings, "
                                  "usually under CPU or Advanced settings, then come back here to turn on the sandbox."));
        break;
    default:
        availability_->setTone("MED");
        availability_->setText(TR("Could not check Windows Sandbox"), QString::fromStdWString(env.reason));
        break;
    }
    const bool available = env.status == SandboxEnvironment::Status::Available;
    sampleCard_->setEnabled(available && !running_);
}

void BehaviorPage::start() {
    const QString path = samplePath_->text().trimmed();
    if (path.isEmpty() || !QFileInfo(path).isFile()) {
        window()->toast("MED", TR("Choose a file first"), TR("The sandbox runs one file at a time."));
        return;
    }
    static const int kSeconds[] = { 30, 60, 120, 300 };
    const int ms = kSeconds[std::clamp(duration_->current(), 0, 3)] * 1000;
    QJsonObject options;
    options["samplePath"] = path;
    options["observeTimeoutMs"] = ms;
    options["networking"] = network_->isChecked();
    options["waitForReportMs"] = ms + 300000;
    options["closeWhenDone"] = true;
    QString error;
    if (!window()->bridge()->startSandbox(options, &error)) {
        window()->toast("CRIT", TR("Could not start the sandbox"), error);
        return;
    }
    running_ = true;
    runningSample_ = path;
    sampleCard_->setEnabled(false);
    progressCard_->setVisible(true);
    spinner_->setRunning(true);
    stage_->setText(TR("Preparing the isolated session"));
    reportCard_->setVisible(false);
}

void BehaviorPage::onStage(const QString& stage) {
    stage_->setText(TR(stage));
}

void BehaviorPage::onFinished(int result, const QString& message, const QString& howToFix,
                              const QString& reportPath)
{
    running_ = false;
    spinner_->setRunning(false);
    progressCard_->setVisible(false);
    refreshAvailability();

    if (result != static_cast<int>(SandboxSession::Result::Completed) || reportPath.isEmpty()) {
        window()->toast("CRIT", TR("The sandbox session did not complete"),
                        TR(message) + (howToFix.isEmpty() ? QString() : "\n" + TR(howToFix)));
        return;
    }
    BehaviorReport report;
    std::wstring error;
    if (!SandboxSession::ReadReportJson(reportPath.toStdWString(), report, &error)) {
        window()->toast("CRIT", TR("Could not read the report"), QString::fromStdWString(error));
        return;
    }
    publish(report, reportPath);
    showReport(report, false);
}

void BehaviorPage::loadReportFile(const QString& path) {
    BehaviorReport report;
    std::wstring error;
    if (!SandboxSession::ReadReportJson(path.toStdWString(), report, &error)) {
        window()->toast("CRIT", TR("Could not read the report"), QString::fromStdWString(error));
        return;
    }
    showReport(report, true);
}

void BehaviorPage::publish(const BehaviorReport& report, const QString& reportPath) {
    const BehaviorVerdict verdict = JudgeBehavior(report);
    ScanRecord rec;
    rec.when = QDateTime::currentDateTime();
    rec.mode = 3;
    rec.reportPath = reportPath;
    rec.durationMs = report.durationMs;
    rec.objects = static_cast<qint64>(report.events.size());
    rec.target = runningSample_;
    if (VerdictWarrantsThreat(verdict)) {
        Threat t = ThreatFromBehaviour(runningSample_.toStdWString(), report, verdict);
        t.malwareClass = 18;   // MalwareClass::Suspicious
        rec.threats = 1;
        rec.critical = verdict.severity == Severity::Critical ? 1 : 0;
        rec.findings.push_back(t);
        AppState::instance().addLocalThreat(t);
    }
    ScanHistory::instance().add(rec);
}

void BehaviorPage::showReport(const BehaviorReport& report, bool fromFile) {
    clearLayout(reportLayout_);
    const BehaviorVerdict verdict = JudgeBehavior(report);

    auto* head = new QHBoxLayout();
    head->setSpacing(10);
    head->addWidget(new Pill(Texts::severityLabel(verdict.severity), SevCode(verdict.severity)), 0, Qt::AlignTop);
    auto* summary = makeLabel(TR(QString::fromStdWString(verdict.summary)), "heading");
    summary->setWordWrap(true);
    head->addWidget(summary, 1);
    reportLayout_->addLayout(head);

    QString meta = QFileInfo(QString::fromStdWString(report.target)).fileName() + " · " +
                   formatDuration(report.durationMs) + " · " +
                   TR("%1 events").arg(report.events.size());
    if (report.timedOut) meta += " · " + TR("time limit reached");
    if (fromFile) meta += " · " + TR("opened from a file");
    reportLayout_->addWidget(makeLabel(meta, "caption"));

    if (!verdict.findings.empty()) {
        reportLayout_->addWidget(makeLabel(TR("What it did"), "label"));
        for (const auto& f : verdict.findings) {
            auto* row = new QHBoxLayout();
            row->setSpacing(10);
            row->addWidget(new Pill(Texts::severityLabel(f.severity), SevCode(f.severity)), 0, Qt::AlignTop);
            auto* col = new QVBoxLayout();
            col->setSpacing(1);
            col->addWidget(makeLabel(TR(QString::fromStdWString(f.title)), "body"));
            if (!f.detail.empty()) {
                auto* d = makeLabel(QString::fromStdWString(f.detail), "caption");
                d->setTextInteractionFlags(Qt::TextSelectableByMouse);
                col->addWidget(d);
            }
            row->addLayout(col, 1);
            reportLayout_->addLayout(row);
        }
    }

    // Лента событий.
    if (!report.events.empty()) {
        reportLayout_->addWidget(makeLabel(TR("Events"), "label"));
        auto* table = new QTableWidget(static_cast<int>(report.events.size()), 3);
        table->setHorizontalHeaderLabels({ TR("Time"), TR("Event"), TR("Object") });
        table->verticalHeader()->setVisible(false);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setWordWrap(false);
        table->setShowGrid(false);
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
        table->setColumnWidth(0, 80);
        table->setColumnWidth(1, 210);
        table->verticalHeader()->setDefaultSectionSize(34);
        for (int i = 0; i < static_cast<int>(report.events.size()); ++i) {
            const BehaviorEvent& e = report.events[i];
            table->setItem(i, 0, new QTableWidgetItem(QString::number(e.atMs / 1000.0, 'f', 1) + " " + TR("s")));
            table->setItem(i, 1, new QTableWidgetItem(EventGroup(e.type)));
            QString obj = QString::fromStdWString(e.target);
            if (!e.detail.empty()) obj += "  —  " + QString::fromStdWString(e.detail);
            auto* item = new QTableWidgetItem(obj);
            item->setToolTip(obj);
            table->setItem(i, 2, item);
        }
        table->setMinimumHeight(std::min(420, 40 + 34 * static_cast<int>(report.events.size())));
        reportLayout_->addWidget(table);
    }

    // Ограничения — всегда, иначе отчёт выглядит полным, а он не полный.
    reportLayout_->addWidget(makeLabel(TR("What this observation could not see"), "label"));
    for (const auto& l : report.limitations)
        reportLayout_->addWidget(makeLabel("• " + TranslatePrefixed(QString::fromStdWString(l)), "muted"));
    reportCard_->setVisible(true);
}
