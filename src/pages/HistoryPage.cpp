#include "HistoryPage.h"

#include "../app/Lang.h"
#include "../app/MainWindow.h"
#include "../app/ScanHistory.h"
#include "../app/Texts.h"

#include <QDesktopServices>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLocale>
#include <QStandardPaths>
#include <QTextStream>
#include <QUrl>
#include <QVBoxLayout>

using namespace Ui;

HistoryPage::HistoryPage(MainWindow* window)
    : Page(window, TR("History"), TR("Past scans are kept between sessions. Open one to see what it found."))
{
    auto* import = new Button(TR("Background scans"), Button::Variant::Ghost);
    import->setToolTip(TR("Load the results of scans made by the background service while the window was closed."));
    import->setIconId(Icons::Id::Refresh);
    actions()->addWidget(import);
    connect(import, &QPushButton::clicked, this, [window]() {
        const int n = ScanHistory::instance().importServiceScans();
        window->toast(n ? "OK" : "INFO", n ? TR("Added %1 background %2").arg(n)
                                               .arg(TRN(n, "scan", "scans", "проверка", "проверки", "проверок"))
                                           : TR("No new background scans"));
    });

    clear_ = new Button(TR("Clear history"), Button::Variant::Secondary);
    clear_->setIconId(Icons::Id::Trash);
    actions()->addWidget(clear_);
    connect(clear_, &QPushButton::clicked, this, [window]() {
        Modal::confirm(window->overlayHost(), TR("Clear the history?"),
                       TR("The list of past scans will be deleted. Quarantine and settings are not affected."),
                       TR("Clear"), true, []() { ScanHistory::instance().clear(); });
    });

    emptyCard_ = new Card(this, 0);
    auto* empty = new EmptyState(Icons::Id::History, TR("No scans yet"),
                                 TR("As soon as you run a scan, its result is saved here."));
    auto* scan = empty->addAction(TR("Quick scan"), Button::Variant::Primary);
    connect(scan, &QPushButton::clicked, this, [window]() { window->startScan(0); });
    static_cast<Card*>(emptyCard_)->body()->addWidget(empty);
    body()->addWidget(emptyCard_);

    listCard_ = new Card(this, 0);
    auto* inner = new QWidget();
    list_ = new QVBoxLayout(inner);
    list_->setContentsMargins(0, 0, 0, 0);
    list_->setSpacing(0);
    static_cast<Card*>(listCard_)->body()->addWidget(inner);
    body()->addWidget(listCard_);
    body()->addStretch(1);

    connect(&ScanHistory::instance(), &ScanHistory::changed, this, &HistoryPage::refresh);
    refresh();
}

void HistoryPage::onShown() { refresh(); }

QWidget* HistoryPage::makeRow(int index) {
    const ScanRecord& r = ScanHistory::instance().records()[index];
    const QLocale loc = Lang::instance().current() == Lang::Id::Ru ? QLocale(QLocale::Russian)
                                                                    : QLocale(QLocale::English);
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(20, 14, 16, 14);
    col->setSpacing(10);

    auto* row = new QHBoxLayout();
    row->setSpacing(14);
    const bool sandbox = r.mode == 3;
    const bool dirty = r.threats > 0;
    auto* icon = new IconLabel(sandbox ? Icons::Id::Cube : (dirty ? Icons::Id::ShieldAlert : Icons::Id::ShieldCheck),
                               18, dirty ? ColorRole::Danger : (r.cancelled ? ColorRole::Warn : ColorRole::Ok));
    icon->setTile(true, 36);
    row->addWidget(icon, 0, Qt::AlignTop);

    auto* text = new QVBoxLayout();
    text->setSpacing(2);
    QString title = sandbox ? TR("Sandbox: %1").arg(QFileInfo(r.target).fileName())
                            : (r.target.isEmpty() ? Texts::modeLabel(r.mode)
                                                  : TR("File check: %1").arg(QFileInfo(r.target).fileName()));
    if (r.bySchedule) title += " · " + TR("background");
    auto* t = makeLabel(title, "subheading");
    t->setWordWrap(true);
    text->addWidget(t);
    text->addWidget(makeLabel(loc.toString(r.when, "d MMMM yyyy, HH:mm") + " · " + formatDuration(r.durationMs) +
                                  " · " + TR("%1 %2").arg(formatCount(r.objects))
                                              .arg(sandbox ? TRN(r.objects, "event", "events", "событие", "события", "событий")
                                                           : TRN(r.objects, "object", "objects", "объект", "объекта", "объектов")),
                              "caption"));
    row->addLayout(text, 1);

    QString resultText;
    QString tone;
    if (r.cancelled) { resultText = TR("Stopped"); tone = "MED"; }
    else if (dirty)  { resultText = TR("Found: %1").arg(r.threats); tone = r.critical ? "CRIT" : "HIGH"; }
    else             { resultText = TR("Clean"); tone = "OK"; }
    row->addWidget(new Pill(resultText, tone), 0, Qt::AlignVCenter);

    // Развёрнутость помним по времени проверки, а не по номеру строки:
    // новая проверка сдвигает номера, и раскрывалась бы чужая запись.
    const qint64 key = r.when.toMSecsSinceEpoch();
    auto* more = new IconButton(expanded_.contains(key) ? Icons::Id::ChevronDown : Icons::Id::ChevronRight,
                                TR("Details"), nullptr, 32);
    row->addWidget(more, 0, Qt::AlignVCenter);
    col->addLayout(row);
    connect(more, &QAbstractButton::clicked, this, [this, key]() {
        if (expanded_.contains(key)) expanded_.remove(key);
        else expanded_.insert(key);
        refresh();
    });

    if (expanded_.contains(key)) {
        auto* details = new QVBoxLayout();
        details->setContentsMargins(50, 0, 0, 0);
        details->setSpacing(8);
        if (r.findings.isEmpty()) {
            details->addWidget(makeLabel(sandbox ? TR("Nothing typical of malware was observed.")
                                                 : TR("Nothing dangerous was found."), "muted"));
        }
        for (const Threat& f : r.findings) {
            auto* fr = new QHBoxLayout();
            fr->setSpacing(10);
            fr->addWidget(new Pill(Texts::severityLabel(f.severity), Texts::severityCode(f.severity)), 0, Qt::AlignTop);
            auto* fc = new QVBoxLayout();
            fc->setSpacing(1);
            fc->addWidget(makeLabel(QString::fromStdWString(f.name) + " — " + Texts::headline(f), "body"));
            auto* path = new ElidedLabel(QString::fromStdWString(f.source), Qt::ElideMiddle);
            path->setProperty("role", "caption");
            fc->addWidget(path);
            fr->addLayout(fc, 1);
            fr->addWidget(makeLabel(Texts::statusLabel(f.status), "caption"), 0, Qt::AlignTop);
            details->addLayout(fr);
        }
        auto* buttons = new QHBoxLayout();
        auto* exportBtn = new Button(TR("Save report…"), Button::Variant::Secondary);
        exportBtn->setSize(Button::Size::Small);
        exportBtn->setIconId(Icons::Id::Download);
        buttons->addWidget(exportBtn);
        connect(exportBtn, &QPushButton::clicked, this, [this, index]() {
            const ScanRecord& rec = ScanHistory::instance().records()[index];
            // Копия: пока открыт диалог, список истории может перестроиться.
            const ScanRecord copy = rec;
            const QString suggested = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) +
                                      "/ThreatScanner-" + copy.when.toString("yyyy-MM-dd-HHmm") + ".html";
            // Формат — по расширению: страница для чтения и пересылки,
            // текст — в письмо или чат, JSON — для разбора программой.
            QString chosen;
            const QString path = QFileDialog::getSaveFileName(
                this, TR("Save report"), suggested,
                TR("Web page (*.html)") + ";;" + TR("Text files (*.txt)") + ";;" + TR("JSON data (*.json)"), &chosen);
            if (path.isEmpty()) return;
            const QString ext = QFileInfo(path).suffix().toLower();
            QFile f(path);
            if (!f.open(QIODevice::WriteOnly)) {
                window()->toast("CRIT", TR("Could not save the report"), f.errorString());
                return;
            }
            QByteArray data;
            if (ext == "json") {
                data = ScanHistory::instance().exportJson(copy);
            } else if (ext == "txt") {
                // С меткой порядка байтов: без неё Блокнот старых Windows
                // читает кириллицу в кодировке системы.
                data = QByteArray("\xEF\xBB\xBF") +
                       ScanHistory::instance().exportText(copy).replace("\n", "\r\n").toUtf8();
            } else {
                data = ScanHistory::instance().exportHtml(copy).toUtf8();
            }
            if (f.write(data) != data.size()) {
                window()->toast("CRIT", TR("Could not save the report"), f.errorString());
                return;
            }
            f.close();
            const QString saved = path;
            window()->toast("OK", TR("Report saved"), QFileInfo(path).fileName(), TR("Open"),
                            [saved]() { QDesktopServices::openUrl(QUrl::fromLocalFile(saved)); });
        });
        if (!r.reportPath.isEmpty() && QFileInfo::exists(r.reportPath)) {
            auto* behavior = new Button(TR("Open behavior report"), Button::Variant::Secondary);
            behavior->setSize(Button::Size::Small);
            buttons->addWidget(behavior);
            connect(behavior, &QPushButton::clicked, this, [this, path = r.reportPath]() {
                emit behaviorReportRequested(path);
            });
        }
        buttons->addStretch(1);
        details->addLayout(buttons);
        col->addLayout(details);
    }
    return w;
}

void HistoryPage::refresh() {
    clearLayout(list_);
    const auto& records = ScanHistory::instance().records();
    for (int i = 0; i < records.size(); ++i) {
        if (i > 0) list_->addWidget(makeDivider());
        list_->addWidget(makeRow(i));
    }
    listCard_->setVisible(!records.isEmpty());
    emptyCard_->setVisible(records.isEmpty());
    clear_->setVisible(!records.isEmpty());
}
