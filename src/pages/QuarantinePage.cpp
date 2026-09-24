#include "QuarantinePage.h"

#include "../app/Lang.h"
#include "../app/MainWindow.h"
#include "../app/ScannerBridge.h"

#include <QDateTime>
#include <QHBoxLayout>
#include <QVBoxLayout>

using namespace Ui;

namespace {

QString SeverityTone(const std::wstring& s) {
    if (s == L"CRIT") return "CRIT";
    if (s == L"HIGH") return "HIGH";
    if (s == L"MED")  return "MED";
    if (s == L"LOW")  return "LOW";
    return "INFO";
}

// Демонстрационные записи для снимков экрана.
std::vector<QuarantineItem> DemoItems() {
    QuarantineItem a;
    a.id = "demo1";
    a.originalName = L"invoice_2026.pdf.exe";
    a.originalPath = L"C:\\Users\\Alex\\Downloads\\invoice_2026.pdf.exe";
    a.threatName = L"AgentTesla";
    a.severity = L"CRIT";
    a.quarantinedAt = "2026-09-24 10:12:40";
    a.size = 1'204'224;
    QuarantineItem b;
    b.id = "demo2";
    b.originalName = L"update_helper.ps1";
    b.originalPath = L"C:\\Users\\Alex\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update_helper.ps1";
    b.threatName = L"Suspicious script";
    b.severity = L"HIGH";
    b.quarantinedAt = "2026-09-23 19:47:02";
    b.size = 4'812;
    return { a, b };
}

} // namespace

QuarantinePage::QuarantinePage(MainWindow* window)
    : Page(window, TR("Quarantine"),
           TR("Isolated files cannot run. Restore a file if it was flagged by mistake, or delete it for good."))
{
    clearAll_ = new Button(TR("Delete all"), Button::Variant::Secondary);
    clearAll_->setIconId(Icons::Id::Trash);
    actions()->addWidget(clearAll_);
    connect(clearAll_, &QPushButton::clicked, this, [this, window]() {
        Modal::confirm(window->overlayHost(), TR("Delete everything in quarantine?"),
                       TR("All isolated files will be deleted for good. This cannot be undone."),
                       TR("Delete all"), true, [this, window]() {
                           for (const QuarantineItem& item : items_) {
                               window->bridge()->deleteFromQuarantine(QString::fromStdString(item.id),
                                   [window](bool, const QString&) { emit window->quarantineChanged(); });
                           }
                       });
    });

    emptyCard_ = new Card(this, 0);
    empty_ = new EmptyState(Icons::Id::Quarantine, TR("Quarantine is empty"),
                            TR("Files you move to quarantine are kept here in a form that cannot run."));
    static_cast<Card*>(emptyCard_)->body()->addWidget(empty_);
    body()->addWidget(emptyCard_);

    listCard_ = new Card(this, 0);
    auto* inner = new QWidget();
    list_ = new QVBoxLayout(inner);
    list_->setContentsMargins(0, 0, 0, 0);
    list_->setSpacing(0);
    static_cast<Card*>(listCard_)->body()->addWidget(inner);
    body()->addWidget(listCard_);
    body()->addStretch(1);

    connect(window, &MainWindow::quarantineChanged, this, &QuarantinePage::refresh);
    refresh();
}

void QuarantinePage::onShown() { refresh(); }

QWidget* QuarantinePage::makeRow(const QuarantineItem& item) {
    auto* row = new QWidget();
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(20, 14, 16, 14);
    h->setSpacing(14);

    auto* icon = new IconLabel(Icons::Id::File, 18, ColorRole::Text2);
    icon->setTile(true, 36);
    h->addWidget(icon, 0, Qt::AlignTop);

    auto* col = new QVBoxLayout();
    col->setSpacing(2);
    auto* top = new QHBoxLayout();
    top->setSpacing(8);
    auto* name = makeLabel(QString::fromStdWString(item.originalName), "subheading");
    name->setWordWrap(true);
    top->addWidget(name, 1);
    top->addWidget(new Pill(QString::fromStdWString(item.threatName.empty() ? L"—" : item.threatName),
                            SeverityTone(item.severity)));
    col->addLayout(top);
    auto* path = new ElidedLabel(QString::fromStdWString(item.originalPath), Qt::ElideMiddle);
    path->setProperty("role", "caption");
    col->addWidget(path);
    const QDateTime when = QDateTime::fromString(QString::fromStdString(item.quarantinedAt), "yyyy-MM-dd HH:mm:ss");
    col->addWidget(makeLabel(TR("Isolated %1 · %2").arg(when.toString("dd.MM.yyyy HH:mm"),
                                                        formatBytes(static_cast<qint64>(item.size))), "caption"));
    h->addLayout(col, 1);

    auto* restore = new Button(TR("Restore"), Button::Variant::Secondary);
    restore->setSize(Button::Size::Small);
    restore->setIconId(Icons::Id::Restore);
    auto* del = new Button(TR("Delete"), Button::Variant::Ghost);
    del->setSize(Button::Size::Small);
    del->setIconId(Icons::Id::Trash);
    h->addWidget(restore, 0, Qt::AlignVCenter);
    h->addWidget(del, 0, Qt::AlignVCenter);

    MainWindow* w = window();
    const QString id = QString::fromStdString(item.id);
    const QString nameText = QString::fromStdWString(item.originalName);
    connect(restore, &QPushButton::clicked, this, [w, id, nameText]() {
        Modal::confirm(w->overlayHost(), TR("Restore %1?").arg(nameText),
                       TR("The file goes back to where it was and can run again. Restore it only if you are "
                          "sure it was flagged by mistake."),
                       TR("Restore"), false, [w, id, nameText]() {
                           w->bridge()->restoreFromQuarantine(id, [w, nameText](bool ok, const QString& err) {
                               if (ok) w->toast("OK", TR("Restored"), nameText);
                               else w->toast("CRIT", TR("Could not restore the file"), err);
                               emit w->quarantineChanged();
                           });
                       });
    });
    connect(del, &QPushButton::clicked, this, [w, id, nameText]() {
        Modal::confirm(w->overlayHost(), TR("Delete %1 for good?").arg(nameText),
                       TR("The isolated copy will be deleted. This cannot be undone."),
                       TR("Delete"), true, [w, id, nameText]() {
                           w->bridge()->deleteFromQuarantine(id, [w, nameText](bool ok, const QString& err) {
                               if (ok) w->toast("OK", TR("Deleted"), nameText);
                               else w->toast("CRIT", TR("Could not delete the file"), err);
                               emit w->quarantineChanged();
                           });
                       });
    });
    return row;
}

void QuarantinePage::refresh() {
    clearLayout(list_);
    items_ = window()->demoMode() ? DemoItems() : Quarantine::Instance().List();
    std::sort(items_.begin(), items_.end(), [](const QuarantineItem& a, const QuarantineItem& b) {
        return a.quarantinedAt > b.quarantinedAt;
    });
    for (size_t i = 0; i < items_.size(); ++i) {
        if (i > 0) list_->addWidget(makeDivider());
        list_->addWidget(makeRow(items_[i]));
    }
    const bool any = !items_.empty();
    listCard_->setVisible(any);
    emptyCard_->setVisible(!any);
    clearAll_->setVisible(any);
    setSubtitle(any ? TR("%1 %2 isolated. They cannot run while they are here.")
                          .arg(items_.size())
                          .arg(TRN(static_cast<qint64>(items_.size()), "file", "files", "файл", "файла", "файлов"))
                    : TR("Isolated files cannot run. Restore a file if it was flagged by mistake, or delete it for good."));
}
