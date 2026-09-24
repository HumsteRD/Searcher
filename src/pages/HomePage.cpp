#include "HomePage.h"

#include "../app/AppSettings.h"
#include "../app/AppState.h"
#include "../app/Automation.h"
#include "../app/Lang.h"
#include "../app/MainWindow.h"
#include "../app/ScanHistory.h"
#include "../app/Texts.h"
#include "../app/Updater.h"
#include "../core/Quarantine.h"
#include "../engine/HashDatabase.h"
#include "../engine/SignatureStore.h"
#include "../engine/YaraEngine.h"

#include <QDate>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLocale>
#include <QVBoxLayout>

using namespace Ui;

namespace {

QString Ago(const QDateTime& when) {
    if (!when.isValid()) return {};
    const qint64 s = when.secsTo(QDateTime::currentDateTime());
    if (s < 90) return TR("just now");
    if (s < 3600) {
        const qint64 m = s / 60;
        return TR("%1 %2 ago").arg(m).arg(TRN(m, "minute", "minutes", "минуту", "минуты", "минут"));
    }
    if (s < 86400) {
        const qint64 h = s / 3600;
        return TR("%1 %2 ago").arg(h).arg(TRN(h, "hour", "hours", "час", "часа", "часов"));
    }
    const qint64 d = s / 86400;
    if (d == 1) return TR("yesterday");
    return TR("%1 %2 ago").arg(d).arg(TRN(d, "day", "days", "день", "дня", "дней"));
}

QString StampDate(uint32_t stamp) {
    if (!stamp) return QStringLiteral("—");
    return QDate::fromString(QString::number(stamp), "yyyyMMdd").toString("dd.MM.yyyy");
}

// Строка «Защита»: название, состояние, ссылка на настройку.
QHBoxLayout* StateRow(QVBoxLayout* into, Icons::Id icon, const QString& title, QLabel** state,
                      QWidget* action)
{
    auto* row = new QHBoxLayout();
    row->setSpacing(12);
    row->addWidget(new IconLabel(icon, 18, ColorRole::Text2));
    auto* col = new QVBoxLayout();
    col->setSpacing(1);
    auto* t = makeLabel(title, "body");
    t->setWordWrap(true);
    col->addWidget(t);
    *state = makeLabel(QString(), "caption");
    col->addWidget(*state);
    row->addLayout(col, 1);
    if (action) row->addWidget(action, 0, Qt::AlignVCenter);
    into->addLayout(row);
    return row;
}

} // namespace

HomePage::HomePage(MainWindow* window)
    : Page(window, TR("Overview"), TR("The protection status of this computer at a glance."))
{
    // ─── Главная карточка ───
    auto* hero = new Card(this, 24);
    auto* heroRow = new QHBoxLayout();
    heroRow->setSpacing(20);
    heroIcon_ = new IconLabel(Icons::Id::Shield, 28, ColorRole::Text2);
    heroIcon_->setTile(true, 56);
    heroRow->addWidget(heroIcon_, 0, Qt::AlignTop);

    auto* heroCol = new QVBoxLayout();
    heroCol->setSpacing(6);
    heroTitle_ = makeLabel(QString(), "hero");
    heroTitle_->setWordWrap(true);
    heroText_ = makeLabel(QString(), "muted");
    heroProgress_ = new ProgressBar();
    heroProgress_->setMaximumWidth(420);
    heroCol->addWidget(heroTitle_);
    heroCol->addWidget(heroText_);
    heroCol->addSpacing(4);
    heroCol->addWidget(heroProgress_);

    auto* buttons = new QHBoxLayout();
    buttons->setSpacing(8);
    primary_ = new Button(QString(), Button::Variant::Primary);
    secondary_ = new Button(QString(), Button::Variant::Secondary);
    buttons->addWidget(primary_);
    buttons->addWidget(secondary_);
    buttons->addStretch(1);
    heroCol->addSpacing(8);
    heroCol->addLayout(buttons);
    heroRow->addLayout(heroCol, 1);
    hero->body()->addLayout(heroRow);
    body()->addWidget(hero);

    // ─── Показатели ───
    auto* grid = new AdaptiveGrid(210, 4);
    lastScan_ = new StatTile(Icons::Id::History, TR("Last scan"));
    pending_ = new StatTile(Icons::Id::Alert, TR("Need your decision"));
    quarantine_ = new StatTile(Icons::Id::Quarantine, TR("In quarantine"));
    databases_ = new StatTile(Icons::Id::Database, TR("Signature databases"));
    for (StatTile* t : { lastScan_, pending_, quarantine_, databases_ }) grid->addWidget(t);
    pending_->setClickable(true);
    quarantine_->setClickable(true);
    lastScan_->setClickable(true);
    connect(pending_, &StatTile::clicked, this, [window]() { window->navigate(MainWindow::Results); });
    connect(quarantine_, &StatTile::clicked, this, [window]() { window->navigate(MainWindow::Quarantine); });
    connect(lastScan_, &StatTile::clicked, this, [window]() { window->navigate(MainWindow::History); });
    body()->addWidget(grid);

    // ─── Проверить файл и защита ───
    auto* lower = new AdaptiveGrid(360, 2);

    auto* drop = new Card(this, 22);
    auto* dropHead = new QHBoxLayout();
    dropHead->setSpacing(12);
    auto* dropIcon = new IconLabel(Icons::Id::File, 20, ColorRole::AccentText);
    dropIcon->setTile(true, 40);
    dropHead->addWidget(dropIcon, 0, Qt::AlignTop);
    auto* dropText = new QVBoxLayout();
    dropText->setSpacing(4);
    dropText->addWidget(makeLabel(TR("Check a file"), "heading"));
    dropText->addWidget(makeLabel(TR("Drag a file anywhere into this window or choose it. The check takes seconds "
                                     "and does not need administrator rights."), "muted"));
    dropHead->addLayout(dropText, 1);
    drop->body()->addLayout(dropHead);
    auto* dropButtons = new QHBoxLayout();
    auto* choose = new Button(TR("Choose files…"), Button::Variant::Secondary);
    choose->setIconId(Icons::Id::File);
    auto* chooseFolder = new Button(TR("Scan a folder…"), Button::Variant::Ghost);
    chooseFolder->setIconId(Icons::Id::Folder);
    dropButtons->addWidget(choose);
    dropButtons->addWidget(chooseFolder);
    dropButtons->addStretch(1);
    drop->body()->addWidget(new DropZone(TR("Drop files here")), 1);
    drop->body()->addLayout(dropButtons);
    connect(choose, &QPushButton::clicked, this, [this, window]() {
        const QStringList files = QFileDialog::getOpenFileNames(this, TR("Choose files to check"));
        if (!files.isEmpty()) window->checkFiles(files);
    });
    connect(chooseFolder, &QPushButton::clicked, this, [this, window]() {
        const QString dir = QFileDialog::getExistingDirectory(this, TR("Choose a folder to scan"));
        if (!dir.isEmpty()) window->startScan(2, { dir });
    });
    lower->addWidget(drop);

    auto* protect = new Card(this, 22);
    protect->body()->setSpacing(14);
    protect->body()->addWidget(makeLabel(TR("Protection"), "heading"));
    auto settingsLink = [window](const QString& text) {
        auto* b = new Button(text, Button::Variant::Link);
        QObject::connect(b, &QPushButton::clicked, b, [window]() { window->navigate(MainWindow::Settings); });
        return b;
    };
    StateRow(protect->body(), Icons::Id::Download, TR("Download monitoring"), &guardState_,
             settingsLink(TR("Change")));
    StateRow(protect->body(), Icons::Id::Calendar, TR("Scheduled scan"), &scheduleState_,
             settingsLink(TR("Change")));
    StateRow(protect->body(), Icons::Id::Database, TR("Signature updates"), &signaturesState_,
             settingsLink(TR("Change")));
    StateRow(protect->body(), Icons::Id::ArrowUp, TR("Program updates"), &updateState_,
             settingsLink(TR("Change")));
    lower->addWidget(protect);
    body()->addWidget(lower);
    body()->addStretch(1);

    connect(&AppState::instance(), &AppState::scanChanged, this, &HomePage::refresh);
    connect(&AppState::instance(), &AppState::itemsReset, this, &HomePage::refresh);
    connect(&AppState::instance(), &AppState::itemAdded, this, &HomePage::refresh);
    connect(&AppState::instance(), &AppState::itemChanged, this, &HomePage::refresh);
    connect(window, &MainWindow::quarantineChanged, this, &HomePage::refresh);
    connect(window, &MainWindow::signaturesChanged, this, &HomePage::refresh);
    connect(&ScanHistory::instance(), &ScanHistory::changed, this, &HomePage::refresh);
    refresh();
}

void HomePage::onShown() { refresh(); }

void HomePage::refresh() {
    MainWindow* w = window();
    const AppState& st = AppState::instance();
    const AppState::Scan& scan = st.scan();
    const int pending = st.pendingCount();
    const auto& records = ScanHistory::instance().records();
    const ScanRecord* last = nullptr;
    // Состояние системы — по проверкам системы: проверка одного файла или
    // песочница не говорят ничего о том, чисто ли всё остальное.
    for (const ScanRecord& r : records) if (r.mode != 3 && r.target.isEmpty()) { last = &r; break; }

    QObject::disconnect(primaryConn_);
    QObject::disconnect(secondaryConn_);
    heroProgress_->setVisible(false);
    secondary_->setVisible(true);

    if (scan.running) {
        heroIcon_->set(Icons::Id::Scan, ColorRole::AccentText);
        heroTitle_->setText(scan.percent >= 0 ? TR("Scan in progress — %1%").arg(scan.percent)
                                              : TR("Scan in progress"));
        heroText_->setText(Texts::stageLabel(scan.stage));
        heroProgress_->setVisible(true);
        heroProgress_->setValue(scan.percent >= 0 ? scan.percent / 100.0 : -1.0);
        primary_->setText(TR("Show progress"));
        primary_->setIconId(std::nullopt);
        secondary_->setText(TR("Stop"));
        primaryConn_ = connect(primary_, &QPushButton::clicked, w, [w]() { w->navigate(MainWindow::Scan); });
        secondaryConn_ = connect(secondary_, &QPushButton::clicked, w, [w]() { w->cancelScan(); });
    } else if (pending > 0) {
        const int crit = st.criticalCount();
        heroIcon_->set(Icons::Id::ShieldAlert, ColorRole::Danger);
        heroTitle_->setText(TR("%1 %2 need your decision").arg(pending)
                                .arg(TRN(pending, "threat", "threats", "угроза", "угрозы", "угроз")));
        heroText_->setText(crit > 0
            ? TR("Critical: %1. Neutralize them now: quarantined files stop working but can be restored.").arg(crit)
            : TR("Review what was found and decide what to do with each item."));
        primary_->setText(TR("Neutralize all"));
        primary_->setIconId(Icons::Id::Quarantine);
        secondary_->setText(TR("Review results"));
        primaryConn_ = connect(primary_, &QPushButton::clicked, w, [w]() { w->neutralizeAll(); });
        secondaryConn_ = connect(secondary_, &QPushButton::clicked, w, [w]() { w->navigate(MainWindow::Results); });
    } else if (scan.finished || last) {
        const bool cancelled = scan.finished ? scan.cancelled : (last && last->cancelled);
        heroIcon_->set(cancelled ? Icons::Id::Shield : Icons::Id::ShieldCheck,
                       cancelled ? ColorRole::Warn : ColorRole::Ok);
        heroTitle_->setText(cancelled ? TR("The last scan was stopped") : TR("No threats found"));
        const QDateTime when = scan.finished ? scan.finishedAt : last->when;
        const int mode = scan.finished ? scan.mode : last->mode;
        heroText_->setText(TR("%1, %2.").arg(Texts::modeLabel(mode), Ago(when)) + " " +
                           (cancelled ? TR("Run it again to check everything.")
                                      : TR("Nothing dangerous was found in the checked areas.")));
        primary_->setText(TR("Quick scan"));
        primary_->setIconId(Icons::Id::Bolt);
        secondary_->setText(TR("Full scan"));
        primaryConn_ = connect(primary_, &QPushButton::clicked, w, [w]() { w->startScan(0); });
        secondaryConn_ = connect(secondary_, &QPushButton::clicked, w, [w]() { w->startScan(1); });
    } else {
        heroIcon_->set(Icons::Id::Shield, ColorRole::Text2);
        heroTitle_->setText(TR("This computer has not been scanned yet"));
        heroText_->setText(TR("Start with a quick scan: it checks the places where malware usually ends up "
                              "and takes a few minutes."));
        primary_->setText(TR("Quick scan"));
        primary_->setIconId(Icons::Id::Bolt);
        secondary_->setText(TR("Full scan"));
        primaryConn_ = connect(primary_, &QPushButton::clicked, w, [w]() { w->startScan(0); });
        secondaryConn_ = connect(secondary_, &QPushButton::clicked, w, [w]() { w->startScan(1); });
    }

    // Показатели.
    if (last) {
        lastScan_->set(Ago(last->when), Texts::modeLabel(last->mode) + " · " +
                       TR("%1 %2").arg(formatCount(last->objects))
                           .arg(TRN(last->objects, "object", "objects", "объект", "объекта", "объектов")));
    } else {
        lastScan_->set(TR("Never"), TR("Run the first scan"));
    }
    pending_->set(QString::number(pending),
                  pending ? TR("Open the results to decide") : TR("Nothing is waiting"),
                  pending ? ColorRole::Danger : ColorRole::Text);
    const int inQuarantine = w->demoMode() ? 2 : static_cast<int>(Quarantine::Instance().List().size());
    quarantine_->set(QString::number(inQuarantine),
                     inQuarantine ? TR("Isolated and harmless") : TR("Quarantine is empty"));

    const uint64_t hashes = HashDatabase::Get().Count();
    const auto rulesFile = SignatureStore::RulesFile("core");
    const uint32_t rulesStamp = rulesFile.empty() ? 0 : SignatureStore::RulesStamp(rulesFile);
    const uint32_t stamp = std::max(HashDatabase::Get().NewestStamp(), rulesStamp);
    databases_->set(StampDate(stamp),
                    TR("%1 known files, signature rules").arg(formatCount(static_cast<qint64>(hashes))),
                    hashes ? ColorRole::Text : ColorRole::Warn);

    const AppSettings& s = AppSettings::Get();
    guardState_->setText(s.downloadGuard() ? TR("On: new files in Downloads and on the desktop are checked at once")
                                           : TR("Off"));
    const QDateTime next = Automation::nextRun();
    scheduleState_->setText(next.isValid()
        ? TR("Next: %1").arg(QLocale(Lang::instance().current() == Lang::Id::Ru ? QLocale::Russian : QLocale::English)
                                 .toString(next, "d MMM, HH:mm"))
        : TR("Off"));
    const QDateTime sigs = s.lastSignatureUpdate();
    signaturesState_->setText(s.autoUpdateSignatures()
        ? (sigs.isValid() ? TR("Automatic, last update %1").arg(Ago(sigs)) : TR("Automatic"))
        : TR("Manual only"));
    updateState_->setText(Updater::instance().hasUpdate()
        ? TR("Version %1 is available").arg(Updater::instance().latest().version)
        : (s.autoInstallUpdates() ? TR("Installed automatically, version %1").arg(Updater::currentVersion())
                                  : TR("You will be offered new versions, version %1").arg(Updater::currentVersion())));
}
