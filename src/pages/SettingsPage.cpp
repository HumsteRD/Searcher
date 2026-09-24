#include "SettingsPage.h"

#include "../app/AppSettings.h"
#include "../app/Automation.h"
#include "../app/Lang.h"
#include "../app/MainWindow.h"
#include "../app/ScannerBridge.h"
#include "../app/SignatureUpdater.h"
#include "../app/Updater.h"
#include "../app/VirusTotalClient.h"
#include "../core/ServiceConfig.h"
#include "../engine/HashDatabase.h"
#include "../engine/SignatureStore.h"
#include "../engine/YaraEngine.h"

#include <QDate>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QListWidget>
#include <QPainter>
#include <QSpinBox>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

using namespace Ui;

// ─── ThemeOption ───

ThemeOption::ThemeOption(Theme::Id id, const QString& title, QWidget* parent)
    : QAbstractButton(parent), id_(id), title_(title)
{
    setCheckable(true);
    setAutoExclusive(true);
    setCursor(Qt::PointingHandCursor);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setFixedHeight(118);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void ThemeOption::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& cur = pal();
    const QRectF r = QRectF(rect()).adjusted(1, 1, -1, -1);

    // Рамка карточки.
    p.setPen(QPen(isChecked() ? cur.accent : (underMouse() ? cur.borderStrong : cur.border),
                  isChecked() ? 2.0 : 1.0));
    p.setBrush(cur.surface);
    p.drawRoundedRect(r, 10, 10);

    // Превью: окно в цветах темы. «Как в системе» — половина светлой,
    // половина тёмной.
    const QRectF pv(r.left() + 10, r.top() + 10, r.width() - 20, 64);
    auto drawPreview = [&](const Palette& t, const QRectF& clip) {
        p.save();
        p.setClipRect(clip);
        p.setPen(QPen(t.border, 1));
        p.setBrush(t.window);
        p.drawRoundedRect(pv, 6, 6);
        p.setPen(Qt::NoPen);
        p.setBrush(t.sidebar);
        p.drawRoundedRect(QRectF(pv.left() + 1, pv.top() + 1, pv.width() * 0.28, pv.height() - 2), 5, 5);
        p.setBrush(t.accent);
        p.drawRoundedRect(QRectF(pv.left() + 6, pv.top() + 10, pv.width() * 0.18, 5), 2.5, 2.5);
        p.setBrush(t.text3);
        p.drawRoundedRect(QRectF(pv.left() + 6, pv.top() + 20, pv.width() * 0.14, 4), 2, 2);
        p.drawRoundedRect(QRectF(pv.left() + 6, pv.top() + 28, pv.width() * 0.16, 4), 2, 2);
        const QRectF card(pv.left() + pv.width() * 0.34, pv.top() + 9, pv.width() * 0.6, pv.height() - 18);
        p.setPen(QPen(t.border, 1));
        p.setBrush(t.surface);
        p.drawRoundedRect(card, 4, 4);
        p.setPen(Qt::NoPen);
        p.setBrush(t.text);
        p.drawRoundedRect(QRectF(card.left() + 6, card.top() + 7, card.width() * 0.5, 5), 2.5, 2.5);
        p.setBrush(t.text3);
        p.drawRoundedRect(QRectF(card.left() + 6, card.top() + 17, card.width() * 0.7, 4), 2, 2);
        p.setBrush(t.accent);
        p.drawRoundedRect(QRectF(card.left() + 6, card.bottom() - 14, card.width() * 0.3, 8), 3, 3);
        p.restore();
    };
    if (id_ == Theme::Id::System) {
        drawPreview(Theme::paletteFor(Theme::Id::Light), QRectF(pv.left(), pv.top(), pv.width() / 2, pv.height()));
        drawPreview(Theme::paletteFor(Theme::Id::Dark),
                    QRectF(pv.center().x(), pv.top(), pv.width() / 2 + 1, pv.height()));
    } else {
        drawPreview(Theme::paletteFor(id_), pv);
    }

    // Подпись и отметка выбора.
    p.setPen(cur.text);
    p.setFont(Font::make(Font::Control, QFont::DemiBold));
    const QRectF label(r.left() + 12, pv.bottom() + 8, r.width() - 40, 22);
    p.drawText(label, Qt::AlignLeft | Qt::AlignVCenter,
               QFontMetrics(p.font()).elidedText(title_, Qt::ElideRight, static_cast<int>(label.width())));
    const QRectF dot(r.right() - 26, label.center().y() - 8, 16, 16);
    p.setPen(QPen(isChecked() ? cur.accent : cur.borderStrong, 1.5));
    p.setBrush(isChecked() ? cur.accent : Qt::transparent);
    p.drawEllipse(dot);
    if (isChecked()) {
        p.drawPixmap(dot.toRect().adjusted(2, 2, -2, -2), Icons::pixmap(Icons::Id::Check, 12, cur.textOnAccent));
    }
}

// ─── SettingsPage ───

SettingsPage::SettingsPage(MainWindow* window)
    : Page(window, TR("Settings"), QString())
{
    body()->addWidget(section(TR("Appearance"), QString(), buildAppearance()));
    body()->addWidget(section(TR("Scanning"), TR("How files are checked and what counts as a finding."), buildScanning()));
    body()->addWidget(section(TR("Protection"), TR("What works in the background while the program is running."),
                              buildProtection()));
    body()->addWidget(section(TR("Updates"), TR("New versions of the program and fresh signature databases."),
                              buildUpdates()));
    body()->addWidget(section(TR("VirusTotal"), TR("Look up found files among the results of 70+ antivirus engines."),
                              buildIntegrations()));
    body()->addWidget(section(TR("Application"), QString(), buildApplication()));
    body()->addWidget(section(TR("About"), QString(), buildAbout()));
    body()->addStretch(1);

    connect(&Updater::instance(), &Updater::checkFinished, this, [this](bool available, bool) {
        if (!updateStatus_) return;
        updateStatus_->setText(available
            ? TR("Version %1 is available.").arg(Updater::instance().latest().version)
            : TR("You have the latest version (%1).").arg(Updater::currentVersion()));
        checkUpdates_->setEnabled(true);
    });
    connect(&Updater::instance(), &Updater::checkFailed, this, [this](const QString& error, bool) {
        if (!updateStatus_) return;
        updateStatus_->setText(TR("Could not check for updates: %1").arg(error));
        checkUpdates_->setEnabled(true);
    });
    connect(&SignatureUpdater::instance(), &SignatureUpdater::finished, this, [this](bool, QString, bool) {
        updateSignatures_->setEnabled(true);
        updateSignatures_->setText(TR("Update now"));
        refreshSignatureInfo();
    });
}

void SettingsPage::onShown() {
    refreshSignatureInfo();
    refreshService();
}

QWidget* SettingsPage::section(const QString& title, const QString& subtitle, QWidget* content) {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 0, 0, 8);
    col->setSpacing(10);
    auto* head = new QVBoxLayout();
    head->setSpacing(2);
    head->addWidget(makeLabel(title, "heading"));
    if (!subtitle.isEmpty()) head->addWidget(makeLabel(subtitle, "muted"));
    col->addLayout(head);
    auto* card = new Card(nullptr, 0);
    card->body()->setContentsMargins(20, 6, 20, 6);
    card->body()->addWidget(content);
    col->addWidget(card);
    return w;
}

QWidget* SettingsPage::buildAppearance() {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 12, 0, 12);
    col->setSpacing(12);
    col->addWidget(makeLabel(TR("Theme"), "subheading"));
    auto* grid = new AdaptiveGrid(130, 4);
    const std::pair<Theme::Id, const char*> options[] = {
        { Theme::Id::System, "As in Windows" }, { Theme::Id::Light, "Light" },
        { Theme::Id::Dark, "Dark" }, { Theme::Id::Graphite, "Graphite" },
    };
    for (const auto& [id, name] : options) {
        auto* opt = new ThemeOption(id, TR(name));
        opt->setChecked(Theme::instance().id() == id);
        connect(opt, &QAbstractButton::clicked, this, [id]() { Theme::instance().setId(id); });
        themes_ << opt;
        grid->addWidget(opt);
    }
    col->addWidget(grid);
    col->addWidget(makeDivider());

    auto* lang = new Segmented({ QStringLiteral("Русский"), QStringLiteral("English") });
    lang->setCurrent(Lang::instance().current() == Lang::Id::Ru ? 0 : 1);
    connect(lang, &Segmented::currentChanged, this, [](int i) {
        // Страницы пересоздаются, в том числе эта: откладываем до выхода
        // из обработчика, иначе удалим виджет, который сейчас работает.
        QTimer::singleShot(0, [i]() { Lang::instance().setLanguage(i == 0 ? Lang::Id::Ru : Lang::Id::En); });
    });
    col->addWidget(new SettingRow(TR("Language"), TR("The interface language. It changes at once."), lang));
    return w;
}

QWidget* SettingsPage::buildScanning() {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(0);
    AppSettings& s = AppSettings::Get();

    auto addToggle = [&](const QString& title, const QString& text, bool value, std::function<void(bool)> set) {
        auto* t = new Toggle();
        t->setCheckedNoAnim(value);
        connect(t, &QAbstractButton::toggled, this, [set](bool on) { set(on); });
        if (col->count() > 0) col->addWidget(makeDivider());
        col->addWidget(new SettingRow(title, text, t));
        return t;
    };
    addToggle(TR("Look inside archives and installers"),
              TR("Unpacks ZIP archives and Python programs packed with PyInstaller and checks what is inside."),
              s.unpackArchives(), [](bool on) { AppSettings::Get().setUnpackArchives(on); });
    addToggle(TR("Extended signature set"),
              TR("About twice as many YARA rules. Finds more, but occasionally flags a legitimate program."),
              s.extendedRules(), [](bool on) { AppSettings::Get().setExtendedRules(on); });
    addToggle(TR("Report hacking tools and unwanted programs"),
              TR("Tools like password recovery utilities are not malware by themselves, but attackers use them."),
              s.reportPua(), [](bool on) { AppSettings::Get().setReportPua(on); });
    addToggle(TR("Quarantine critical threats automatically"),
              TR("Known malware is isolated at once, without waiting for your decision."),
              s.autoQuarantine(), [](bool on) { AppSettings::Get().setAutoQuarantine(on); });

    // Исключения.
    col->addWidget(makeDivider());
    auto* ex = new QWidget();
    auto* exCol = new QVBoxLayout(ex);
    exCol->setContentsMargins(0, 12, 0, 12);
    exCol->setSpacing(8);
    exCol->addWidget(makeLabel(TR("Excluded folders"), "body"));
    exCol->addWidget(makeLabel(TR("These folders are never scanned. Add only folders you trust completely."), "muted"));
    exclusions_ = new QListWidget();
    exclusions_->setMaximumHeight(140);
    exclusions_->setTextElideMode(Qt::ElideMiddle);
    exCol->addWidget(exclusions_);
    auto* exButtons = new QHBoxLayout();
    auto* addEx = new Button(TR("Add folder…"), Button::Variant::Secondary);
    addEx->setSize(Button::Size::Small);
    auto* removeEx = new Button(TR("Remove"), Button::Variant::Ghost);
    removeEx->setSize(Button::Size::Small);
    exButtons->addWidget(addEx);
    exButtons->addWidget(removeEx);
    exButtons->addStretch(1);
    exCol->addLayout(exButtons);
    col->addWidget(ex);
    connect(addEx, &QPushButton::clicked, this, [this]() {
        const QString d = QFileDialog::getExistingDirectory(this, TR("Choose a folder to exclude"));
        if (d.isEmpty()) return;
        QStringList list = AppSettings::Get().excludedPaths();
        list << QDir::toNativeSeparators(d);
        list.removeDuplicates();
        AppSettings::Get().setExcludedPaths(list);
        refreshExclusions();
    });
    connect(removeEx, &QPushButton::clicked, this, [this]() {
        QStringList list = AppSettings::Get().excludedPaths();
        for (auto* item : exclusions_->selectedItems()) list.removeAll(item->text());
        AppSettings::Get().setExcludedPaths(list);
        refreshExclusions();
    });

    // Доверенные файлы.
    col->addWidget(makeDivider());
    auto* tr = new QWidget();
    auto* trCol = new QVBoxLayout(tr);
    trCol->setContentsMargins(0, 12, 0, 12);
    trCol->setSpacing(8);
    trCol->addWidget(makeLabel(TR("Trusted files"), "body"));
    trCol->addWidget(makeLabel(TR("Files you marked as safe. They are identified by contents (SHA-256), so a "
                                  "changed file is checked again."), "muted"));
    trusted_ = new QListWidget();
    trusted_->setMaximumHeight(140);
    trCol->addWidget(trusted_);
    auto* removeTr = new Button(TR("Stop trusting"), Button::Variant::Ghost);
    removeTr->setSize(Button::Size::Small);
    auto* trButtons = new QHBoxLayout();
    trButtons->addWidget(removeTr);
    trButtons->addStretch(1);
    trCol->addLayout(trButtons);
    col->addWidget(tr);
    connect(removeTr, &QPushButton::clicked, this, [this]() {
        for (auto* item : trusted_->selectedItems())
            AppSettings::Get().removeAllowedHash(item->data(Qt::UserRole).toString());
        refreshTrusted();
    });
    refreshExclusions();
    refreshTrusted();
    return w;
}

QWidget* SettingsPage::buildProtection() {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(0);
    MainWindow* win = window();

    auto* guard = new Toggle();
    guard->setCheckedNoAnim(AppSettings::Get().downloadGuard());
    connect(guard, &QAbstractButton::toggled, this, [win](bool on) {
        AppSettings::Get().setDownloadGuard(on);
        win->applySettings();
    });
    col->addWidget(new SettingRow(TR("Download monitoring"),
        TR("New files in Downloads and on the desktop are checked as soon as they finish downloading. "
           "Works while the program is open or in the tray."), guard));

    col->addWidget(makeDivider());
    auto* scheduleBox = new QWidget();
    auto* sb = new QHBoxLayout(scheduleBox);
    sb->setContentsMargins(0, 0, 0, 0);
    sb->setSpacing(8);
    auto* schedule = new Segmented({ TR("Off"), TR("Daily"), TR("Weekly") });
    schedule->setCurrent(static_cast<int>(Automation::schedule()));
    auto* hour = new QSpinBox();
    hour->setRange(0, 23);
    hour->setValue(Automation::scheduleHour());
    hour->setSuffix(":00");
    hour->setFixedWidth(84);
    hour->setEnabled(Automation::schedule() != Automation::Schedule::Off);
    sb->addWidget(schedule);
    sb->addWidget(hour);
    connect(schedule, &Segmented::currentChanged, this, [hour, win](int i) {
        Automation::setSchedule(static_cast<Automation::Schedule>(i));
        hour->setEnabled(i != 0);
        win->refreshBadges();
    });
    connect(hour, qOverload<int>(&QSpinBox::valueChanged), this, [](int h) { Automation::setScheduleHour(h); });
    col->addWidget(new SettingRow(TR("Scheduled quick scan"),
        TR("Runs while the program is open or in the tray. For scans with the window closed, use the background "
           "service below."), scheduleBox));

    col->addWidget(makeDivider());
    auto* serviceBox = new QWidget();
    auto* sv = new QHBoxLayout(serviceBox);
    sv->setContentsMargins(0, 0, 0, 0);
    sv->setSpacing(10);
    serviceStatus_ = makeLabel(QString(), "caption");
    service_ = new Toggle();
    sv->addWidget(serviceStatus_);
    sv->addWidget(service_);
    connect(service_, &QAbstractButton::clicked, this, [this, win](bool on) {
        service_->setEnabled(false);
        serviceStatus_->setText(TR("Applying…"));
        win->bridge()->setServiceEnabled(on, 24, false, [this](bool ok, const QString&, const QString& error) {
            service_->setEnabled(true);
            if (!ok) window()->toast("CRIT", TR("Could not change the background service"), error);
            refreshService();
        });
    });
    col->addWidget(new SettingRow(TR("Background service"),
        TR("A Windows service runs a quick scan once a day even when the program is closed. Results appear "
           "in History. Needs administrator rights to turn on or off."), serviceBox));
    refreshService();
    return w;
}

QWidget* SettingsPage::buildUpdates() {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(0);
    AppSettings& s = AppSettings::Get();

    auto* onStart = new Toggle();
    onStart->setCheckedNoAnim(s.checkUpdatesOnStart());
    connect(onStart, &QAbstractButton::toggled, this, [](bool on) { AppSettings::Get().setCheckUpdatesOnStart(on); });
    col->addWidget(new SettingRow(TR("Check for new versions"),
        TR("When a new version comes out, the program offers to install it."), onStart));

    col->addWidget(makeDivider());
    auto* auto_ = new Toggle();
    auto_->setCheckedNoAnim(s.autoInstallUpdates());
    connect(auto_, &QAbstractButton::toggled, this, [](bool on) { AppSettings::Get().setAutoInstallUpdates(on); });
    col->addWidget(new SettingRow(TR("Install updates automatically"),
        TR("Off by default. When on, a new version is downloaded and installed without asking; the program "
           "restarts by itself. Windows asks for administrator rights for the installer."), auto_));

    col->addWidget(makeDivider());
    auto* row = new QWidget();
    auto* r = new QHBoxLayout(row);
    r->setContentsMargins(0, 12, 0, 12);
    auto* texts = new QVBoxLayout();
    texts->setSpacing(2);
    texts->addWidget(makeLabel(TR("Version %1").arg(Updater::currentVersion()), "body"));
    updateStatus_ = makeLabel(Updater::instance().hasUpdate()
                                  ? TR("Version %1 is available.").arg(Updater::instance().latest().version)
                                  : TR("Press the button to check now."), "muted");
    texts->addWidget(updateStatus_);
    r->addLayout(texts, 1);
    checkUpdates_ = new Button(TR("Check now"), Button::Variant::Secondary);
    checkUpdates_->setIconId(Icons::Id::Refresh);
    r->addWidget(checkUpdates_, 0, Qt::AlignVCenter);
    col->addWidget(row);
    connect(checkUpdates_, &QPushButton::clicked, this, [this]() {
        checkUpdates_->setEnabled(false);
        updateStatus_->setText(TR("Checking…"));
        Updater::instance().check(true);
    });

    col->addWidget(makeDivider());
    auto* sigAuto = new Toggle();
    sigAuto->setCheckedNoAnim(s.autoUpdateSignatures());
    connect(sigAuto, &QAbstractButton::toggled, this, [](bool on) { AppSettings::Get().setAutoUpdateSignatures(on); });
    col->addWidget(new SettingRow(TR("Update signature databases automatically"),
        TR("Once a day: fresh samples from MalwareBazaar and new YARA-Forge rules."), sigAuto));

    col->addWidget(makeDivider());
    auto* sigRow = new QWidget();
    auto* sr = new QHBoxLayout(sigRow);
    sr->setContentsMargins(0, 12, 0, 12);
    signatureInfo_ = makeLabel(QString(), "muted");
    sr->addWidget(signatureInfo_, 1);
    updateSignatures_ = new Button(TR("Update now"), Button::Variant::Secondary);
    updateSignatures_->setIconId(Icons::Id::Download);
    sr->addWidget(updateSignatures_, 0, Qt::AlignVCenter);
    col->addWidget(sigRow);
    connect(updateSignatures_, &QPushButton::clicked, this, [this]() {
        updateSignatures_->setEnabled(false);
        updateSignatures_->setText(TR("Updating…"));
        SignatureUpdater::instance().updateAll(true);
    });
    refreshSignatureInfo();
    return w;
}

QWidget* SettingsPage::buildIntegrations() {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 12, 0, 12);
    col->setSpacing(8);
    col->addWidget(makeLabel(TR("API key"), "body"));
    col->addWidget(makeLabel(TR("Free key: sign up at virustotal.com, then open your profile and copy the API key. "
                                "The free key allows 4 lookups per minute. Only file hashes are sent, "
                                "never the files themselves."), "muted"));
    auto* row = new QHBoxLayout();
    vtKey_ = new QLineEdit(AppSettings::Get().virusTotalKey());
    vtKey_->setEchoMode(QLineEdit::Password);
    vtKey_->setPlaceholderText(TR("Paste the key here"));
    auto* save = new Button(TR("Save"), Button::Variant::Secondary);
    auto* test = new Button(TR("Check key"), Button::Variant::Ghost);
    row->addWidget(vtKey_, 1);
    row->addWidget(save);
    row->addWidget(test);
    col->addLayout(row);
    vtStatus_ = makeLabel(QString(), "caption");
    col->addWidget(vtStatus_);
    connect(save, &QPushButton::clicked, this, [this]() {
        AppSettings::Get().setVirusTotalKey(vtKey_->text());
        vtStatus_->setText(vtKey_->text().trimmed().isEmpty() ? TR("The key was removed.") : TR("Saved."));
    });
    connect(test, &QPushButton::clicked, this, [this]() {
        AppSettings::Get().setVirusTotalKey(vtKey_->text());
        vtStatus_->setText(TR("Checking…"));
        VirusTotalClient::instance().testApiKey();
    });
    connect(&VirusTotalClient::instance(), &VirusTotalClient::apiKeyTested, this, [this](bool ok, QString msg) {
        if (!vtStatus_) return;
        vtStatus_->setText(ok ? TR("The key works.") : TR("The key does not work: %1").arg(msg));
        setStyleProp(vtStatus_, "tone", ok ? "ok" : "danger");
    });
    return w;
}

QWidget* SettingsPage::buildApplication() {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(0);
    MainWindow* win = window();

    auto* autostart = new Toggle();
    autostart->setCheckedNoAnim(Automation::autostartEnabled());
    connect(autostart, &QAbstractButton::toggled, this, [](bool on) { Automation::setAutostartEnabled(on); });
    col->addWidget(new SettingRow(TR("Start with Windows"),
        TR("The program starts minimized to the tray, so download monitoring and the schedule keep working."),
        autostart));

    col->addWidget(makeDivider());
    auto* tray = new Toggle();
    tray->setCheckedNoAnim(Automation::trayEnabled());
    connect(tray, &QAbstractButton::toggled, this, [win](bool on) {
        Automation::setTrayEnabled(on);
        win->applySettings();
    });
    col->addWidget(new SettingRow(TR("Keep running in the tray when closed"),
        TR("Closing the window hides it next to the clock. Exit from the tray icon menu."), tray));

    col->addWidget(makeDivider());
    auto* folders = new QWidget();
    auto* fr = new QHBoxLayout(folders);
    fr->setContentsMargins(0, 12, 0, 12);
    fr->setSpacing(8);
    auto* data = new Button(TR("Open data folder"), Button::Variant::Secondary);
    data->setIconId(Icons::Id::Folder);
    auto* sigs = new Button(TR("Open signatures folder"), Button::Variant::Secondary);
    sigs->setIconId(Icons::Id::Database);
    fr->addWidget(data);
    fr->addWidget(sigs);
    fr->addStretch(1);
    col->addWidget(folders);
    connect(data, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)));
    });
    connect(sigs, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(QString::fromStdWString(SignatureStore::UpdateDir().wstring())));
    });
    return w;
}

QWidget* SettingsPage::buildAbout() {
    auto* w = new QWidget();
    auto* col = new QVBoxLayout(w);
    col->setContentsMargins(0, 14, 0, 14);
    col->setSpacing(8);
    auto* head = new QHBoxLayout();
    head->setSpacing(12);
    auto* logo = new QLabel();
    logo->setPixmap(Icons::logo(40));
    logo->setFixedSize(40, 40);
    head->addWidget(logo);
    auto* names = new QVBoxLayout();
    names->setSpacing(0);
    names->addWidget(makeLabel("Threat Scanner", "subheading"));
    names->addWidget(makeLabel(TR("Version %1").arg(Updater::currentVersion()), "caption"));
    head->addLayout(names, 1);
    auto* site = new Button(TR("Project on GitHub"), Button::Variant::Secondary);
    site->setIconId(Icons::Id::External);
    connect(site, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl("https://github.com/HumsteRD/Searcher"));
    });
    head->addWidget(site, 0, Qt::AlignVCenter);
    col->addLayout(head);
    col->addWidget(makeLabel(TR("Signature data: MalwareBazaar by abuse.ch (CC0) and YARA-Forge, a curated "
                                "collection of public YARA rules; each rule keeps its authors and license. "
                                "Scanning engine: YARA by VirusTotal (BSD-3). Interface: Qt 6 (LGPL)."), "caption"));
    return w;
}

void SettingsPage::refreshExclusions() {
    if (!exclusions_) return;
    exclusions_->clear();
    for (const QString& p : AppSettings::Get().excludedPaths()) exclusions_->addItem(p);
    if (exclusions_->count() == 0) {
        auto* item = new QListWidgetItem(TR("No exclusions"));
        item->setFlags(Qt::NoItemFlags);
        exclusions_->addItem(item);
    }
}

void SettingsPage::refreshTrusted() {
    if (!trusted_) return;
    trusted_->clear();
    for (const QString& sha : AppSettings::Get().allowedHashes()) {
        const QString label = AppSettings::Get().allowedLabel(sha);
        auto* item = new QListWidgetItem((label.isEmpty() ? QString() : label + "  ·  ") + sha.left(16) + "…");
        item->setData(Qt::UserRole, sha);
        item->setToolTip(sha);
        trusted_->addItem(item);
    }
    if (trusted_->count() == 0) {
        auto* item = new QListWidgetItem(TR("No trusted files"));
        item->setFlags(Qt::NoItemFlags);
        trusted_->addItem(item);
    }
}

void SettingsPage::refreshSignatureInfo() {
    if (!signatureInfo_) return;
    const uint64_t hashes = HashDatabase::Get().Count();
    const auto rules = SignatureStore::RulesFile(AppSettings::Get().extendedRules() ? "extended" : "core");
    const uint32_t stamp = rules.empty() ? 0 : SignatureStore::RulesStamp(rules);
    const QDateTime last = AppSettings::Get().lastSignatureUpdate();
    QString text = TR("%1 known malicious files; rules from %2.")
                       .arg(formatCount(static_cast<qint64>(hashes)))
                       .arg(stamp ? QDate::fromString(QString::number(stamp), "yyyyMMdd").toString("dd.MM.yyyy")
                                  : TR("unknown date"));
    if (last.isValid()) text += " " + TR("Last checked %1.").arg(last.toString("dd.MM.yyyy HH:mm"));
    signatureInfo_->setText(text);
}

void SettingsPage::refreshService() {
    if (!service_) return;
    const ServiceConfig::State state = ServiceConfig::QueryState();
    const bool installed = state == ServiceConfig::State::Running || state == ServiceConfig::State::Stopped;
    service_->setCheckedNoAnim(installed && ServiceConfig::Read().enabled);
    serviceStatus_->setText(state == ServiceConfig::State::Running ? TR("Running")
                          : state == ServiceConfig::State::Stopped ? TR("Stopped")
                          : TR("Not installed"));
}
