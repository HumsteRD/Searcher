#include "SettingsPage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/AppSettings.h"
#include "../core/VirusTotalClient.h"
#include "../core/Lang.h"
#include "../core/Automation.h"
#include "../core/SignatureDB.h"
#include <QDesktopServices>
#include <QUrl>
#include <QFileInfo>
#include <QFile>
#include <QComboBox>
#include "../core/ScannerBridge.h"
#include "../core/ServiceConfig.h"
#include <QScrollArea>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include "../ui/ToggleSwitch.h"
#include <QFrame>
#include <QPushButton>
#include "../ui/GradientButton.h"

static QFrame* settingsCard(QWidget* parent,
                            const QString& title,
                            const QString& subtitle,
                            QWidget* control)
{
    QFrame* card = PageHelpers::card(parent, Theme::Radius::CARD);
    QVBoxLayout* lay = new QVBoxLayout(card);
    lay->setContentsMargins(24, 22, 24, 22);
    lay->setSpacing(8);

    QLabel* t = new QLabel(title, card);
    t->setStyleSheet(QString(
        "color: %1; font-size: 14px; font-weight: 700;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY));
    lay->addWidget(t);

    if (!subtitle.isEmpty()) {
        QLabel* s = new QLabel(subtitle, card);
        s->setStyleSheet(QString(
            "color: %1; font-size: 12.5px;"
            "background: transparent; border: none;"
        ).arg(Theme::TEXT_SECONDARY));
        s->setWordWrap(true);
        lay->addWidget(s);
    }

    lay->addSpacing(10);
    lay->addWidget(control);
    card->setMinimumHeight(card->sizeHint().height());

    return card;
}

SettingsPage::SettingsPage(QWidget* parent) : QWidget(parent) {
    setStyleSheet("background: transparent;");

    // Содержимое не помещается в окно целиком, поэтому кладём его
    // в прокрутку: иначе layout сжимает карточки и они наезжают.
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                              Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    outer->setSpacing(0);

    QScrollArea* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background: transparent;");
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    QWidget* content = new QWidget(scroll);
    content->setStyleSheet("background: transparent;");
    scroll->setWidget(content);
    outer->addWidget(scroll, 1);

    QVBoxLayout* root = new QVBoxLayout(content);
    root->setContentsMargins(0, 0, Theme::Space::S, 0);
    root->setSpacing(16);

    root->addWidget(PageHelpers::pageTitle(TR("Settings"), this));
    root->addWidget(PageHelpers::pageSubtitle(
        TR("Configure scan behavior and external integrations."), this));

    root->addSpacing(12);

    // ─── Язык ───
    root->addWidget(PageHelpers::sectionTitle(TR("INTERFACE"), content));

    langBox_ = new QComboBox(this);
    langBox_->addItem("English");
    langBox_->addItem("Русский");
    langBox_->setCurrentIndex(Lang::instance().current() == Lang::Id::Ru ? 1 : 0);
    langBox_->setMinimumHeight(Theme::Size::BTN_INPUT);
    langBox_->setCursor(Qt::PointingHandCursor);
    langBox_->setStyleSheet(QString(
        "QComboBox {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: %4px;"
        "  padding: 0 12px; font-size: %5px;"
        "}"
        "QComboBox:hover { border-color: %6; }"
        "QComboBox::drop-down { border: none; width: 24px; }"
        "QComboBox QAbstractItemView {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3;"
        "  selection-background-color: %7;"
        "  outline: none;"
        "}"
    ).arg(Theme::SUNKEN, Theme::TEXT_PRIMARY, Theme::BORDER_CONTROL)
     .arg(Theme::Radius::CONTROL)
     .arg(Theme::Font::BODY)
     .arg(Theme::BORDER_CONTROL_HOVER, Theme::ROW_SELECTED));

    connect(langBox_, &QComboBox::currentIndexChanged, this, [](int i) {
        Lang::instance().setLanguage(i == 1 ? Lang::Id::Ru : Lang::Id::En);
    });

    root->addWidget(settingsCard(content, TR("Language"),
        TR("Interface language. Applies immediately."), langBox_));

    root->addSpacing(8);
    root->addWidget(PageHelpers::sectionTitle(TR("INTEGRATIONS"), content));

    // VirusTotal API key
    vtKey_ = new QLineEdit(this);
    vtKey_->setEchoMode(QLineEdit::Password);
    vtKey_->setPlaceholderText(TR("Paste your VirusTotal API key here"));
    vtKey_->setMinimumHeight(40);
    vtKey_->setStyleSheet(QString(
        "QLineEdit {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 8px;"
        "  padding: 6px 14px;"
        "  font-size: 13px;"
        "}"
        "QLineEdit:focus {"
        "  border-color: %4;"
        "}"
    ).arg(Theme::SUNKEN, Theme::TEXT_PRIMARY, Theme::BORDER_CONTROL, Theme::ACCENT));

    // Ключ + кнопка проверки + строка статуса в одной "обёртке"
    QWidget* vtBlock = new QWidget(this);
    vtBlock->setStyleSheet("background: transparent;");
    QVBoxLayout* vtLay = new QVBoxLayout(vtBlock);
    vtLay->setContentsMargins(0, 0, 0, 0);
    vtLay->setSpacing(10);

    QWidget* vtRow = new QWidget(vtBlock);
    vtRow->setStyleSheet("background: transparent;");
    QHBoxLayout* vtRowLay = new QHBoxLayout(vtRow);
    vtRowLay->setContentsMargins(0, 0, 0, 0);
    vtRowLay->setSpacing(10);
    vtRowLay->addWidget(vtKey_, 1);

    auto* testBtn = new GradientButton(TR("Test key"),
        GradientButton::Style::Outline, vtRow);
    testBtn->setFixedHeight(Theme::Size::BTN_INPUT);
    testBtn->setMinimumWidth(120);
    testBtn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    vtTestBtn_ = testBtn;
    vtRowLay->addWidget(vtTestBtn_);
    vtLay->addWidget(vtRow);

    vtStatus_ = new QLabel(QString(), vtBlock);
    vtStatus_->setStyleSheet(QString(
        "color: %1; font-size: 12px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY));
    vtStatus_->setWordWrap(true);
    vtLay->addWidget(vtStatus_);

    root->addWidget(settingsCard(content,
        TR("VirusTotal API key"),
        "Optional. Adds cloud-based threat verification. Get a free key at virustotal.com. "
        "Free keys allow 4 lookups per minute, so checks are queued.",
        vtBlock));

    root->addSpacing(8);
    root->addWidget(PageHelpers::sectionTitle(TR("SCAN BEHAVIOR"), content));

    auto toggleRow = [this](const QString& text) {
        // Тумблер + подпись в одной строке: сам ToggleSwitch текста не несёт.
        QWidget* row = new QWidget(this);
        row->setStyleSheet("background: transparent;");
        QHBoxLayout* rowLay = new QHBoxLayout(row);
        rowLay->setContentsMargins(0, 0, 0, 0);
        rowLay->setSpacing(12);

        ToggleSwitch* sw = new ToggleSwitch(row);
        rowLay->addWidget(sw);

        QLabel* lbl = new QLabel(text, row);
        lbl->setStyleSheet(QString(
            "color: %1; font-size: %2px;"
            "background: transparent; border: none;"
        ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::CONTROL));
        rowLay->addWidget(lbl);
        rowLay->addStretch();

        toggleRows_.insert(sw, row);
        return sw;
    };

    deepScan_ = toggleRow(TR("Enable deep file scanning (slower, more thorough)"));
    root->addWidget(settingsCard(content,
        TR("Deep scan"),
        "Computes SHA-256 hashes of all files in hot directories. "
        "Slower but more reliable for catching known malware.",
        toggleRows_.value(deepScan_)));

    autoQuar_ = toggleRow(TR("Automatically quarantine critical threats"));
    root->addWidget(settingsCard(content,
        TR("Auto-quarantine"),
        "When enabled, threats marked as Critical will be moved to quarantine without asking.",
        toggleRows_.value(autoQuar_)));


    // ─── Автоматизация ───
    root->addSpacing(8);
    root->addWidget(PageHelpers::sectionTitle(TR("AUTOMATION"), content));

    autostart_ = toggleRow(TR("Start with Windows"));
    autostart_->setChecked(Automation::autostartEnabled());
    connect(autostart_, &ToggleSwitch::toggled, this, [](bool on) {
        Automation::setAutostartEnabled(on);
    });
    root->addWidget(settingsCard(content, TR("Autostart"),
        TR("Launch Threat Scanner when you sign in to Windows."),
        toggleRows_.value(autostart_)));

    trayToggle_ = toggleRow(TR("Keep running in the tray"));
    trayToggle_->setChecked(Automation::trayEnabled());
    connect(trayToggle_, &ToggleSwitch::toggled, this, [](bool on) {
        Automation::setTrayEnabled(on);
        // Применяем немедленно: иначе значок появлялся только после перезапуска.
        if (auto* a = Automation::instance()) a->applyTraySetting();
    });
    root->addWidget(settingsCard(content, TR("Tray icon"),
        TR("Closing the window hides it to the tray instead of quitting, "
           "so scheduled scans keep working."),
        toggleRows_.value(trayToggle_)));

    QWidget* schedRow = new QWidget(content);
    schedRow->setStyleSheet("background: transparent;");
    QHBoxLayout* schedLay = new QHBoxLayout(schedRow);
    schedLay->setContentsMargins(0, 0, 0, 0);
    schedLay->setSpacing(10);

    scheduleBox_ = new QComboBox(schedRow);
    scheduleBox_->addItem(TR("Off"));
    scheduleBox_->addItem(TR("Every day"));
    scheduleBox_->addItem(TR("Every week"));
    scheduleBox_->setCurrentIndex(static_cast<int>(Automation::schedule()));
    scheduleBox_->setMinimumHeight(Theme::Size::BTN_INPUT);
    scheduleBox_->setStyleSheet(langBox_->styleSheet());
    schedLay->addWidget(scheduleBox_, 1);

    hourBox_ = new QComboBox(schedRow);
    for (int h = 0; h < 24; ++h) {
        hourBox_->addItem(QString("%1:00").arg(h, 2, 10, QChar('0')));
    }
    hourBox_->setCurrentIndex(Automation::scheduleHour());
    hourBox_->setMinimumHeight(Theme::Size::BTN_INPUT);
    hourBox_->setStyleSheet(langBox_->styleSheet());
    schedLay->addWidget(hourBox_);

    connect(scheduleBox_, &QComboBox::currentIndexChanged, this, [](int i) {
        Automation::setSchedule(static_cast<Automation::Schedule>(i));
    });
    connect(hourBox_, &QComboBox::currentIndexChanged, this, [](int h) {
        Automation::setScheduleHour(h);
    });

    root->addWidget(settingsCard(content, TR("Scheduled scan"),
        TR("Runs a scan automatically at the chosen hour. The app must be "
           "running — enable autostart and the tray icon for it to be reliable."),
        schedRow));

    // ─── Фоновая служба ───
    // Расписание выше работает, только пока открыто окно. Служба — это
    // единственный способ проверять систему при закрытом приложении,
    // и стоит она отдельным пунктом, чтобы разница была видна.
    QWidget* serviceBlock = new QWidget(content);
    serviceBlock->setStyleSheet("background: transparent;");
    QVBoxLayout* serviceLay = new QVBoxLayout(serviceBlock);
    serviceLay->setContentsMargins(0, 0, 0, 0);
    serviceLay->setSpacing(10);

    serviceToggle_ = toggleRow(TR("Scan even when the app is closed"));
    serviceToggle_->setEnabled(false);   // пока не узнали состояние
    serviceLay->addWidget(toggleRows_.value(serviceToggle_));

    serviceStatus_ = new QLabel(TR("Checking the background service..."),
                                serviceBlock);
    serviceStatus_->setWordWrap(true);
    serviceStatus_->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_MUTED).arg(Theme::Font::OVERLINE));
    serviceLay->addWidget(serviceStatus_);

    connect(serviceToggle_, &ToggleSwitch::toggled,
            this, &SettingsPage::onServiceToggled);

    root->addWidget(settingsCard(content, TR("Background service"),
        TR("Installs a Windows service that runs a scan once a day even when "
           "Threat Scanner is closed. Installing and removing it asks for "
           "administrator rights."),
        serviceBlock));

    // ─── База сигнатур ───
    root->addSpacing(8);
    root->addWidget(PageHelpers::sectionTitle(TR("SIGNATURES"), content));

    QWidget* sigBlock = new QWidget(content);
    sigBlock->setStyleSheet("background: transparent;");
    QVBoxLayout* sigLay = new QVBoxLayout(sigBlock);
    sigLay->setContentsMargins(0, 0, 0, 0);
    sigLay->setSpacing(10);

    sigStatus_ = new QLabel(sigBlock);
    sigStatus_->setWordWrap(true);
    sigStatus_->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::CONTROL));
    sigLay->addWidget(sigStatus_);

    QWidget* sigRow = new QWidget(sigBlock);
    sigRow->setStyleSheet("background: transparent;");
    QHBoxLayout* sigRowLay = new QHBoxLayout(sigRow);
    sigRowLay->setContentsMargins(0, 0, 0, 0);
    sigRowLay->setSpacing(10);

    auto* reloadBtn = new GradientButton(TR("Reload"),
        GradientButton::Style::Outline, sigRow);
    reloadBtn->setFixedHeight(Theme::Size::BTN_INPUT);
    reloadBtn->setMinimumWidth(120);
    reloadBtn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    connect(reloadBtn, &QPushButton::clicked, this, [this]() {
        SignatureDB::Get().Reload();
        updateSignatureStatus();
    });
    sigRowLay->addWidget(reloadBtn);

    auto* openSigBtn = new GradientButton(TR("Open file"),
        GradientButton::Style::Outline, sigRow);
    openSigBtn->setFixedHeight(Theme::Size::BTN_INPUT);
    openSigBtn->setMinimumWidth(140);
    openSigBtn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    connect(openSigBtn, &QPushButton::clicked, this, [this]() {
        const QString path =
            QString::fromStdWString(SignatureDB::ExternalPath());
        if (!QFileInfo::exists(path)) {
            // Файла ещё нет — создаём заготовку, иначе открывать нечего.
            QFile f(path);
            if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
                // Заготовка, чтобы файл сразу открывался и было видно формат.
                f.write(R"({
  "hashes": [],
  "fileNamePatterns": [],
  "miningPools": []
}
)");
            }
        }
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    sigRowLay->addWidget(openSigBtn);
    sigRowLay->addStretch();
    sigLay->addWidget(sigRow);

    root->addWidget(settingsCard(content, TR("Signature database"),
        TR("Built-in signatures always apply. You can add your own in a JSON "
           "file with hashes, file-name patterns and mining pools — your "
           "entries are added on top, never replacing the built-in ones."),
        sigBlock));

    updateSignatureStatus();

    root->addStretch();

    // === Персист ===
    loadSettings();

    connect(vtKey_, &QLineEdit::textChanged, this, [this](const QString& text) {
        AppSettings::Get().SetVirusTotalKey(text.trimmed().toStdString());
        vtStatus_->clear();
    });
    connect(deepScan_, &ToggleSwitch::toggled, this, [](bool on) {
        AppSettings::Get().SetDeepScan(on);
    });
    connect(autoQuar_, &ToggleSwitch::toggled, this, [](bool on) {
        AppSettings::Get().SetAutoQuarantine(on);
    });

    connect(vtTestBtn_, &QPushButton::clicked, this, [this]() {
        vtTestBtn_->setEnabled(false);
        vtStatus_->setStyleSheet(QString(
            "color: %1; font-size: 12px;"
            "background: transparent; border: none;"
        ).arg(Theme::TEXT_SECONDARY));
        vtStatus_->setText("Checking…");
        VirusTotalClient::instance().testApiKey();
    });

    connect(&VirusTotalClient::instance(), &VirusTotalClient::apiKeyTested,
            this, [this](bool ok, QString message) {
        vtTestBtn_->setEnabled(true);
        vtStatus_->setStyleSheet(QString(
            "color: %1; font-size: 12px;"
            "background: transparent; border: none;"
        ).arg(ok ? Theme::OK : Theme::SEV_CRIT));
        vtStatus_->setText(message);
    });
}

void SettingsPage::setBridge(ScannerBridge* bridge) {
    bridge_ = bridge;
    refreshServiceStatus();
}

void SettingsPage::refreshServiceStatus() {
    if (!serviceToggle_) return;

    // Спрашиваем диспетчер служб напрямую. Через помощника это стоило бы
    // запроса UAC на каждом открытии настроек — при том, что состояние
    // службы Windows разрешает читать кому угодно.
    const ServiceConfig::State state = ServiceConfig::QueryState();
    const bool installed = (state == ServiceConfig::State::Running ||
                            state == ServiceConfig::State::Stopped);

    serviceBusy_ = true;   // ставим галку молча, без обработчика
    serviceToggle_->setChecked(installed);
    serviceBusy_ = false;

    serviceToggle_->setEnabled(state != ServiceConfig::State::Unknown);

    switch (state) {
    case ServiceConfig::State::Running:
        serviceStatus_->setText(TR("Installed and running."));
        break;
    case ServiceConfig::State::Stopped:
        serviceStatus_->setText(TR("Installed, but not running."));
        break;
    case ServiceConfig::State::NotInstalled:
        serviceStatus_->setText(TR("Not installed."));
        break;
    default:
        serviceStatus_->setText(TR("The background service is unavailable."));
        break;
    }
}

void SettingsPage::onServiceToggled(bool on) {
    if (serviceBusy_ || !bridge_) return;

    serviceBusy_ = true;
    serviceToggle_->setEnabled(false);
    serviceStatus_->setText(on ? TR("Installing the service...")
                               : TR("Removing the service..."));

    bridge_->setServiceEnabled(on, 24, [this, on](bool ok, const QString&,
                                                  const QString& error) {
        serviceBusy_ = false;
        serviceToggle_->setEnabled(true);

        if (!ok) {
            // Не получилось — возвращаем переключатель назад, иначе он
            // показывает состояние, которого нет.
            serviceBusy_ = true;
            serviceToggle_->setChecked(!on);
            serviceBusy_ = false;
            serviceStatus_->setText(error.isEmpty()
                ? TR("The background service is unavailable.") : error);
            return;
        }

        // Состояние перечитываем у диспетчера служб: «команда прошла»
        // и «служба стоит» — разные утверждения.
        refreshServiceStatus();
    });
}

void SettingsPage::updateSignatureStatus() {
    const auto& db = SignatureDB::Get();
    const QString path = QString::fromStdWString(SignatureDB::ExternalPath());

    if (!QFileInfo::exists(path)) {
        sigStatus_->setText(TR("No custom signature file yet — only built-in "
                               "signatures are in use."));
        return;
    }
    sigStatus_->setText(
        TR("Loaded from your file: %1 hashes, %2 name patterns, %3 pools.")
            .arg(db.ExternalHashCount())
            .arg(db.ExternalPatternCount())
            .arg(db.ExternalPoolCount()));
}

void SettingsPage::loadSettings() {
    const auto& s = AppSettings::Get();

    // Значения проставляем до connect(), чтобы не перезаписать их же обратно.
    vtKey_->setText(QString::fromStdString(s.VirusTotalKey()));
    deepScan_->setChecked(s.DeepScan());
    autoQuar_->setChecked(s.AutoQuarantine());
}
