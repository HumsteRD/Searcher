#include "SandboxPage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"
#include "../core/SandboxEnvironment.h"
#include "../core/BehaviorVerdict.h"
#include "../core/BehaviorReportJson.h"
#include "../core/ScanHistory.h"
#include "../core/Logger.h"
#include "../core/ScannerBridge.h"
#include "../ui/GradientButton.h"
#include "../ui/ToggleSwitch.h"
#include "../ui/Icons.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFrame>
#include <QComboBox>
#include <QTableWidget>
#include <QTreeWidget>
#include <QHeaderView>
#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QSet>
#include <QHash>
#include <QStringList>
#include <QDateTime>

namespace {

// Поле пути: не редактируется, но выглядит как поле ввода — иначе путь
// читается как обычная подпись и его начинают искать глазами не там.
// Моноширинный шрифт включается только под настоящий путь: заглушка
// «файл не выбран», набранная им, читается как дефект вёрстки.
QString fieldQss(bool hasPath) {
    return QString(
        "QLabel {"
        "  background-color: %1; color: %2;"
        "  border: 1px solid %3; border-radius: %4px;"
        "  padding: 0 12px; font-family: \"%5\"; font-size: %6px;"
        "}"
    ).arg(Theme::SUNKEN,
          hasPath ? Theme::TEXT_MONO : Theme::TEXT_DISABLED,
          Theme::BORDER_DISABLED)
     .arg(Theme::Radius::CONTROL)
     .arg(hasPath ? Theme::FONT_MONO : Theme::FONT_UI)
     .arg(Theme::Font::BODY);
}

QString plainLabelQss(const QString& color, int size, int weight = 400) {
    return QString(
        "color: %1; font-size: %2px; font-weight: %3;"
        "background: transparent; border: none;"
    ).arg(color).arg(size).arg(weight);
}

// Цвет типа события. Смысл несут не оттенки сами по себе, а группы:
// процессы, файлы, реестр, сеть и заметки наблюдателя.
const char* eventColor(BehaviorEventType type) {
    switch (type) {
    case BehaviorEventType::ProcessStarted:
    case BehaviorEventType::ProcessExited:
        return Theme::ACCENT_TEXT;

    case BehaviorEventType::RegistryValueSet:
    case BehaviorEventType::RegistryValueChanged:
    case BehaviorEventType::RegistryValueDeleted:
    case BehaviorEventType::RegistryKeyCreated:
    case BehaviorEventType::RegistryKeyDeleted:
        return Theme::SEV_MED;

    case BehaviorEventType::NetworkConnection:
    case BehaviorEventType::NetworkListen:
        return Theme::SEV_HIGH;

    case BehaviorEventType::MonitorNote:
        return Theme::TEXT_MUTED;

    default:
        return Theme::TEXT_PRIMARY;   // файловые события
    }
}

QString formatMs(int ms) {
    return QString::number(ms / 1000.0, 'f', 2) + " " + TR("s");
}

// Те же коды, что и в остальном приложении: пилюля показывает слово,
// а не только цвет.
QString severityCode(Severity severity) {
    switch (severity) {
    case Severity::Critical: return "CRIT";
    case Severity::High:     return "HIGH";
    case Severity::Medium:   return "MED";
    case Severity::Low:      return "LOW";
    default:                 return "INFO";
    }
}

QString eventName(BehaviorEventType type) {
    return TR(QString::fromWCharArray(BehaviorEventTypeName(type)));
}

// Папка сохранённых отчётов. Пишет туда помощник — он же удаляет
// рабочую папку сеанса, — а страница только предлагает её в диалоге
// открытия, чтобы не заставлять искать путь вручную.
QString reportsFolder() {
    const QString base =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (base.isEmpty()) return {};
    return base + "/sandbox/reports";
}

// Подробности события ядро тоже отдаёт по-английски. Пути и командные
// строки не трогаем — их незачем переводить, а вот приписки вроде
// «exit code» и состояния соединения в русской таблице выглядят чужими.
QString translateDetail(BehaviorEventType type, const std::wstring& source) {
    const QString text = QString::fromStdWString(source);
    if (text.isEmpty()) return text;

    switch (type) {
    case BehaviorEventType::ProcessExited: {
        const QString prefix = "exit code ";
        if (text.startsWith(prefix))
            return TR("exit code") + " " + text.mid(prefix.size());
        break;
    }
    case BehaviorEventType::FileRenamed: {
        const QString prefix = "from ";
        if (text.startsWith(prefix))
            return TR("renamed from") + " " + text.mid(prefix.size());
        return TR(text);
    }
    case BehaviorEventType::NetworkConnection:
    case BehaviorEventType::NetworkListen: {
        // «TCP, established» — протокол оставляем, состояние переводим.
        QStringList parts = text.split(", ");
        for (QString& part : parts) part = TR(part);
        return parts.join(", ");
    }
    case BehaviorEventType::MonitorNote:
        return TR(text);
    default:
        break;
    }
    return text;
}

// Ограничения приходят из ядра готовыми английскими фразами. Две из них
// заканчиваются подставленным списком каталогов — целиком в словарь их
// не положишь, поэтому переводим постоянную часть, а хвост оставляем
// как есть: путь всё равно не переводится.
QString translateLimitation(const std::wstring& source) {
    const QString text = QString::fromStdWString(source);

    static const char* kPrefixes[] = {
        "Only these directories were watched: ",
        "Directory could not be watched: ",
    };
    for (const char* prefix : kPrefixes) {
        const QString head = QString::fromLatin1(prefix);
        if (text.startsWith(head))
            return TR(head.trimmed()) + " " + text.mid(head.size());
    }
    return TR(text);
}

} // namespace

SandboxPage::SandboxPage(QWidget* parent) : QWidget(parent) {
    QVBoxLayout* root = PageHelpers::scrollablePageLayout(this);

    QWidget* titleRow = new QWidget(this);
    titleRow->setStyleSheet("background: transparent;");
    QHBoxLayout* titleLay = new QHBoxLayout(titleRow);
    titleLay->setContentsMargins(0, 0, 0, 0);
    titleLay->setSpacing(Theme::Space::S);
    titleLay->addWidget(PageHelpers::pageTitle(TR("Behavior analysis"), this));
    titleLay->addStretch();

    // Чтение сохранённого отчёта не требует песочницы, поэтому кнопка
    // работает и там, где сеанс запустить нельзя.
    auto* openButton = new GradientButton(TR("Open a report"),
                                          GradientButton::Style::Outline, titleRow);
    openButton->setFixedHeight(Theme::Size::BTN_HEADER);
    openButton->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    connect(openButton, &QPushButton::clicked, this, &SandboxPage::openReport);
    titleLay->addWidget(openButton);

    root->addWidget(titleRow);
    root->addWidget(PageHelpers::pageSubtitle(
        TR("A file is started inside Windows Sandbox — a throwaway copy of "
           "Windows — and everything it does there is recorded. The sandbox "
           "is discarded afterwards, so nothing it changes touches this "
           "computer."), this));

    buildAvailabilityCard(root);
    buildSampleCard(root);
    buildStatusCard(root);
    buildReportCards(root);

    root->addStretch();

}

SandboxPage::~SandboxPage() = default;

void SandboxPage::setBridge(ScannerBridge* bridge) {
    bridge_ = bridge;
    if (!bridge_) return;

    connect(bridge_, &ScannerBridge::sandboxStage, this,
            [this](QString stage) { setStatus(TR(stage)); });
    connect(bridge_, &ScannerBridge::sandboxFinished,
            this, &SandboxPage::onSessionFinished);
}

void SandboxPage::buildAvailabilityCard(QVBoxLayout* root) {
    const auto& environment = SandboxEnvironment::Get();
    sandboxAvailable_ =
        (environment.status == SandboxEnvironment::Status::Available);

    availabilityCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QHBoxLayout* outer = new QHBoxLayout(availabilityCard_);
    outer->setContentsMargins(Theme::Space::L, Theme::Space::M,
                              Theme::Space::L, Theme::Space::M);
    outer->setSpacing(Theme::Space::M);

    const bool ok = sandboxAvailable_;

    QLabel* icon = new QLabel(availabilityCard_);
    icon->setPixmap(Icons::pixmap(ok ? Icons::Id::ShieldCheck : Icons::Id::Warning,
                                  24, QColor(ok ? Theme::OK : Theme::SEV_HIGH)));
    icon->setStyleSheet("background: transparent; border: none;");
    icon->setAlignment(Qt::AlignTop);
    outer->addWidget(icon);

    QVBoxLayout* text = new QVBoxLayout();
    text->setContentsMargins(0, 0, 0, 0);
    text->setSpacing(Theme::Space::XXS);

    QLabel* title = new QLabel(
        ok ? TR("Windows Sandbox is ready")
           : TR("Windows Sandbox is not available"), availabilityCard_);
    title->setStyleSheet(plainLabelQss(ok ? Theme::OK : Theme::SEV_HIGH,
                                       Theme::Font::CARD, 600));
    text->addWidget(title);

    // Название редакции — то, как система зовёт себя сама, его не
    // переводим. Причину — обязательно: иначе половина карточки
    // остаётся на чужом языке.
    QString detail = QString::fromStdWString(environment.editionName);
    if (!environment.reason.empty())
        detail += "  ·  " + TR(QString::fromStdWString(environment.reason));

    QLabel* reason = new QLabel(detail, availabilityCard_);
    reason->setWordWrap(true);
    reason->setStyleSheet(plainLabelQss(Theme::TEXT_SECONDARY,
                                        Theme::Font::CONTROL));
    text->addWidget(reason);

    if (!environment.howToFix.empty()) {
        QLabel* fix = new QLabel(TR(QString::fromStdWString(environment.howToFix)),
                                 availabilityCard_);
        fix->setWordWrap(true);
        fix->setTextInteractionFlags(Qt::TextSelectableByMouse);
        fix->setStyleSheet(plainLabelQss(Theme::TEXT_MUTED, Theme::Font::CONTROL));
        text->addWidget(fix);
    } else if (!ok) {
        // Чинить нечего: на домашней редакции компонента нет и не будет.
        // Обещать обратное — врать, поэтому говорим прямо.
        QLabel* dead = new QLabel(
            TR("There is no way to enable it on this edition. Everything "
               "else in the application works as usual."), availabilityCard_);
        dead->setWordWrap(true);
        dead->setStyleSheet(plainLabelQss(Theme::TEXT_MUTED, Theme::Font::CONTROL));
        text->addWidget(dead);
    }

    outer->addLayout(text, 1);
    root->addWidget(availabilityCard_);
}

void SandboxPage::buildSampleCard(QVBoxLayout* root) {
    root->addWidget(PageHelpers::sectionTitle(TR("SAMPLE"), this));

    QFrame* card = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* lay = new QVBoxLayout(card);
    lay->setContentsMargins(Theme::Space::L, Theme::Space::L,
                            Theme::Space::L, Theme::Space::L);
    lay->setSpacing(Theme::Space::M);

    // ─── Путь к файлу ───
    QWidget* fileRow = new QWidget(card);
    fileRow->setStyleSheet("background: transparent;");
    QHBoxLayout* fileLay = new QHBoxLayout(fileRow);
    fileLay->setContentsMargins(0, 0, 0, 0);
    fileLay->setSpacing(Theme::Space::XS);

    sampleField_ = new QLabel(TR("No file chosen"), fileRow);
    sampleField_->setFixedHeight(Theme::Size::BTN_INPUT);
    sampleField_->setStyleSheet(fieldQss(false));
    sampleField_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    fileLay->addWidget(sampleField_, 1);

    chooseButton_ = new GradientButton(TR("Choose file"),
                                       GradientButton::Style::Outline, fileRow);
    chooseButton_->setFixedHeight(Theme::Size::BTN_INPUT);
    chooseButton_->setGradient(QColor(Theme::ACCENT),
                               QColor(Theme::ACCENT_GRAD_END));
    connect(chooseButton_, &QPushButton::clicked,
            this, &SandboxPage::chooseSample);
    fileLay->addWidget(chooseButton_);

    lay->addWidget(fileRow);

    // ─── Сеть ───
    QWidget* netRow = new QWidget(card);
    netRow->setStyleSheet("background: transparent;");
    QHBoxLayout* netLay = new QHBoxLayout(netRow);
    netLay->setContentsMargins(0, 0, 0, 0);
    netLay->setSpacing(Theme::Space::S);

    networkToggle_ = new ToggleSwitch(netRow);
    netLay->addWidget(networkToggle_, 0, Qt::AlignTop);

    QVBoxLayout* netText = new QVBoxLayout();
    netText->setContentsMargins(0, 0, 0, 0);
    netText->setSpacing(2);

    QLabel* netTitle = new QLabel(TR("Give the sandbox network access"), netRow);
    netTitle->setStyleSheet(plainLabelQss(Theme::TEXT_PRIMARY,
                                          Theme::Font::CONTROL, 500));
    netText->addWidget(netTitle);

    QLabel* netHint = new QLabel(
        TR("Many samples do nothing without it. The traffic is real and "
           "leaves your network, so turn this on deliberately."), netRow);
    netHint->setWordWrap(true);
    netHint->setStyleSheet(plainLabelQss(Theme::TEXT_MUTED, Theme::Font::OVERLINE));
    netText->addWidget(netHint);

    netLay->addLayout(netText, 1);
    lay->addWidget(netRow);

    // ─── Время наблюдения ───
    QWidget* timeRow = new QWidget(card);
    timeRow->setStyleSheet("background: transparent;");
    QHBoxLayout* timeLay = new QHBoxLayout(timeRow);
    timeLay->setContentsMargins(0, 0, 0, 0);
    timeLay->setSpacing(Theme::Space::S);

    QLabel* timeTitle = new QLabel(TR("Watch for"), timeRow);
    timeTitle->setStyleSheet(plainLabelQss(Theme::TEXT_PRIMARY,
                                           Theme::Font::CONTROL, 500));
    timeLay->addWidget(timeTitle);

    durationBox_ = new QComboBox(timeRow);
    durationBox_->addItem(TR("15 seconds"), 15000);
    durationBox_->addItem(TR("30 seconds"), 30000);
    durationBox_->addItem(TR("1 minute"),   60000);
    durationBox_->addItem(TR("2 minutes"),  120000);
    durationBox_->setCurrentIndex(1);
    durationBox_->setFixedHeight(Theme::Size::BTN_INPUT);
    durationBox_->setMinimumWidth(150);
    durationBox_->setCursor(Qt::PointingHandCursor);
    durationBox_->setStyleSheet(QString(
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
     .arg(Theme::Font::CONTROL)
     .arg(Theme::BORDER_CONTROL_HOVER, Theme::ROW_SELECTED));
    timeLay->addWidget(durationBox_);
    timeLay->addStretch();

    lay->addWidget(timeRow);

    // ─── Запуск ───
    QWidget* actionRow = new QWidget(card);
    actionRow->setStyleSheet("background: transparent;");
    QHBoxLayout* actionLay = new QHBoxLayout(actionRow);
    actionLay->setContentsMargins(0, 0, 0, 0);
    actionLay->setSpacing(Theme::Space::XS);

    runButton_ = new GradientButton(TR("Run in sandbox"),
                                    GradientButton::Style::Filled, actionRow);
    runButton_->setFixedHeight(Theme::Size::BTN_HERO);
    runButton_->setMinimumWidth(200);
    runButton_->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    runButton_->setEnabled(false);
    connect(runButton_, &QPushButton::clicked, this, &SandboxPage::startSession);
    actionLay->addWidget(runButton_);

    cancelButton_ = new GradientButton(TR("Cancel"),
                                       GradientButton::Style::Outline, actionRow);
    cancelButton_->setFixedHeight(Theme::Size::BTN_HERO);
    cancelButton_->setMinimumWidth(120);
    cancelButton_->setGradient(QColor(Theme::SEV_HIGH), QColor(Theme::SEV_CRIT));
    cancelButton_->hide();
    connect(cancelButton_, &QPushButton::clicked, this, &SandboxPage::cancelSession);
    actionLay->addWidget(cancelButton_);
    actionLay->addStretch();

    lay->addWidget(actionRow);

    if (!sandboxAvailable_) {
        chooseButton_->setEnabled(false);
        durationBox_->setEnabled(false);
        networkToggle_->setEnabled(false);
        card->setEnabled(false);
    }

    root->addWidget(card);
}

void SandboxPage::buildStatusCard(QVBoxLayout* root) {
    statusCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* lay = new QVBoxLayout(statusCard_);
    lay->setContentsMargins(Theme::Space::L, Theme::Space::M,
                            Theme::Space::L, Theme::Space::M);
    lay->setSpacing(Theme::Space::XXS);

    statusLabel_ = new QLabel(statusCard_);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(plainLabelQss(Theme::TEXT_PRIMARY,
                                              Theme::Font::CONTROL, 600));
    lay->addWidget(statusLabel_);

    statusHint_ = new QLabel(statusCard_);
    statusHint_->setWordWrap(true);
    statusHint_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusHint_->setStyleSheet(plainLabelQss(Theme::TEXT_SECONDARY,
                                             Theme::Font::CONTROL));
    lay->addWidget(statusHint_);

    statusCard_->hide();
    root->addWidget(statusCard_);
}

void SandboxPage::buildReportCards(QVBoxLayout* root) {
    // ─── Вердикт ───
    // Первое, что видит пользователь в отчёте: лента из десятков событий
    // без вывода — это работа, переложенная на него.
    verdictCard_ = PageHelpers::card(this, Theme::Radius::HERO);
    verdictLayout_ = new QVBoxLayout(verdictCard_);
    verdictLayout_->setContentsMargins(Theme::Space::L, Theme::Space::L,
                                       Theme::Space::L, Theme::Space::L);
    verdictLayout_->setSpacing(Theme::Space::S);
    root->addWidget(verdictCard_);

    // ─── Сводка ───
    summaryCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* summaryLay = new QVBoxLayout(summaryCard_);
    summaryLay->setContentsMargins(Theme::Space::L, Theme::Space::M,
                                   Theme::Space::L, Theme::Space::M);
    summaryLabel_ = new QLabel(summaryCard_);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setStyleSheet(plainLabelQss(Theme::TEXT_PRIMARY,
                                               Theme::Font::CARD, 600));
    summaryLay->addWidget(summaryLabel_);
    root->addWidget(summaryCard_);

    // ─── Дерево процессов ───
    processesTitle_ = PageHelpers::sectionTitle(TR("PROCESSES"), this);
    root->addWidget(processesTitle_);

    treeCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* treeLay = new QVBoxLayout(treeCard_);
    treeLay->setContentsMargins(1, 1, 1, 1);

    processTree_ = new QTreeWidget(treeCard_);
    processTree_->setColumnCount(4);
    processTree_->setHeaderLabels({ TR("Process"), TR("PID"),
                                    TR("Started"), TR("Exited") });
    processTree_->setRootIsDecorated(true);
    processTree_->setUniformRowHeights(true);
    processTree_->setSelectionMode(QAbstractItemView::NoSelection);
    processTree_->setFocusPolicy(Qt::NoFocus);
    processTree_->setMinimumHeight(140);
    processTree_->header()->setStretchLastSection(false);
    processTree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    processTree_->setColumnWidth(1, 90);
    processTree_->setColumnWidth(2, 110);
    processTree_->setColumnWidth(3, 150);
    processTree_->setStyleSheet(QString(
        "QTreeWidget {"
        "  background-color: transparent; color: %1; border: none;"
        "  font-size: %2px; outline: none;"
        "}"
        "QTreeWidget::item { height: %3px; }"
        "QHeaderView::section {"
        "  background-color: %4; color: %5; font-weight: 600;"
        "  font-size: %6px; padding: 0 12px; height: %7px;"
        "  border: none; border-bottom: 1px solid %8;"
        "}"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::BODY)
     .arg(Theme::Size::TABLE_ROW)
     .arg(Theme::SUNKEN, Theme::TEXT_MUTED)
     .arg(Theme::Font::OVERLINE).arg(Theme::Size::TABLE_HEADER)
     .arg(Theme::BORDER_CARD));

    treeLay->addWidget(processTree_);
    root->addWidget(treeCard_);

    // ─── События ───
    eventsTitle_ = PageHelpers::sectionTitle(TR("WHAT IT DID"), this);
    root->addWidget(eventsTitle_);

    eventsCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* eventsLay = new QVBoxLayout(eventsCard_);
    eventsLay->setContentsMargins(1, 1, 1, 1);

    eventsTable_ = new QTableWidget(eventsCard_);
    eventsTable_->setColumnCount(5);
    eventsTable_->setHorizontalHeaderLabels({ TR("Time"), TR("Event"), TR("PID"),
                                              TR("Object"), TR("Details") });
    eventsTable_->verticalHeader()->setVisible(false);
    eventsTable_->setShowGrid(false);
    eventsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventsTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    eventsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventsTable_->verticalHeader()->setDefaultSectionSize(Theme::Size::TABLE_ROW);
    // Перенос строк в ячейках Qt включает по умолчанию, и таблица
    // превращается в кашу из двухэтажных строк.
    eventsTable_->setWordWrap(false);
    eventsTable_->setTextElideMode(Qt::ElideMiddle);
    eventsTable_->horizontalHeader()->setHighlightSections(false);
    eventsTable_->setMinimumHeight(240);
    eventsTable_->setMaximumHeight(460);

    eventsTable_->setColumnWidth(0, 90);
    eventsTable_->setColumnWidth(1, 170);
    eventsTable_->setColumnWidth(2, 70);
    eventsTable_->setColumnWidth(3, 460);
    eventsTable_->setColumnWidth(4, 240);
    // Тянутся все колонки: в «Объекте» лежат пути, и разница между
    // соседними событиями часто именно в невидимой их части.
    eventsTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    eventsTable_->horizontalHeader()->setStretchLastSection(false);
    eventsTable_->horizontalHeader()->setMinimumSectionSize(60);

    eventsTable_->setStyleSheet(QString(
        "QTableWidget {"
        "  outline: none;"   // пунктирная рамка фокуса на текущей ячейке
        "  background-color: transparent; color: %1; border: none;"
        "  gridline-color: transparent; font-size: %6px;"
        "  selection-background-color: %5; selection-color: %1;"
        "}"
        "QTableWidget::item { padding: 0 12px; border-bottom: 1px solid %2; }"
        "QTableWidget::item:hover { background-color: %7; }"
        "QHeaderView::section {"
        "  background-color: %4; color: %3; font-weight: 600;"
        "  font-size: %8px; padding: 0 12px; height: %9px;"
        "  border: none; border-bottom: 1px solid %10;"
        "}"
    ).arg(Theme::TEXT_PRIMARY, Theme::BORDER_DIVIDER, Theme::TEXT_MUTED,
          Theme::SUNKEN, Theme::ROW_SELECTED)
     .arg(Theme::Font::BODY).arg(Theme::ROW_HOVER)
     .arg(Theme::Font::OVERLINE).arg(Theme::Size::TABLE_HEADER)
     .arg(Theme::BORDER_CARD));

    eventsLay->addWidget(eventsTable_);
    root->addWidget(eventsCard_);

    // ─── Ограничения ───
    limitationsTitle_ = PageHelpers::sectionTitle(
        TR("WHAT THIS OBSERVATION CANNOT SEE"), this);
    root->addWidget(limitationsTitle_);

    limitationsCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    limitationsLayout_ = new QVBoxLayout(limitationsCard_);
    limitationsLayout_->setContentsMargins(Theme::Space::L, Theme::Space::M,
                                           Theme::Space::L, Theme::Space::M);
    limitationsLayout_->setSpacing(Theme::Space::XS);
    root->addWidget(limitationsCard_);

    // ─── Пока ничего не запускали ───
    emptyCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* emptyLay = new QVBoxLayout(emptyCard_);
    emptyLay->setContentsMargins(40, 56, 40, 56);
    emptyLay->setAlignment(Qt::AlignCenter);
    emptyLay->setSpacing(Theme::Space::S);

    QLabel* emptyIcon = new QLabel(emptyCard_);
    emptyIcon->setPixmap(Icons::pixmap(Icons::Id::Flask, 48,
                                       QColor(Theme::TEXT_MUTED)));
    emptyIcon->setAlignment(Qt::AlignCenter);
    emptyIcon->setStyleSheet("background: transparent; border: none;");
    emptyLay->addWidget(emptyIcon);

    QLabel* emptyTitle = new QLabel(TR("Nothing has been observed yet"),
                                    emptyCard_);
    emptyTitle->setAlignment(Qt::AlignCenter);
    emptyTitle->setStyleSheet(plainLabelQss(Theme::TEXT_PRIMARY,
                                            Theme::Font::CARD, 600));
    emptyLay->addWidget(emptyTitle);

    QLabel* emptyHint = new QLabel(
        TR("Choose a file and run it in the sandbox. What it creates, where "
           "it writes, what it adds to the registry and which processes it "
           "starts will appear here."), emptyCard_);
    emptyHint->setAlignment(Qt::AlignCenter);
    emptyHint->setWordWrap(true);
    emptyHint->setStyleSheet(plainLabelQss(Theme::TEXT_SECONDARY,
                                           Theme::Font::CONTROL));
    emptyLay->addWidget(emptyHint);

    root->addWidget(emptyCard_);

    showReportCards(false);
    // Без песочницы обещать нечего: причина уже сказана выше, и вторая
    // карточка под ней была бы пустой болтовнёй.
    emptyCard_->setVisible(sandboxAvailable_);
}

void SandboxPage::showReportCards(bool visible) {
    for (QWidget* widget : { static_cast<QWidget*>(verdictCard_),
                             static_cast<QWidget*>(summaryCard_),
                             static_cast<QWidget*>(processesTitle_),
                             static_cast<QWidget*>(treeCard_),
                             static_cast<QWidget*>(eventsTitle_),
                             static_cast<QWidget*>(eventsCard_),
                             static_cast<QWidget*>(limitationsTitle_),
                             static_cast<QWidget*>(limitationsCard_) }) {
        if (widget) widget->setVisible(visible);
    }
}

void SandboxPage::chooseSample() {
    const QString path = QFileDialog::getOpenFileName(
        this, TR("Choose a file to observe"), QString(),
        TR("Programs and scripts") +
            " (*.exe *.bat *.cmd *.ps1 *.vbs *.js *.wsf);;" +
            TR("All files") + " (*)");
    if (path.isEmpty()) return;

    // Диалог отдаёт путь с прямыми слэшами, обход каталога — с обратными.
    // Дальше путь идёт в .wsb и в сравнения, поэтому приводим к родным.
    samplePath_ = QDir::toNativeSeparators(path);
    sampleField_->setText(samplePath_);
    sampleField_->setToolTip(samplePath_);
    sampleField_->setStyleSheet(fieldQss(true));
    runButton_->setEnabled(sandboxAvailable_);
}

void SandboxPage::openReport() {
    const QString path = QFileDialog::getOpenFileName(
        this, TR("Open a report"), reportsFolder(), "JSON (*.json)");
    if (path.isEmpty()) return;
    loadReportFile(path);
}

void SandboxPage::loadReportFile(const QString& path) {
    BehaviorReport report;
    std::wstring error;
    if (!SandboxSession::ReadReportJson(QDir::toNativeSeparators(path)
                                            .toStdWString(), report, &error)) {
        setStatus(TR("Could not read the report"),
                  QString::fromStdWString(error), Theme::SEV_HIGH);
        showReportCards(false);
        return;
    }

    emptyCard_->hide();
    showReport(report);
    // Отчёт из файла — не результат только что прошедшего сеанса, и
    // выдавать его за таковой нельзя: песочница могла быть чужой.
    setStatus(TR("Report loaded from a file"),
              QDir::toNativeSeparators(path), Theme::TEXT_SECONDARY);
}

void SandboxPage::startSession() {
    if (running_ || samplePath_.isEmpty() || !sandboxAvailable_ || !bridge_)
        return;

    const int observeMs = durationBox_->currentData().toInt();

    QJsonObject options;
    options["samplePath"]      = samplePath_;
    options["observeTimeoutMs"] = observeMs;
    options["networking"]      = networkToggle_->isChecked();
    // Ждать отчёт надо заметно дольше самого наблюдения: почти всё время
    // уходит на загрузку виртуальной машины.
    options["waitForReportMs"] = observeMs + 300000;

    QString error;
    if (!bridge_->startSandbox(options, &error)) {
        setStatus(TR("The session did not finish"), error, Theme::SEV_CRIT);
        return;
    }

    running_ = true;
    setRunning(true);
    showReportCards(false);
    emptyCard_->hide();

    setStatus(TR("Preparing the isolated session"),
              TR("Windows Sandbox needs a while to boot. The window it opens "
                 "belongs to the sandbox, not to this computer."));
}

void SandboxPage::cancelSession() {
    if (!running_ || !bridge_) return;
    bridge_->cancelSandbox();
    setStatus(TR("Stopping the session"));
    cancelButton_->setEnabled(false);
}

void SandboxPage::onSessionFinished(int result, const QString& message,
                                    const QString& howToFix,
                                    const QString& reportPath)
{
    if (!running_) return;   // чужой сеанс или уже разобранный

    running_ = false;
    setRunning(false);

    switch (static_cast<SandboxSession::Result>(result)) {
    case SandboxSession::Result::Completed: {
        // Отчёт лежит на диске: помощник сохранил его сам, потому что
        // рабочую папку сеанса он же и удаляет.
        BehaviorReport report;
        std::wstring error;
        if (!SandboxSession::ReadReportJson(reportPath.toStdWString(),
                                            report, &error)) {
            setStatus(TR("Could not read the report"),
                      QString::fromStdWString(error), Theme::SEV_HIGH);
            return;
        }
        showReport(report);
        publishSession(report, reportPath);
        break;
    }

    case SandboxSession::Result::Cancelled:
        setStatus(TR("Session cancelled"), message, Theme::TEXT_SECONDARY);
        break;

    case SandboxSession::Result::Unavailable:
        setStatus(TR("Windows Sandbox is not available"),
                  howToFix.isEmpty() ? message : message + "\n" + howToFix,
                  Theme::SEV_HIGH);
        break;

    default:
        setStatus(TR("The session did not finish"), message, Theme::SEV_CRIT);
        break;
    }
}

void SandboxPage::showReport(const BehaviorReport& report) {
    const int processCount = static_cast<int>(report.processes.size());
    const int eventCount   = static_cast<int>(report.events.size());

    QStringList parts;
    parts << TR("Observed for") + " " + formatMs(report.durationMs);
    parts << QString::number(processCount) + " " +
             TRN(processCount, "process", "processes",
                 "процесс", "процесса", "процессов");
    parts << QString::number(eventCount) + " " +
             TRN(eventCount, "event", "events",
                 "событие", "события", "событий");

    QString summary = parts.join("  ·  ");
    if (report.launchFailed) {
        summary = TR("The sample did not start");
    } else {
        if (report.timedOut)
            summary += "  ·  " + TR("time limit reached");
        if (report.killed)
            summary += "  ·  " + TR("process tree was terminated");
    }
    summaryLabel_->setText(summary);

    if (report.launchFailed) {
        setStatus(TR("The sample did not start"),
                  QString::fromStdWString(report.failureReason),
                  Theme::SEV_HIGH);
    } else {
        setStatus(TR("Session finished"),
                  TR("The sandbox has been discarded together with everything "
                     "the sample did inside it."),
                  Theme::OK);
    }

    fillVerdict(report);
    fillProcessTree(report);
    fillEvents(report);
    fillLimitations(report);
    showReportCards(true);
}

void SandboxPage::publishSession(const BehaviorReport& report,
                                 const QString& reportPath)
{
    const BehaviorVerdict verdict = JudgeBehavior(report);

    Logger::Instance().Info(
        "[Sandbox] verdict for " + samplePath_.toStdString() + ": " +
        severityCode(verdict.severity).toStdString() + ", " +
        std::to_string(verdict.findings.size()) + " findings");

    // Сеанс попадает в историю всегда: «проверили и ничего не нашли» —
    // тоже результат, и через неделю о нём иначе не вспомнить.
    ScanRecord record;
    record.when           = QDateTime::currentDateTime();
    record.mode           = "Sandbox";
    record.reportPath     = reportPath;
    record.durationMs     = report.durationMs;
    record.objectsScanned = static_cast<qint64>(report.events.size());
    // cancelled намеренно не ставим по таймауту: наблюдение с лимитом
    // времени дошло до конца, а «прервана» в истории читается как сбой.
    record.cancelled      = false;

    for (const auto& finding : verdict.findings) {
        record.findings.push_back(ScanRecord::Finding{
            severityCode(finding.severity),
            QString::fromStdWString(finding.title),
            QString::fromStdWString(finding.detail) });
    }

    if (VerdictWarrantsThreat(verdict)) {
        record.totalThreats = 1;
        record.criticalThreats = (verdict.severity == Severity::Critical) ? 1 : 0;

        emit behaviourThreatFound(
            ThreatFromBehaviour(samplePath_.toStdWString(), report, verdict));
    }

    ScanHistory::instance().add(record);
}

void SandboxPage::fillVerdict(const BehaviorReport& report) {
    while (QLayoutItem* item = verdictLayout_->takeAt(0)) {
        if (QWidget* widget = item->widget()) widget->deleteLater();
        if (QLayout* child = item->layout()) delete child;
        delete item;
    }

    const BehaviorVerdict verdict = JudgeBehavior(report);
    const QString code = severityCode(verdict.severity);

    QWidget* head = new QWidget(verdictCard_);
    head->setStyleSheet("background: transparent;");
    QHBoxLayout* headLay = new QHBoxLayout(head);
    headLay->setContentsMargins(0, 0, 0, 0);
    headLay->setSpacing(Theme::Space::S);

    QLabel* pill = PageHelpers::severityPill(code, head);
    headLay->addWidget(pill, 0, Qt::AlignTop);

    QLabel* summary = new QLabel(TR(QString::fromStdWString(verdict.summary)), head);
    summary->setWordWrap(true);
    summary->setStyleSheet(plainLabelQss(
        PageHelpers::severityColors(code).fg, Theme::Font::CARD, 600));
    headLay->addWidget(summary, 1);

    verdictLayout_->addWidget(head);

    if (verdict.findings.empty()) return;

    QFrame* divider = new QFrame(verdictCard_);
    divider->setFixedHeight(1);
    divider->setStyleSheet(QString("background-color: %1; border: none;")
                               .arg(Theme::BORDER_DIVIDER));
    verdictLayout_->addWidget(divider);

    for (const auto& finding : verdict.findings) {
        QWidget* row = new QWidget(verdictCard_);
        row->setStyleSheet("background: transparent;");
        QHBoxLayout* rowLay = new QHBoxLayout(row);
        rowLay->setContentsMargins(0, 0, 0, 0);
        rowLay->setSpacing(Theme::Space::S);

        QLabel* rowPill = PageHelpers::severityPill(
            severityCode(finding.severity), row);
        rowLay->addWidget(rowPill, 0, Qt::AlignTop);

        QVBoxLayout* textLay = new QVBoxLayout();
        textLay->setContentsMargins(0, 0, 0, 0);
        textLay->setSpacing(2);

        QLabel* title = new QLabel(TR(QString::fromStdWString(finding.title)), row);
        title->setWordWrap(true);
        title->setStyleSheet(plainLabelQss(Theme::TEXT_PRIMARY,
                                           Theme::Font::CONTROL, 600));
        textLay->addWidget(title);

        QLabel* detail = new QLabel(QString::fromStdWString(finding.detail), row);
        detail->setWordWrap(true);
        detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
        detail->setStyleSheet(QString(
            "color: %1; font-family: \"%2\"; font-size: %3px;"
            "background: transparent; border: none;"
        ).arg(Theme::TEXT_MONO_DIM, Theme::FONT_MONO).arg(Theme::Font::OVERLINE));
        textLay->addWidget(detail);

        rowLay->addLayout(textLay, 1);
        verdictLayout_->addWidget(row);
    }
}

void SandboxPage::fillProcessTree(const BehaviorReport& report) {
    processTree_->clear();

    QSet<quint32> known;
    for (const auto& process : report.processes)
        known.insert(process.pid);

    QHash<quint32, QTreeWidgetItem*> items;

    auto makeItem = [&](const ObservedProcess& process) {
        QFileInfo info(QString::fromStdWString(process.image));
        QString name = info.fileName();
        if (name.isEmpty()) name = TR("unknown");

        auto* item = new QTreeWidgetItem();
        item->setText(0, name);
        item->setText(1, QString::number(process.pid));
        item->setText(2, formatMs(process.startedAtMs));
        item->setText(3, process.exitedAtMs >= 0
            ? formatMs(process.exitedAtMs) + "  ·  " + TR("code") + " " +
              QString::number(process.exitCode)
            : TR("still running"));

        item->setToolTip(0, process.commandLine.empty()
            ? QString::fromStdWString(process.image)
            : QString::fromStdWString(process.commandLine));

        item->setForeground(0, QColor(process.isRoot ? Theme::ACCENT_TEXT
                                                     : Theme::TEXT_PRIMARY));
        for (int column = 1; column < 4; ++column)
            item->setForeground(column, QColor(Theme::TEXT_SECONDARY));
        return item;
    };

    // Сначала все узлы, потом связи: потомок может встретиться в списке
    // раньше своего родителя.
    for (const auto& process : report.processes)
        items.insert(process.pid, makeItem(process));

    for (const auto& process : report.processes) {
        QTreeWidgetItem* item = items.value(process.pid);
        auto parent = items.constFind(process.parentPid);
        if (!process.isRoot && parent != items.constEnd() &&
            known.contains(process.parentPid)) {
            (*parent)->addChild(item);
        } else {
            processTree_->addTopLevelItem(item);
        }
    }
    processTree_->expandAll();

    // Дерево подгоняем под содержимое и возвращаем в начало: без этого
    // видны потомки, а корень оказывается выше края — картина получается
    // ровно обратная тому, что дерево должно показывать.
    const int rows = static_cast<int>(report.processes.size());
    const int wanted = processTree_->header()->height() +
                       rows * Theme::Size::TABLE_ROW + Theme::Space::XS;
    processTree_->setFixedHeight(qBound(140, wanted, 360));
    processTree_->scrollToTop();
}

void SandboxPage::fillEvents(const BehaviorReport& report) {
    eventsTable_->setRowCount(0);

    for (const auto& event : report.events) {
        const int row = eventsTable_->rowCount();
        eventsTable_->insertRow(row);

        auto* time = new QTableWidgetItem(formatMs(event.atMs));
        time->setForeground(QColor(Theme::TEXT_MUTED));
        eventsTable_->setItem(row, 0, time);

        auto* what = new QTableWidgetItem(eventName(event.type));
        what->setForeground(QColor(eventColor(event.type)));
        eventsTable_->setItem(row, 1, what);

        // Ноль означает «источник неизвестен», а не «процесс номер ноль».
        auto* pid = new QTableWidgetItem(
            event.pid ? QString::number(event.pid) : QString("—"));
        pid->setForeground(QColor(Theme::TEXT_SECONDARY));
        pid->setToolTip(event.pid ? QString()
                                  : TR("The author of this change is not "
                                       "visible without a kernel driver."));
        eventsTable_->setItem(row, 2, pid);

        auto* target = new QTableWidgetItem(
            QString::fromStdWString(event.target));
        target->setForeground(QColor(Theme::TEXT_PRIMARY));
        target->setToolTip(QString::fromStdWString(event.target));
        eventsTable_->setItem(row, 3, target);

        const QString detailText = translateDetail(event.type, event.detail);
        auto* detail = new QTableWidgetItem(detailText);
        detail->setForeground(QColor(Theme::TEXT_SECONDARY));
        detail->setToolTip(detailText);
        eventsTable_->setItem(row, 4, detail);
    }
}

void SandboxPage::fillLimitations(const BehaviorReport& report) {
    while (QLayoutItem* item = limitationsLayout_->takeAt(0)) {
        if (QWidget* widget = item->widget()) widget->deleteLater();
        delete item;
    }

    for (const auto& limitation : report.limitations) {
        QLabel* line = new QLabel(
            "•  " + translateLimitation(limitation), limitationsCard_);
        line->setWordWrap(true);
        line->setStyleSheet(plainLabelQss(Theme::TEXT_SECONDARY,
                                          Theme::Font::CONTROL));
        limitationsLayout_->addWidget(line);
    }
}

void SandboxPage::setRunning(bool running) {
    runButton_->setVisible(!running);
    cancelButton_->setVisible(running);
    cancelButton_->setEnabled(true);
    chooseButton_->setEnabled(!running);
    durationBox_->setEnabled(!running);
    networkToggle_->setEnabled(!running);
}

void SandboxPage::setStatus(const QString& text, const QString& hint,
                            const QString& color)
{
    statusCard_->show();
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(plainLabelQss(
        color.isEmpty() ? QString(Theme::TEXT_PRIMARY) : color,
        Theme::Font::CONTROL, 600));

    statusHint_->setText(hint);
    statusHint_->setVisible(!hint.isEmpty());
}
