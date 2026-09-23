#include "ThreatsPage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"
#include "../core/ThreatReport.h"   // ThreatKind

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QFontMetrics>
#include <QFrame>
#include <QPushButton>
#include <QMessageBox>
#include <QUrl>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include "../ui/GradientButton.h"
#include "../ui/ConfirmDialog.h"
#include "../ui/Icons.h"

namespace {

// Маленькая кнопка для ячейки TR("Actions") — обычные слишком высокие для строки.
GradientButton* cellButton(const QString& text, const QColor& from,
                           const QColor& to, QWidget* parent)
{
    auto* b = new GradientButton(text, GradientButton::Style::Outline, parent);
    b->setFixedHeight(Theme::Size::BTN_ROW);
    b->setGradient(from, to);
    b->setRadius(Theme::Radius::PILL);

    // Поля у кнопки в строке уже, чем у обычной: три кнопки со штатными
    // 24 пикселями с каждой стороны съедали треть таблицы, и на путь
    // не оставалось места. Запас на жирное начертание — DemiBold рисуется
    // шире, чем считают метрики обычного шрифта.
    QFont bold = b->font();
    bold.setWeight(QFont::DemiBold);
    b->setFixedWidth(QFontMetrics(bold).horizontalAdvance(text) + 26);
    return b;
}

// evidence у файловых угроз — это SHA-256, а у записей реестра туда
// кладётся командная строка. В VirusTotal имеет смысл слать только хэш.
bool IsSha256(const QString& s) {
    if (s.size() != 64) return false;
    for (QChar c : s) {
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

QString statusColor(const QString& status) {
    if (status == "Quarantined") return Theme::SEV_MED;
    if (status == "Deleted")     return Theme::OK;
    if (status == "Ignored")     return Theme::TEXT_MUTED;
    if (status == "Failed")      return Theme::SEV_CRIT;
    return Theme::TEXT_SECONDARY;
}

} // namespace

ThreatsPage::ThreatsPage(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet("background: transparent;");

    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                             Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    root->setSpacing(12);

    // Заголовок + бейдж количества + массовые действия
    QWidget* titleRow = new QWidget(this);
    titleRow->setStyleSheet("background: transparent;");
    QHBoxLayout* titleLay = new QHBoxLayout(titleRow);
    titleLay->setContentsMargins(0, 0, 0, 0);
    titleLay->setSpacing(12);
    titleLay->setAlignment(Qt::AlignVCenter);

    titleLay->addWidget(PageHelpers::pageTitle(TR("Threats"), this));

    countBadge_ = new QLabel("0", titleRow);
    countBadge_->setStyleSheet(QString(
        "background-color: rgba(239,68,68,30);"
        "color: %1;"
        "border: 1px solid rgba(239,68,68,80);"
        "border-radius: 11px;"
        "padding: 2px 12px;"
        "font-size: 12px;"
        "font-weight: 700;"
        "min-width: 20px;"
    ).arg(Theme::SEV_CRIT));
    countBadge_->setAlignment(Qt::AlignCenter);
    countBadge_->setVisible(false);
    titleLay->addWidget(countBadge_);

    titleLay->addStretch();

    auto* vtBtn = new GradientButton(TR("Check all on VirusTotal"),
                                     GradientButton::Style::Outline, titleRow);
    vtBtn->setFixedHeight(Theme::Size::BTN_HEADER);
    vtBtn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    vtAllBtn_ = vtBtn;
    vtAllBtn_->setEnabled(false);
    connect(vtAllBtn_, &QPushButton::clicked,
            this, &ThreatsPage::checkAllOnVirusTotal);
    titleLay->addWidget(vtAllBtn_);

    // Градиент от оранжевого к красному: действие массовое и необратимое
    // для части угроз, поэтому оно должно читаться как самое «горячее».
    auto* quarBtn = new GradientButton(TR("Quarantine all critical"),
                                       GradientButton::Style::Outline, titleRow);
    quarBtn->setFixedHeight(Theme::Size::BTN_HEADER);
    quarBtn->setGradient(QColor(Theme::SEV_HIGH), QColor(Theme::SEV_CRIT));
    quarantineAllBtn_ = quarBtn;
    quarantineAllBtn_->setEnabled(false);
    connect(quarantineAllBtn_, &QPushButton::clicked,
            this, &ThreatsPage::quarantineAllCritical);
    titleLay->addWidget(quarantineAllBtn_);

    root->addWidget(titleRow);

    root->addWidget(PageHelpers::pageSubtitle(
        TR("Detected suspicious items across registry, files and processes. "
           "Double-click a row to see why it was flagged."), this));

    root->addSpacing(12);

    // Карточка с таблицей
    QFrame* cardFrame = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* cardLay = new QVBoxLayout(cardFrame);
    cardLay->setContentsMargins(1, 1, 1, 1);

    table_ = new QTableWidget(cardFrame);
    table_->setColumnCount(ColumnCount);
    table_->setHorizontalHeaderLabels(
        {TR("Severity"), TR("Name"), TR("Source"), TR("VirusTotal"), TR("Status"), TR("Actions")});
    table_->verticalHeader()->setVisible(false);
    table_->setShowGrid(false);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(false);

    table_->setColumnWidth(ColSeverity,  130);
    table_->setColumnWidth(ColName,      220);
    table_->setColumnWidth(ColSource,    420);
    table_->setColumnWidth(ColVirusTotal, 130);
    table_->setColumnWidth(ColStatus,    110);
    table_->setColumnWidth(ColActions,   120);

    // Все колонки тянутся мышью, включая расположение. Растягивающаяся
    // колонка мышью не двигается, а именно в ней лежат пути — из-за
    // этого два разных файла с одинаковым именем выглядели как одна
    // строка, размноженная дважды.
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(false);
    table_->horizontalHeader()->setMinimumSectionSize(60);
    // Двойной щелчок по границе заголовка подгоняет колонку под
    // содержимое — так же, как в диспетчере задач.
    table_->horizontalHeader()->setCascadingSectionResizes(false);

    table_->verticalHeader()->setDefaultSectionSize(Theme::Size::TABLE_ROW);
    // По умолчанию QTableView переносит текст по словам — длинные пути
    // из-за этого лезли в две строки и наезжали на границу строки.
    table_->setWordWrap(false);
    // Обрезаем середину, а не хвост: в конце пути стоит имя файла,
    // и именно оно отличает соседние находки друг от друга.
    table_->setTextElideMode(Qt::ElideMiddle);
    table_->horizontalHeader()->setHighlightSections(false);

    table_->setStyleSheet(QString(
        "QTableWidget {"
        // Пунктирная рамка вокруг текущей ячейки читается как дефект
        // вёрстки — особенно на пилюле уровня, где выглядит обводкой
        // кнопки. Выделение строки видно и без неё.
        "  outline: none;"
        "  background-color: transparent;"
        "  color: %1;"
        "  border: none;"
        "  gridline-color: transparent;"
        "  font-size: %6px;"
        "  selection-background-color: %5;"
        "  selection-color: %1;"
        "}"
        // Скругления у ячеек недоступны — строки разделяет нижняя граница.
        "QTableWidget::item {"
        "  padding: 0 16px;"
        "  border-bottom: 1px solid %2;"
        "}"
        "QTableWidget::item:hover    { background-color: %7; }"
        "QTableWidget::item:selected { background-color: %5; color: %1; }"
        "QHeaderView::section {"
        "  background-color: %4;"
        "  color: %3;"
        "  font-weight: 600;"
        "  font-size: %8px;"
        "  padding: 0 16px;"
        "  height: %9px;"
        "  border: none;"
        "  border-bottom: 1px solid %10;"
        "}"
        "QTableCornerButton::section { background-color: %4; border: none; }"
    ).arg(Theme::TEXT_PRIMARY, Theme::BORDER_DIVIDER, Theme::TEXT_MUTED,
          Theme::SUNKEN, Theme::ROW_SELECTED)
     .arg(Theme::Font::BODY)
     .arg(Theme::ROW_HOVER)
     .arg(Theme::Font::OVERLINE)
     .arg(Theme::Size::TABLE_HEADER)
     .arg(Theme::BORDER_CARD));

    // Двойной клик по строке — подробности. Раньше причина находки жила
    // только во всплывающей подсказке, а её никто не находит.
    connect(table_, &QTableWidget::cellDoubleClicked,
            this, [this](int row, int column) {
        if (column == ColVirusTotal) return;   // там своя обработка ниже

        auto* nameItem = table_->item(row, ColName);
        auto* srcItem  = table_->item(row, ColSource);
        if (!nameItem) return;

        // По расположению открываем проводник с выделенным файлом —
        // это первое, что хочется сделать, увидев подозрительный путь.
        if (column == ColSource && srcItem) {
            const QString path = srcItem->data(Qt::UserRole).toString();
            const QFileInfo info(path);

            if (info.exists()) {
                // /select требует системных разделителей и кавычек:
                // в пути почти всегда есть пробелы.
                QProcess::startDetached(
                    "explorer.exe",
                    { "/select,", QDir::toNativeSeparators(path) });
            } else if (info.dir().exists()) {
                // Файла уже нет (удалён, в карантине) — открываем папку.
                QDesktopServices::openUrl(
                    QUrl::fromLocalFile(info.dir().absolutePath()));
            }
            return;
        }

        auto* sevWrap = table_->cellWidget(row, ColSeverity);
        auto* sevLabel = sevWrap ? sevWrap->findChild<QLabel*>() : nullptr;

        const QString nl = "\n\n";

        QString body;
        body += TR("Severity") + ": "
              + (sevLabel ? sevLabel->text() : QString("—")) + nl;
        body += TR("Source") + ":\n"
              + (srcItem ? srcItem->text() : QString()) + nl;
        body += TR("Why it was flagged") + ":\n"
              + indexDetails_.value(nameItem->data(Qt::UserRole).toInt(),
                                    TR("No details available."));

        ConfirmDialog::ask(this, nameItem->text(), body, TR("Close"), false);
    });

    // Проверка одной строки: двойной клик по ячейке VirusTotal
    connect(table_, &QTableWidget::cellDoubleClicked,
            this, [this](int row, int column) {
        if (column != ColVirusTotal) return;
        auto* item = table_->item(row, ColVirusTotal);
        if (!item) return;

        const int index = item->data(Qt::UserRole).toInt();
        const QString sha = indexToHash_.value(index);
        if (sha.isEmpty()) return;

        setVirusTotalPending(index);
        emit vtCheckRequested(index, sha);
    });

    cardLay->addWidget(table_);

    // Пустое состояние: иконка, объяснение и действие, а не голая строка.
    emptyBox_ = new QWidget(cardFrame);
    emptyBox_->setStyleSheet("background: transparent;");
    QVBoxLayout* emptyLay = new QVBoxLayout(emptyBox_);
    emptyLay->setContentsMargins(40, 64, 40, 64);
    emptyLay->setAlignment(Qt::AlignCenter);
    emptyLay->setSpacing(Theme::Space::S);

    QLabel* emptyIcon = new QLabel(emptyBox_);
    emptyIcon->setPixmap(Icons::fromResource("glyph-clean", 48,
                                             QColor(Theme::OK)));
    emptyIcon->setAlignment(Qt::AlignCenter);
    emptyIcon->setStyleSheet("background: transparent; border: none;");
    emptyLay->addWidget(emptyIcon);

    QLabel* emptyTitle = new QLabel(TR("No threats found"), emptyBox_);
    emptyTitle->setAlignment(Qt::AlignCenter);
    emptyTitle->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::CARD));
    emptyLay->addWidget(emptyTitle);

    QLabel* emptySub = new QLabel(
        TR("Run a scan to see results here."), emptyBox_);
    emptySub->setAlignment(Qt::AlignCenter);
    emptySub->setWordWrap(true);
    emptySub->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::CONTROL));
    emptyLay->addWidget(emptySub);

    auto* emptyBtn = new GradientButton(TR("Start scan"),
                                        GradientButton::Style::Filled, emptyBox_);
    emptyBtn->setFixedHeight(Theme::Size::BTN_HERO);
    emptyBtn->setMinimumWidth(180);
    connect(emptyBtn, &QPushButton::clicked, this, &ThreatsPage::scanRequested);

    QHBoxLayout* emptyBtnRow = new QHBoxLayout;
    emptyBtnRow->addStretch();
    emptyBtnRow->addWidget(emptyBtn);
    emptyBtnRow->addStretch();
    emptyLay->addLayout(emptyBtnRow);

    cardLay->addWidget(emptyBox_);

    root->addWidget(cardFrame, 1);

    updateEmptyState();
}

void ThreatsPage::clearThreats() {
    table_->setRowCount(0);
    indexToRow_.clear();
    indexToHash_.clear();
    indexDetails_.clear();
    updateEmptyState();
}

QWidget* ThreatsPage::buildActionCell(int index, int kind) {
    QWidget* wrap = new QWidget(table_);
    wrap->setStyleSheet("background: transparent;");
    QHBoxLayout* lay = new QHBoxLayout(wrap);
    lay->setContentsMargins(8, 0, 8, 0);
    lay->setSpacing(6);

    // В карантин можно положить только файл. Запись реестра и задачу
    // "карантин" удаляет безвозвратно — называем вещи своими именами
    // и спрашиваем подтверждение, как у Delete.
    const bool storable = (kind == static_cast<int>(ThreatKind::File) ||
                           kind == static_cast<int>(ThreatKind::Process));

    auto* quar = cellButton(storable ? TR("Quarantine") : TR("Remove"),
                            QColor(Theme::SEV_MED), QColor(Theme::SEV_HIGH), wrap);
    auto* del  = cellButton(TR("Delete"), QColor(Theme::SEV_HIGH),
                            QColor(Theme::SEV_CRIT), wrap);
    auto* ign  = cellButton(TR("Ignore"), QColor(Theme::TEXT_MUTED),
                            QColor(Theme::TEXT_SECONDARY), wrap);

    quar->setToolTip(storable
        ? "Move the file to quarantine. It can be restored later."
        : "Remove this entry. This is permanent — it cannot be restored.");

    connect(quar, &QPushButton::clicked, this, [this, index, storable]() {
        if (!storable &&
            QMessageBox::question(
                this, TR("Remove entry"),
                "This item is not a file, so it cannot be quarantined — "
                "it will be removed permanently.\n\nContinue?")
            != QMessageBox::Yes) {
            return;
        }
        emit actionRequested(index, 0);
    });
    connect(del, &QPushButton::clicked, this, [this, index]() {
        if (QMessageBox::question(
                this, TR("Delete permanently"),
                "Delete this item permanently? This cannot be undone.\n\n"
                "Quarantine is the safer option — it can be restored later.")
            != QMessageBox::Yes) {
            return;
        }
        emit actionRequested(index, 1);
    });
    connect(ign, &QPushButton::clicked, this, [this, index]() {
        emit actionRequested(index, 2);
    });

    lay->addWidget(quar);
    lay->addWidget(del);
    lay->addWidget(ign);
    lay->addStretch();

    return wrap;
}

void ThreatsPage::addThreat(int index, int kind, const QString& severity,
                            const QString& name, const QString& source,
                            const QString& why, const QString& evidence)
{
    int row = table_->rowCount();
    table_->insertRow(row);
    indexToRow_[index] = row;

    const QString sha = IsSha256(evidence) ? evidence : QString();
    indexToHash_[index] = sha;

    QLabel* sevLabel = PageHelpers::severityPill(severity, table_);

    QWidget* sevWrap = new QWidget(table_);
    sevWrap->setStyleSheet("background: transparent;");
    QHBoxLayout* sevWrapLay = new QHBoxLayout(sevWrap);
    sevWrapLay->setContentsMargins(16, 0, 8, 0);
    sevWrapLay->setSpacing(0);
    sevWrapLay->addWidget(sevLabel);
    sevWrapLay->addStretch();
    table_->setCellWidget(row, ColSeverity, sevWrap);
    // ResizeToContents не видит виджеты в ячейках — ширину задаём сами.
    sevWrap->adjustSize();
    table_->setColumnWidth(ColSeverity,
                           qMax(table_->columnWidth(ColSeverity),
                                sevWrap->minimumSizeHint().width() + 16));

    auto whiteItem = [](const QString& text) {
        auto* it = new QTableWidgetItem(text);
        it->setForeground(QColor(Theme::TEXT_PRIMARY));
        return it;
    };
    auto mutedItem = [](const QString& text) {
        auto* it = new QTableWidgetItem(text);
        it->setForeground(QColor(Theme::TEXT_SECONDARY));
        return it;
    };

    // Полные детали — в подсказке, чтобы не раздувать таблицу колонками.
    QString tip = why;
    if (!sha.isEmpty())           tip += "\n\nSHA-256: " + sha;
    else if (!evidence.isEmpty()) tip += "\n\nEvidence: " + evidence;

    auto* nameItem = whiteItem(name);
    nameItem->setToolTip(tip);
    nameItem->setData(Qt::UserRole, index);
    indexDetails_[index] = why.isEmpty() ? TR("No details available.") : why;
    table_->setItem(row, ColName, nameItem);

    auto* sourceItem = mutedItem(source);
    sourceItem->setToolTip(source + "\n\n" + tip);
    sourceItem->setData(Qt::UserRole, source);   // полный путь для проводника
    table_->setItem(row, ColSource, sourceItem);

    auto* vtItem = mutedItem(sha.isEmpty() ? "—" : TR("Not checked"));
    vtItem->setTextAlignment(Qt::AlignCenter);
    vtItem->setData(Qt::UserRole, index);
    vtItem->setToolTip(sha.isEmpty()
        ? "No file hash — nothing to look up."
        : "Double-click to check this file on VirusTotal.");
    table_->setItem(row, ColVirusTotal, vtItem);

    auto* statusItem = new QTableWidgetItem(TR("Pending"));
    statusItem->setForeground(QColor(statusColor("Pending")));
    table_->setItem(row, ColStatus, statusItem);

    QWidget* actions = buildActionCell(index, kind);
    table_->setCellWidget(row, ColActions, actions);
    // Ширину считаем по минимально необходимой: sizeHint до раскладки
    // её занижает, и после перевода кнопки налезали друг на друга.
    actions->adjustSize();
    table_->setColumnWidth(ColActions,
                           qMax(table_->columnWidth(ColActions),
                                actions->minimumSizeHint().width() + 24));

    // Кнопки только что могли раздвинуть свою колонку — «Расположение»
    // должно отдать ей место, иначе действия уезжают за правый край.
    fitSourceColumn();

    updateEmptyState();
}

void ThreatsPage::setThreatStatus(int index, const QString& status,
                                  const QString& message, bool success)
{
    auto it = indexToRow_.constFind(index);
    if (it == indexToRow_.constEnd()) return;
    const int row = it.value();

    if (auto* item = table_->item(row, ColStatus)) {
        // Статус приходит из ядра по-английски: показываем перевод,
        // а цвет подбираем по исходному ключу.
        item->setText(TR(status));
        item->setForeground(QColor(statusColor(status)));
        item->setToolTip(message);
    }

    // Действие применено — повторно его выполнять нельзя.
    if (success) {
        if (auto* cell = table_->cellWidget(row, ColActions)) {
            const auto buttons = cell->findChildren<QPushButton*>();
            for (auto* b : buttons) b->setEnabled(false);
        }
    }
}

void ThreatsPage::setVirusTotalPending(int index) {
    auto it = indexToRow_.constFind(index);
    if (it == indexToRow_.constEnd()) return;
    if (auto* item = table_->item(it.value(), ColVirusTotal)) {
        item->setText(TR("Checking…"));
        item->setForeground(QColor(Theme::TEXT_SECONDARY));
    }
}

void ThreatsPage::setVirusTotalResult(int index, const QString& text,
                                      bool malicious,
                                      const QString& explanation)
{
    auto it = indexToRow_.constFind(index);
    if (it == indexToRow_.constEnd()) return;

    if (auto* item = table_->item(it.value(), ColVirusTotal)) {
        item->setText(text);
        item->setForeground(QColor(malicious ? Theme::SEV_CRIT : Theme::TEXT_SECONDARY));
        item->setToolTip(explanation.isEmpty() ? text : explanation);
    }
}

void ThreatsPage::quarantineAllCritical() {
    QList<int> targets;
    for (auto it = indexToRow_.constBegin(); it != indexToRow_.constEnd(); ++it) {
        auto* statusItem = table_->item(it.value(), ColStatus);
        if (!statusItem || statusItem->text() != TR("Pending")) continue;

        auto* sevWrap = table_->cellWidget(it.value(), ColSeverity);
        auto* sevLabel = sevWrap ? sevWrap->findChild<QLabel*>() : nullptr;
        if (sevLabel && sevLabel->text() == "CRIT") targets.append(it.key());
    }

    if (targets.isEmpty()) {
        QMessageBox::information(this, TR("Quarantine all critical"),
                                 "No pending critical threats.");
        return;
    }

    if (!ConfirmDialog::ask(this, TR("Quarantine all critical"),
            TR("Move %1 critical item(s) to quarantine?").arg(targets.size()),
            TR("Quarantine"), false)) {
        return;
    }

    for (int index : targets) emit actionRequested(index, 0);
}

void ThreatsPage::checkAllOnVirusTotal() {
    int queued = 0;
    for (auto it = indexToHash_.constBegin(); it != indexToHash_.constEnd(); ++it) {
        if (it.value().isEmpty()) continue;
        setVirusTotalPending(it.key());
        emit vtCheckRequested(it.key(), it.value());
        ++queued;
    }

    if (queued == 0) {
        QMessageBox::information(this, TR("VirusTotal"),
                                 "No hashed files to check.");
    }
}

void ThreatsPage::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    fitSourceColumn();
}

void ThreatsPage::fitSourceColumn() {
    if (!table_) return;

    const int available = table_->viewport()->width();
    if (available <= 0) return;

    // Уровень и действия не сжимаем: в них лежат виджеты, и обрезанная
    // кнопка — это не «поместилось», а сломанный интерфейс.
    const int fixed = table_->columnWidth(ColSeverity)
                    + table_->columnWidth(ColActions);

    // Остальное делим по минимумам и весам: сперва каждому его минимум,
    // потом остаток пропорционально. Пути длиннее всего, поэтому вес
    // у «Расположения» самый большой.
    struct Flexible { int column, minimum, weight; };
    const Flexible flexible[] = {
        { ColName,       130, 2 },
        { ColSource,     150, 5 },
        { ColVirusTotal,  90, 1 },
        { ColStatus,      90, 1 },
    };

    int minimums = 0, weights = 0;
    for (const Flexible& item : flexible) {
        minimums += item.minimum;
        weights  += item.weight;
    }

    const int free = available - fixed;
    if (free <= minimums) {
        // Места нет даже под минимумы — отдаём минимумы и живём
        // с горизонтальной прокруткой. Это честнее, чем колонка,
        // в которую не влезает ничего.
        for (const Flexible& item : flexible)
            table_->setColumnWidth(item.column, item.minimum);
        return;
    }

    int extra = free - minimums;
    int given = 0;
    for (int i = 0; i < 4; ++i) {
        const Flexible& item = flexible[i];
        // Последней колонке отдаём весь остаток: иначе из-за деления
        // нацело справа остаётся полоса в пару пикселей.
        const int share = (i == 3) ? (extra - given)
                                   : extra * item.weight / weights;
        given += share;
        table_->setColumnWidth(item.column, item.minimum + share);
    }
}

void ThreatsPage::updateEmptyState() {
    int n = table_->rowCount();
    bool empty = (n == 0);
    emptyBox_->setVisible(empty);
    table_->setVisible(!empty);

    quarantineAllBtn_->setEnabled(!empty);

    bool anyHash = false;
    for (auto it = indexToHash_.constBegin(); it != indexToHash_.constEnd(); ++it) {
        if (!it.value().isEmpty()) { anyHash = true; break; }
    }
    vtAllBtn_->setEnabled(anyHash);

    if (n > 0) {
        countBadge_->setText(QString::number(n));
        countBadge_->setVisible(true);
    } else {
        countBadge_->setVisible(false);
    }
}
