#include "QuarantinePage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"
#include "../core/Quarantine.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFontMetrics>
#include <QFrame>
#include <QTableWidget>
#include <QHeaderView>
#include <QPushButton>
#include <QMessageBox>
#include <QShowEvent>
#include <QDesktopServices>
#include <QUrl>
#include "../ui/GradientButton.h"
#include "../ui/ConfirmDialog.h"
#include "../ui/Icons.h"

namespace {

GradientButton* cellButton(const QString& text, const QColor& from,
                           const QColor& to, QWidget* parent)
{
    auto* b = new GradientButton(text, GradientButton::Style::Outline, parent);
    b->setFixedHeight(Theme::Size::BTN_ROW);
    b->setGradient(from, to);
    b->setRadius(Theme::Radius::PILL);
        // Запас на жирное начертание: GradientButton рисует текст DemiBold,
    // а метрики берутся от обычного шрифта и занижают ширину.
    // ширина берётся из sizeHint() кнопки
    return b;
}

QString humanSize(uint64_t bytes) {
    if (bytes < 1024ull) return QString("%1 B").arg(bytes);
    if (bytes < 1024ull * 1024) return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
    if (bytes < 1024ull * 1024 * 1024)
        return QString("%1 MB").arg(bytes / (1024.0 * 1024), 0, 'f', 1);
    return QString("%1 GB").arg(bytes / (1024.0 * 1024 * 1024), 0, 'f', 2);
}

} // namespace

QuarantinePage::QuarantinePage(QWidget* parent) : QWidget(parent) {
    setStyleSheet("background: transparent;");

    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                             Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    root->setSpacing(12);

    // Заголовок + счётчик + кнопки
    QWidget* titleRow = new QWidget(this);
    titleRow->setStyleSheet("background: transparent;");
    QHBoxLayout* titleLay = new QHBoxLayout(titleRow);
    titleLay->setContentsMargins(0, 0, 0, 0);
    titleLay->setSpacing(12);
    titleLay->setAlignment(Qt::AlignVCenter);

    titleLay->addWidget(PageHelpers::pageTitle(TR("Quarantine"), this));

    countLabel_ = new QLabel("0", titleRow);
    countLabel_->setStyleSheet(QString(
        "background-color: rgba(245,158,11,30);"
        "color: %1;"
        "border: 1px solid rgba(245,158,11,80);"
        "border-radius: 11px;"
        "padding: 2px 12px;"
        "font-size: 12px;"
        "font-weight: 700;"
        "min-width: 20px;"
    ).arg(Theme::SEV_MED));
    countLabel_->setAlignment(Qt::AlignCenter);
    countLabel_->setVisible(false);
    titleLay->addWidget(countLabel_);

    titleLay->addStretch();

    auto* openBtn = new GradientButton(TR("Open folder"),
        GradientButton::Style::Outline, titleRow);
    openBtn->setFixedHeight(Theme::Size::BTN_HEADER);
    openBtn->setMinimumWidth(140);
    openBtn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    connect(openBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(
            QString::fromStdWString(Quarantine::Instance().Dir().wstring())));
    });
    titleLay->addWidget(openBtn);

    auto* refreshBtn = new GradientButton(TR("Refresh"),
        GradientButton::Style::Outline, titleRow);
    refreshBtn->setFixedHeight(Theme::Size::BTN_HEADER);
    refreshBtn->setMinimumWidth(120);
    refreshBtn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    connect(refreshBtn, &QPushButton::clicked, this, &QuarantinePage::refresh);
    titleLay->addWidget(refreshBtn);

    root->addWidget(titleRow);

    root->addWidget(PageHelpers::pageSubtitle(
        TR("Files moved here are isolated and obfuscated. "
           "You can restore them or delete permanently."), this));

    root->addSpacing(12);

    // Таблица
    tableCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* cardLay = new QVBoxLayout(tableCard_);
    cardLay->setContentsMargins(1, 1, 1, 1);

    table_ = new QTableWidget(tableCard_);
    table_->setColumnCount(ColumnCount);
    table_->setHorizontalHeaderLabels(
        {TR("File"), TR("Threat"), TR("Severity"), TR("Original location"), TR("Quarantined at"), TR("Size"), TR("Actions")});
    table_->verticalHeader()->setVisible(false);
    table_->setShowGrid(false);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    table_->setColumnWidth(ColName,     180);
    table_->setColumnWidth(ColThreat,   170);
    table_->setColumnWidth(ColSeverity,  90);
    table_->setColumnWidth(ColOrigin,   420);
    table_->setColumnWidth(ColDate,     150);
    table_->setColumnWidth(ColSize,      90);
    table_->setColumnWidth(ColActions,  120);
    // Тянутся все колонки, включая «Откуда»: растягивающуюся мышью
    // не подвинуть, а именно в ней лежит путь.
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(false);
    table_->horizontalHeader()->setMinimumSectionSize(60);
    table_->verticalHeader()->setDefaultSectionSize(Theme::Size::TABLE_ROW);
    table_->setWordWrap(false);
    // Середину, а не хвост: в конце пути имя файла.
    table_->setTextElideMode(Qt::ElideMiddle);
    table_->horizontalHeader()->setHighlightSections(false);

    table_->setStyleSheet(QString(
        "QTableWidget {"
        "  outline: none;"   // пунктирная рамка фокуса на текущей ячейке
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

    cardLay->addWidget(table_);
    root->addWidget(tableCard_, 1);

    // Пустое состояние — отдельная карточка, показывается вместо таблицы
    emptyCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* emptyLay = new QVBoxLayout(emptyCard_);
    emptyLay->setContentsMargins(40, 80, 40, 80);
    emptyLay->setAlignment(Qt::AlignCenter);
    emptyLay->setSpacing(12);

    QLabel* icon = new QLabel(emptyCard_);
    icon->setPixmap(Icons::fromResource("glyph-quarantine", 48,
                                        QColor(Theme::TEXT_MUTED)));
    icon->setStyleSheet("background: transparent; border: none;");
    icon->setAlignment(Qt::AlignCenter);
    emptyLay->addWidget(icon);

    QLabel* title = new QLabel(TR("Quarantine is empty"), emptyCard_);
    title->setStyleSheet(QString(
        "color: %1;"
        "font-size: 18px;"
        "font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY));
    title->setAlignment(Qt::AlignCenter);
    emptyLay->addWidget(title);

    QLabel* sub = new QLabel(
        "When you quarantine a threat, it will appear here.\n"
        "Quarantined items are safely stored and can be restored at any time.",
        emptyCard_);
    sub->setStyleSheet(QString(
        "color: %1; font-size: 13px;"
        "background: transparent; border: none;"
        "line-height: 1.6em;"
    ).arg(Theme::TEXT_SECONDARY));
    sub->setAlignment(Qt::AlignCenter);
    sub->setWordWrap(true);
    emptyLay->addWidget(sub);

    auto* emptyBtn = new GradientButton(TR("Open folder"),
                                        GradientButton::Style::Outline, emptyCard_);
    emptyBtn->setFixedHeight(Theme::Size::BTN_HEADER);
    emptyBtn->setMinimumWidth(160);
    emptyBtn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
    connect(emptyBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(
            QString::fromStdWString(Quarantine::Instance().Dir().wstring())));
    });

    QHBoxLayout* emptyBtnRow = new QHBoxLayout;
    emptyBtnRow->addStretch();
    emptyBtnRow->addWidget(emptyBtn);
    emptyBtnRow->addStretch();
    emptyLay->addLayout(emptyBtnRow);

    root->addWidget(emptyCard_, 1);

    refresh();
}

void QuarantinePage::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    refresh();
}

void QuarantinePage::refresh() {
    const auto items = Quarantine::Instance().List();

    table_->setRowCount(0);

    for (const auto& qi : items) {
        const int row = table_->rowCount();
        table_->insertRow(row);

        const QString id = QString::fromStdString(qi.id);
        const QString origPath = QString::fromStdWString(qi.originalPath);
        const QString name = QString::fromStdWString(qi.originalName);

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

        auto* nameItem = whiteItem(name);
        nameItem->setToolTip(origPath);
        table_->setItem(row, ColName, nameItem);

        table_->setItem(row, ColThreat,
                        mutedItem(QString::fromStdWString(qi.threatName)));

        const QString sev = QString::fromStdWString(qi.severity);
        auto* sevItem = new QTableWidgetItem(sev.isEmpty() ? "—" : sev);
        if      (sev == "CRIT") sevItem->setForeground(QColor(Theme::SEV_CRIT));
        else if (sev == "HIGH") sevItem->setForeground(QColor("#fb923c"));
        else if (sev == "MED")  sevItem->setForeground(QColor(Theme::SEV_MED));
        else                    sevItem->setForeground(QColor(Theme::TEXT_SECONDARY));
        table_->setItem(row, ColSeverity, sevItem);

        auto* originItem = mutedItem(origPath);
        originItem->setToolTip(origPath);
        table_->setItem(row, ColOrigin, originItem);

        table_->setItem(row, ColDate,
                        mutedItem(QString::fromStdString(qi.quarantinedAt)));
        table_->setItem(row, ColSize, mutedItem(humanSize(qi.size)));

        // Кнопки
        QWidget* wrap = new QWidget(table_);
        wrap->setStyleSheet("background: transparent;");
        QHBoxLayout* lay = new QHBoxLayout(wrap);
        lay->setContentsMargins(8, 0, 8, 0);
        lay->setSpacing(6);

        auto* restore = cellButton(TR("Restore"), QColor(Theme::ACCENT),
                                   QColor(Theme::ACCENT_GRAD_END), wrap);
        auto* del     = cellButton(TR("Delete"), QColor(Theme::SEV_HIGH),
                                   QColor(Theme::SEV_CRIT), wrap);

        connect(restore, &QPushButton::clicked, this, [this, id, origPath]() {
            restoreItem(id, origPath);
        });
        connect(del, &QPushButton::clicked, this, [this, id, name]() {
            deleteItem(id, name);
        });

        lay->addWidget(restore);
        lay->addWidget(del);
        lay->addStretch();

        table_->setCellWidget(row, ColActions, wrap);
// Ширину считаем по минимально необходимой: sizeHint до
        // раскладки её занижает, и после перевода кнопки налезали.
        wrap->adjustSize();
        table_->setColumnWidth(ColActions,
                               qMax(table_->columnWidth(ColActions),
                                    wrap->minimumSizeHint().width() + 24));
    }

    const bool empty = items.empty();
    tableCard_->setVisible(!empty);
    emptyCard_->setVisible(empty);

    countLabel_->setText(QString::number(items.size()));
    countLabel_->setVisible(!empty);
}

void QuarantinePage::restoreItem(const QString& id, const QString& originalPath) {
    if (QMessageBox::question(
            this, TR("Restore file"),
            "Restore this file to its original location?\n\n" + originalPath +
            "\n\nThe file was flagged as a threat — restore it only if you are "
            "sure it is safe.") != QMessageBox::Yes) {
        return;
    }

    // Возврат файла на место пишет туда, откуда его забрали, — в Program
    // Files или в системную папку. Прав интерфейса на это нет, поэтому
    // операцию выполняет помощник.
    emit restoreRequested(id);
}

void QuarantinePage::deleteItem(const QString& id, const QString& name) {
    if (QMessageBox::question(
            this, TR("Delete permanently"),
            "Permanently delete \"" + name + "\" from quarantine?\n\n"
            "This cannot be undone.") != QMessageBox::Yes) {
        return;
    }

    // Хранилище карантина лежит в %ProgramData% — читать оттуда может
    // кто угодно, а удалять только администратор.
    emit deleteRequested(id);
}
