#include "HistoryPage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"
#include "../core/ScanHistory.h"
#include "../ui/GradientButton.h"
#include "../ui/ConfirmDialog.h"
#include "../ui/Icons.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QFrame>
#include <QShowEvent>
#include <QFileDialog>
#include <QFile>
#include <QLocale>
#include <QMessageBox>

namespace {

QString formatDuration(int ms) {
    const int total = ms / 1000;
    if (total >= 60) {
        return QString("%1 %2 %3 %4").arg(total / 60).arg(TR("min"))
                   .arg(total % 60).arg(TR("s"));
    }
    return QString("%1 %2").arg(total).arg(TR("s"));
}

} // namespace

HistoryPage::HistoryPage(QWidget* parent) : QWidget(parent) {
    setStyleSheet("background: transparent;");

    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                             Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    root->setSpacing(Theme::Space::S);

    QWidget* titleRow = new QWidget(this);
    titleRow->setStyleSheet("background: transparent;");
    QHBoxLayout* titleLay = new QHBoxLayout(titleRow);
    titleLay->setContentsMargins(0, 0, 0, 0);
    titleLay->setSpacing(Theme::Space::S);
    titleLay->addWidget(PageHelpers::pageTitle(TR("History"), this));
    titleLay->addStretch();

    auto* clearBtn = new GradientButton(TR("Clear history"),
                                        GradientButton::Style::Outline, titleRow);
    clearBtn->setFixedHeight(Theme::Size::BTN_HEADER);
    clearBtn->setMinimumWidth(150);
    clearBtn->setGradient(QColor(Theme::SEV_HIGH), QColor(Theme::SEV_CRIT));
    connect(clearBtn, &QPushButton::clicked, this, [this]() {
        if (!ConfirmDialog::ask(this, TR("Clear history"),
                TR("Delete all saved scan records? The scans themselves are "
                   "not affected — only this list."),
                TR("Clear history"), true)) {
            return;
        }
        ScanHistory::instance().clear();
        refresh();
    });
    titleLay->addWidget(clearBtn);

    root->addWidget(titleRow);
    root->addWidget(PageHelpers::pageSubtitle(
        TR("Past scans are kept between sessions. Open a report to see what "
           "each scan found."), this));
    root->addSpacing(Theme::Space::S);

    // ─── Таблица ───
    tableCard_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* cardLay = new QVBoxLayout(tableCard_);
    cardLay->setContentsMargins(1, 1, 1, 1);

    table_ = new QTableWidget(tableCard_);
    table_->setColumnCount(ColumnCount);
    table_->setHorizontalHeaderLabels({ TR("Date"), TR("Mode"), TR("Duration"),
                                        TR("Objects checked"), TR("Threats found"),
                                        TR("Actions") });
    table_->verticalHeader()->setVisible(false);
    table_->setShowGrid(false);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->setDefaultSectionSize(Theme::Size::TABLE_ROW);
    // Без этого QTableView переносит текст по словам, и дата в узкой
    // колонке встаёт в две строки, раздвигая всю таблицу.
    table_->setWordWrap(false);
    table_->setTextElideMode(Qt::ElideRight);
    table_->horizontalHeader()->setHighlightSections(false);

    // Ширина считается от заголовка, а не от значения: «Проверено
    // объектов» длиннее любого числа, которое под ним стоит, и при
    // ширине по содержимому подпись обрезается с обеих сторон.
    table_->setColumnWidth(ColDate,     180);
    table_->setColumnWidth(ColMode,     120);
    table_->setColumnWidth(ColDuration, 140);
    table_->setColumnWidth(ColObjects,  200);
    table_->setColumnWidth(ColThreats,  200);
    table_->setColumnWidth(ColActions,  170);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(false);
    table_->horizontalHeader()->setMinimumSectionSize(60);

    table_->setStyleSheet(QString(
        "QTableWidget {"
        "  outline: none;"   // пунктирная рамка фокуса на текущей ячейке
        "  background-color: transparent; color: %1; border: none;"
        "  gridline-color: transparent; font-size: %6px;"
        "  selection-background-color: %5; selection-color: %1;"
        "}"
        "QTableWidget::item { padding: 0 16px; border-bottom: 1px solid %2; }"
        "QTableWidget::item:hover { background-color: %7; }"
        "QHeaderView::section {"
        "  background-color: %4; color: %3; font-weight: 600;"
        "  font-size: %8px; padding: 0 16px; height: %9px;"
        "  border: none; border-bottom: 1px solid %10;"
        "}"
    ).arg(Theme::TEXT_PRIMARY, Theme::BORDER_DIVIDER, Theme::TEXT_MUTED,
          Theme::SUNKEN, Theme::ROW_SELECTED)
     .arg(Theme::Font::BODY).arg(Theme::ROW_HOVER)
     .arg(Theme::Font::OVERLINE).arg(Theme::Size::TABLE_HEADER)
     .arg(Theme::BORDER_CARD));

    cardLay->addWidget(table_);
    root->addWidget(tableCard_, 1);

    // ─── Пустое состояние ───
    emptyBox_ = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* emptyLay = new QVBoxLayout(emptyBox_);
    emptyLay->setContentsMargins(40, 72, 40, 72);
    emptyLay->setAlignment(Qt::AlignCenter);
    emptyLay->setSpacing(Theme::Space::S);

    QLabel* icon = new QLabel(emptyBox_);
    icon->setPixmap(Icons::fromResource("glyph-files", 48,
                                        QColor(Theme::TEXT_MUTED)));
    icon->setAlignment(Qt::AlignCenter);
    icon->setStyleSheet("background: transparent; border: none;");
    emptyLay->addWidget(icon);

    QLabel* title = new QLabel(TR("No scans yet"), emptyBox_);
    title->setAlignment(Qt::AlignCenter);
    title->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::CARD));
    emptyLay->addWidget(title);

    QLabel* sub = new QLabel(
        TR("Once you run a scan, its result is saved here."), emptyBox_);
    sub->setAlignment(Qt::AlignCenter);
    sub->setWordWrap(true);
    sub->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::CONTROL));
    emptyLay->addWidget(sub);

    root->addWidget(emptyBox_, 1);

    refresh();
}

void HistoryPage::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    refresh();
    fitColumns();
}

void HistoryPage::fitColumns() {
    const int available = table_->viewport()->width();
    if (available <= 0) return;

    QFont header = table_->horizontalHeader()->font();
    header.setWeight(QFont::DemiBold);
    header.setPixelSize(Theme::Font::OVERLINE);
    const QFontMetrics metrics(header);

    QFont body = table_->font();
    body.setPixelSize(Theme::Font::BODY);
    const QFontMetrics bodyMetrics(body);

    // Минимум — по самому широкому из того, что в колонке стоит:
    // заголовку и содержимому. По одному заголовку считать нельзя:
    // «Дата» короче самой даты, и она переносилась на вторую строку.
    auto minimumFor = [&](int column) {
        int width = metrics.horizontalAdvance(
            table_->horizontalHeaderItem(column)->text());

        for (int row = 0; row < table_->rowCount(); ++row) {
            if (auto* item = table_->item(row, column))
                width = qMax(width, bodyMetrics.horizontalAdvance(item->text()));
        }
        return width + 36;
    };

    // Веса: датам и числам нужно больше воздуха, чем режиму.
    const int weights[ColumnCount] = { 2, 1, 1, 2, 2, 0 };

    int minimums = 0, weightSum = 0;
    for (int column = 0; column < ColumnCount; ++column) {
        minimums += (column == ColActions) ? table_->columnWidth(ColActions)
                                           : minimumFor(column);
        weightSum += weights[column];
    }

    int extra = available - minimums;
    if (extra < 0) extra = 0;

    int given = 0;
    for (int column = 0; column < ColumnCount; ++column) {
        if (column == ColActions) continue;   // ширина под кнопки уже своя

        // Последней растягиваемой колонке отдаём остаток целиком, иначе
        // от деления нацело справа остаётся полоса в пару пикселей.
        const bool last = (column == ColThreats);
        const int share = last ? (extra - given)
                               : extra * weights[column] / weightSum;
        given += share;
        table_->setColumnWidth(column, minimumFor(column) + share);
    }
}

void HistoryPage::refresh() {
    // Служба пишет свои результаты в общий файл и о нашей истории не
    // знает — забираем их при каждом открытии страницы.
    ScanHistory::instance().importServiceScans();

    const auto& records = ScanHistory::instance().records();
    table_->setRowCount(0);

    // Подписи в шапке стоят по центру, поэтому и значения ставим по
    // центру: иначе колонка визуально не совпадает со своим заголовком.
    // Дата — исключение: она левый край таблицы и читается как список.
    auto mutedItem = [](const QString& t) {
        auto* it = new QTableWidgetItem(t);
        it->setForeground(QColor(Theme::TEXT_SECONDARY));
        it->setTextAlignment(Qt::AlignCenter);
        return it;
    };

    for (int i = 0; i < records.size(); ++i) {
        const ScanRecord& r = records[i];
        const int row = table_->rowCount();
        table_->insertRow(row);

        auto* date = new QTableWidgetItem(
            r.when.toString("yyyy-MM-dd  HH:mm"));
        date->setForeground(QColor(Theme::TEXT_PRIMARY));
        table_->setItem(row, ColDate, date);

        table_->setItem(row, ColMode, mutedItem(TR(r.mode)));
        table_->setItem(row, ColDuration, mutedItem(formatDuration(r.durationMs)));
        table_->setItem(row, ColObjects,
                        mutedItem(QLocale().toString(r.objectsScanned)));

        QString threats = QString::number(r.totalThreats);
        if (r.criticalThreats > 0) {
            threats += "  ·  " + QString::number(r.criticalThreats) + " "
                     + TR("critical");
        }
        auto* th = new QTableWidgetItem(threats);
        th->setTextAlignment(Qt::AlignCenter);
        th->setForeground(QColor(r.criticalThreats > 0 ? Theme::SEV_CRIT
                                : r.totalThreats > 0   ? Theme::SEV_HIGH
                                                       : Theme::OK));
        table_->setItem(row, ColThreats, th);

        QWidget* wrap = new QWidget(table_);
        wrap->setStyleSheet("background: transparent;");
        QHBoxLayout* lay = new QHBoxLayout(wrap);
        lay->setContentsMargins(8, 0, 8, 0);
        lay->setSpacing(6);

        auto addButton = [&](const QString& text, auto&& handler) {
            auto* btn = new GradientButton(text, GradientButton::Style::Outline, wrap);
            btn->setFixedHeight(Theme::Size::BTN_ROW);
            btn->setRadius(Theme::Radius::PILL);
            btn->setGradient(QColor(Theme::ACCENT), QColor(Theme::ACCENT_GRAD_END));
            btn->setMinimumWidth(btn->fontMetrics().horizontalAdvance(text) + 34);
            connect(btn, &QPushButton::clicked, this, handler);
            lay->addWidget(btn);
        };

        addButton(TR("Export"), [this, i]() { exportRecord(i); });

        // Кнопку отчёта показываем, только если файл на месте: старые
        // отчёты вытесняются, и мёртвая кнопка врала бы о наличии данных.
        if (!r.reportPath.isEmpty() && QFile::exists(r.reportPath)) {
            const QString path = r.reportPath;
            addButton(TR("Behavior"),
                      [this, path]() { emit behaviourReportRequested(path); });
        }

        lay->addStretch();
        table_->setCellWidget(row, ColActions, wrap);

        wrap->adjustSize();
        table_->setColumnWidth(ColActions,
                               qMax(table_->columnWidth(ColActions),
                                    wrap->minimumSizeHint().width() + 24));
    }

    const bool empty = records.isEmpty();
    tableCard_->setVisible(!empty);
    emptyBox_->setVisible(empty);

    // Кнопки могли раздвинуть свою колонку — остальные должны отдать место.
    fitColumns();
}

void HistoryPage::exportRecord(int index) {
    const auto& records = ScanHistory::instance().records();
    if (index < 0 || index >= records.size()) return;

    const ScanRecord& r = records[index];
    const QString suggested =
        "threat-scan-" + r.when.toString("yyyyMMdd-HHmmss") + ".txt";

    const QString path = QFileDialog::getSaveFileName(
        this, TR("Save report"), suggested, "Text (*.txt)");
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, TR("Save report"),
                             TR("Could not write the file."));
        return;
    }
    f.write(ScanHistory::instance().exportText(r).toUtf8());
}
