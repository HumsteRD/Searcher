#include "Page.h"

#include <QEvent>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QScrollBar>
#include <QVBoxLayout>

#include <algorithm>

namespace {
constexpr int kMaxContentWidth = 1160;
}

Page::Page(MainWindow* window, const QString& title, const QString& subtitle, QWidget* parent)
    : QWidget(parent), window_(window)
{
    setObjectName("page");
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    scroll_ = new QScrollArea(this);
    scroll_->setObjectName("pageScroll");
    scroll_->setWidgetResizable(true);
    scroll_->setFrameShape(QFrame::NoFrame);
    scroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    outer->addWidget(scroll_);

    // Колонка по центру: растягивается до kMaxContentWidth, дальше поля.
    auto* host = new QWidget();
    host->setObjectName("pageBody");
    auto* hostRow = new QHBoxLayout(host);
    hostRow->setContentsMargins(32, 24, 32, 32);
    hostRow->setSpacing(0);
    column_ = new QWidget(host);
    column_->setMaximumWidth(kMaxContentWidth);
    hostRow->addStretch(0);
    hostRow->addWidget(column_, 1);
    hostRow->addStretch(0);
    scroll_->setWidget(host);
    host->setAutoFillBackground(false);

    auto* col = new QVBoxLayout(column_);
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(Ui::Space::XL);

    // Заголовок и действия. В широком окне действия стоят справа от
    // заголовка, в узком — уходят строкой под него: иначе поле поиска и
    // кнопки сжимают пояснение в столбик из одного слова.
    header_ = new QBoxLayout(QBoxLayout::LeftToRight);
    header_->setSpacing(Ui::Space::L);
    auto* titles = new QVBoxLayout();
    titles->setSpacing(4);
    auto* t = Ui::makeLabel(title, "title");
    t->setWordWrap(true);
    titles->addWidget(t);
    subtitle_ = Ui::makeLabel(subtitle, "muted");
    subtitle_->setVisible(!subtitle.isEmpty());
    titles->addWidget(subtitle_);
    header_->addLayout(titles, 1);
    actionsBox_ = new QWidget(column_);
    actions_ = new QHBoxLayout(actionsBox_);
    actions_->setContentsMargins(0, 0, 0, 0);
    actions_->setSpacing(Ui::Space::S);
    header_->addWidget(actionsBox_, 0, Qt::AlignRight | Qt::AlignTop);
    actionsBox_->installEventFilter(this);
    col->addLayout(header_);

    body_ = new QVBoxLayout();
    body_->setSpacing(Ui::Space::L);
    col->addLayout(body_, 1);
}

void Page::setSubtitle(const QString& text) {
    subtitle_->setText(text);
    subtitle_->setVisible(!text.isEmpty());
}

void Page::resizeEvent(QResizeEvent* e) {
    QWidget::resizeEvent(e);
    relayoutHeader();
}

void Page::showEvent(QShowEvent* e) {
    QWidget::showEvent(e);
    relayoutHeader();
}

bool Page::eventFilter(QObject* o, QEvent* e) {
    // Действия появляются и прячутся по ходу работы (фильтр, поиск,
    // «Обезвредить все») — ширина их ряда меняется без изменения окна.
    if (o == actionsBox_ && e->type() == QEvent::LayoutRequest) relayoutHeader();
    return QWidget::eventFilter(o, e);
}

void Page::relayoutHeader() {
    if (!header_ || !actionsBox_) return;
    // Ширина колонки: окно минус поля страницы, не шире предела.
    const int available = std::min(kMaxContentWidth, width() - 64);
    const int actionsWidth = actionsBox_->sizeHint().width();
    // Заголовку с пояснением нужно хотя бы 360 px, чтобы текст читался.
    const bool stacked = actionsWidth > 0 && available < actionsWidth + Ui::Space::L + 360;
    const auto direction = stacked ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight;
    if (header_->direction() == direction) return;
    header_->setDirection(direction);
    header_->setAlignment(actionsBox_, stacked ? Qt::AlignLeft | Qt::AlignTop : Qt::AlignRight | Qt::AlignTop);
    header_->setSpacing(stacked ? Ui::Space::M : Ui::Space::L);
}

bool Page::scrollPageDown() {
    QScrollBar* bar = scroll_->verticalScrollBar();
    if (!bar || bar->value() >= bar->maximum()) return false;
    bar->setValue(std::min(bar->maximum(), bar->value() + scroll_->viewport()->height() - 48));
    return true;
}

void Page::scrollToTop() {
    if (QScrollBar* bar = scroll_->verticalScrollBar()) bar->setValue(0);
}

void Page::setScrollable(bool scrollable) {
    scroll_->setVerticalScrollBarPolicy(scrollable ? Qt::ScrollBarAsNeeded : Qt::ScrollBarAlwaysOff);
}
