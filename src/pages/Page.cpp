#include "Page.h"

#include <QHBoxLayout>
#include <QScrollArea>
#include <QVBoxLayout>

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

    auto* header = new QHBoxLayout();
    header->setSpacing(Ui::Space::L);
    auto* titles = new QVBoxLayout();
    titles->setSpacing(4);
    auto* t = Ui::makeLabel(title, "title");
    t->setWordWrap(true);
    titles->addWidget(t);
    subtitle_ = Ui::makeLabel(subtitle, "muted");
    subtitle_->setVisible(!subtitle.isEmpty());
    titles->addWidget(subtitle_);
    header->addLayout(titles, 1);
    actions_ = new QHBoxLayout();
    actions_->setSpacing(Ui::Space::S);
    header->addLayout(actions_);
    col->addLayout(header);

    body_ = new QVBoxLayout();
    body_->setSpacing(Ui::Space::L);
    col->addLayout(body_, 1);
}

void Page::setSubtitle(const QString& text) {
    subtitle_->setText(text);
    subtitle_->setVisible(!text.isEmpty());
}

void Page::setScrollable(bool scrollable) {
    scroll_->setVerticalScrollBarPolicy(scrollable ? Qt::ScrollBarAsNeeded : Qt::ScrollBarAlwaysOff);
}
