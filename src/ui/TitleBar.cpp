#include "TitleBar.h"
#include "Icons.h"
#include "../theme.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QStyle>

namespace {

// Кнопки окна: 46×56, без скруглений — они прижаты к краю окна.
// У «закрыть» своя подсветка, остальные подсвечиваются нейтрально.
QString systemButtonQss(bool danger) {
    return QString(
        "QPushButton {"
        "  background-color: transparent;"
        "  border: none;"
        "  border-radius: 0;"
        "  padding: 0;"
        "}"
        "QPushButton:hover  { background-color: %1; }"
        "QPushButton:pressed { background-color: %2; }"
        "QPushButton[sysHover=\"true\"] { background-color: %1; }"
    ).arg(danger ? "#C0334A" : "#181D30",
          danger ? "#A62A3E" : "#232A44");
}

} // namespace

TitleBar::TitleBar(QWidget* parent)
    : QWidget(parent)
{
    setFixedHeight(Theme::Size::TITLEBAR);
    setStyleSheet(QString(
        "TitleBar { background: transparent; border-bottom: 1px solid %1; }"
    ).arg("#171C2E"));

    QHBoxLayout* lay = new QHBoxLayout(this);
    lay->setContentsMargins(Theme::Size::PAGE_PAD_X, 0, 0, 0);
    lay->setSpacing(Theme::Space::XS);

    auto crumb = [this](const QString& text, const char* color, int weight) {
        QLabel* l = new QLabel(text, this);
        l->setStyleSheet(QString(
            "color: %1; font-size: %2px; font-weight: %3;"
            "background: transparent; border: none;"
        ).arg(color).arg(Theme::Font::OVERLINE).arg(weight));
        return l;
    };

    lay->addWidget(crumb("Threat Scanner", Theme::TEXT_MUTED, 400));
    lay->addWidget(crumb("/", "#3A4160", 400));

    pageLabel_ = crumb("Home", Theme::TEXT_SECONDARY, 500);
    lay->addWidget(pageLabel_);

    lay->addStretch();

    minBtn_   = makeSystemButton(static_cast<int>(Icons::Id::WinMinimize), false);
    maxBtn_   = makeSystemButton(static_cast<int>(Icons::Id::WinMaximize), false);
    closeBtn_ = makeSystemButton(static_cast<int>(Icons::Id::WinClose),    true);

    connect(minBtn_,   &QPushButton::clicked, this, &TitleBar::minimizeRequested);
    connect(maxBtn_,   &QPushButton::clicked, this, &TitleBar::maximizeRequested);
    connect(closeBtn_, &QPushButton::clicked, this, &TitleBar::closeRequested);

    lay->addWidget(minBtn_);
    lay->addWidget(maxBtn_);
    lay->addWidget(closeBtn_);
}

QPushButton* TitleBar::makeSystemButton(int iconId, bool danger) {
    QPushButton* b = new QPushButton(this);
    b->setFixedSize(46, Theme::Size::TITLEBAR);
    b->setFocusPolicy(Qt::NoFocus);
    b->setCursor(Qt::ArrowCursor);
    b->setIcon(Icons::icon(static_cast<Icons::Id>(iconId), 16,
                           QColor(Theme::TEXT_SECONDARY)));
    b->setIconSize(QSize(16, 16));
    b->setStyleSheet(systemButtonQss(danger));
    b->setProperty("sysHover", false);
    return b;
}

void TitleBar::setPageName(const QString& page) {
    pageLabel_->setText(page);
}

void TitleBar::setMaximizeHovered(bool hovered) {
    maxBtn_->setProperty("sysHover", hovered);
    maxBtn_->style()->unpolish(maxBtn_);
    maxBtn_->style()->polish(maxBtn_);
}

void TitleBar::setMaximized(bool maximized) {
    // «Восстановить» рисуем той же рамкой, но меньшего размера —
    // отдельной иконки в наборе нет, а смысл читается.
    maxBtn_->setIconSize(maximized ? QSize(13, 13) : QSize(16, 16));
}
