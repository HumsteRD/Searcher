#include "Sidebar.h"
#include "theme.h"
#include "ui/Icons.h"
#include "core/Lang.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QFrame>
#include <QPropertyAnimation>

namespace {

constexpr int kItemHeight = 40;
constexpr int kItemGap    = 4;
constexpr int kNavPadX    = 8;
constexpr int kIndicatorW = 3;
constexpr int kIndicatorH = 20;

QString itemQss(bool active) {
    return QString(
        "QPushButton {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid transparent;"
        "  border-radius: %3px;"
        "  text-align: left;"
        "  padding: 0 12px;"
        "  font-size: %4px;"
        "  font-weight: 500;"
        "}"
        "QPushButton:hover { background-color: %5; }"
    ).arg(active ? Theme::ACCENT_WASH : "transparent",
          active ? Theme::TEXT_PRIMARY : Theme::TEXT_SECONDARY)
     .arg(Theme::Radius::CONTROL)
     .arg(Theme::Font::CONTROL)
     .arg(active ? Theme::ACCENT_WASH : Theme::ROW_HOVER);
}

} // namespace

Sidebar::Sidebar(QWidget* parent)
    : QWidget(parent)
{
    setFixedWidth(Theme::Size::SIDEBAR);
    setObjectName("Sidebar");
    // Пятна фона просвечивают сквозь панель — заливка намеренно полупрозрачная.
    setStyleSheet(QString(
        "#Sidebar { background-color: %1; border-right: 1px solid %2; }"
    ).arg(Theme::SIDEBAR, "#1C2238"));

    layout_ = new QVBoxLayout(this);
    layout_->setContentsMargins(0, 18, 0, 16);
    layout_->setSpacing(0);

    // ─── Логотип ───
    QWidget* logoRow = new QWidget(this);
    logoRow->setStyleSheet("background: transparent;");
    QHBoxLayout* logoLay = new QHBoxLayout(logoRow);
    logoLay->setContentsMargins(16, 0, 16, Theme::Space::XL);
    logoLay->setSpacing(Theme::Space::XS);

    QLabel* mark = new QLabel(logoRow);
    // Маскот из identity-набора вместо обобщённого щита.
    mark->setPixmap(Icons::fromResource("icon", 24,
                                        QColor(Theme::ACCENT_TEXT)));
    mark->setStyleSheet("background: transparent; border: none;");
    logoLay->addWidget(mark);

    QLabel* wordmark = new QLabel("Threat Scanner", logoRow);
    wordmark->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::CARD));
    logoLay->addWidget(wordmark);
    logoLay->addStretch();

    layout_->addWidget(logoRow);

    // ─── Основная навигация ───
    QWidget* nav = new QWidget(this);
    nav->setStyleSheet("background: transparent;");
    QVBoxLayout* navLay = new QVBoxLayout(nav);
    navLay->setContentsMargins(kNavPadX, 0, kNavPadX, 0);
    navLay->setSpacing(kItemGap);

    addItem(static_cast<int>(Icons::Id::Shield),    "Home",       Home,       navLay);
    addItem(static_cast<int>(Icons::Id::Magnifier), "Scan",       Scan,       navLay);
    addItem(static_cast<int>(Icons::Id::Warning),   "Threats",    Threats,    navLay, true);
    addItem(static_cast<int>(Icons::Id::Box),       "Quarantine", Quarantine, navLay);
    addItem(static_cast<int>(Icons::Id::Flask),     "Behavior",   Behavior,   navLay);
    addItem(static_cast<int>(Icons::Id::List),      "Logs",       Logs,       navLay);
    addItem(static_cast<int>(Icons::Id::Refresh),   "History",    History,    navLay);
    addItem(static_cast<int>(Icons::Id::Check),     "Help",       Help,       navLay);

    layout_->addWidget(nav);
    layout_->addStretch();

    // ─── Settings прижат к низу ───
    QWidget* bottom = new QWidget(this);
    bottom->setStyleSheet("background: transparent;");
    QVBoxLayout* bottomLay = new QVBoxLayout(bottom);
    bottomLay->setContentsMargins(kNavPadX, 0, kNavPadX, 0);
    bottomLay->setSpacing(kItemGap);

    addItem(static_cast<int>(Icons::Id::Gear), "Settings", Settings, bottomLay);

    layout_->addWidget(bottom);

    // ─── Индикатор активного пункта ───
    // Отдельный виджет поверх панели: в QSS позиционирования нет,
    // поэтому двигаем его анимацией по координате.
    indicator_ = new QFrame(this);
    indicator_->setFixedSize(kIndicatorW, kIndicatorH);
    indicator_->setStyleSheet(QString(
        "background-color: %1; border: none;"
        "border-top-right-radius: %2px; border-bottom-right-radius: %2px;"
    ).arg(Theme::ACCENT_TEXT).arg(Theme::Radius::INDICATOR));
    indicator_->hide();

    indicatorAnim_ = new QPropertyAnimation(indicator_, "pos", this);
    indicatorAnim_->setDuration(180);
    indicatorAnim_->setEasingCurve(QEasingCurve::InOutQuad);

    updateItemStyles();
}

QPushButton* Sidebar::addItem(int iconId, const QString& key, int pageId,
                              QVBoxLayout* target, bool withBadge)
{
    QPushButton* btn = new QPushButton(TR(key), this);
    const QString text = key;
    btn->setFixedHeight(kItemHeight);
    btn->setCursor(Qt::PointingHandCursor);
    // Пунктирная рамка фокуса по умолчанию читалась как дефект вёрстки —
    // навигация фокус с клавиатуры не забирает.
    btn->setFocusPolicy(Qt::NoFocus);
    btn->setIconSize(QSize(18, 18));
    btn->setProperty("pageId", pageId);

    connect(btn, &QPushButton::clicked, this, [this, pageId]() {
        setActivePage(pageId);
        emit pageRequested(pageId);
    });

    target->addWidget(btn);

    Item item;
    item.button = btn;
    item.iconId = iconId;
    item.pageId = pageId;
    item.key    = key;

    if (withBadge) {
        // Бейдж лежит поверх кнопки справа: прижать элемент к правому краю
        // внутри самой кнопки средствами QSS нельзя.
        QLabel* badge = new QLabel(btn);
        badge->setAlignment(Qt::AlignCenter);
        badge->setStyleSheet(QString(
            "background-color: %1; color: %2;"
            "border: 1px solid %3; border-radius: %4px;"
            "font-size: %5px; font-weight: 600;"
        ).arg(Theme::SEV_CRIT_BG, Theme::SEV_CRIT, Theme::SEV_CRIT_BORDER)
         .arg(Theme::Radius::PILL)
         .arg(Theme::Font::OVERLINE));
        badge->setFixedHeight(20);
        badge->hide();
        item.badge = badge;
    }

    items_.append(item);
    return btn;
}

void Sidebar::setThreatCount(int count) {
    for (const Item& it : items_) {
        if (!it.badge) continue;

        if (count <= 0) {
            it.badge->hide();
            continue;
        }

        it.badge->setText(count > 99 ? "99+" : QString::number(count));
        it.badge->adjustSize();

        const int w = qMax(24, it.badge->width() + 8);
        it.badge->setFixedWidth(w);
        it.badge->move(it.button->width() - w - 12,
                       (it.button->height() - it.badge->height()) / 2);
        it.badge->show();
        it.badge->raise();
    }
}

void Sidebar::retranslate() {
    for (const Item& it : items_) it.button->setText(TR(it.key));
}

void Sidebar::setActivePage(int page) {
    const bool animate = indicator_->isVisible();
    activePage_ = page;
    updateItemStyles();
    moveIndicatorTo(page, animate);
}

void Sidebar::moveIndicatorTo(int pageId, bool animate) {
    for (const Item& it : items_) {
        if (it.pageId != pageId) continue;

        const QPoint btnPos = it.button->mapTo(this, QPoint(0, 0));
        const QPoint target(0, btnPos.y() + (kItemHeight - kIndicatorH) / 2);

        if (animate) {
            indicatorAnim_->stop();
            indicatorAnim_->setStartValue(indicator_->pos());
            indicatorAnim_->setEndValue(target);
            indicatorAnim_->start();
        } else {
            indicator_->move(target);
        }

        indicator_->show();
        indicator_->raise();
        return;
    }
}

void Sidebar::updateItemStyles() {
    for (const Item& it : items_) {
        const bool active = (it.pageId == activePage_);

        it.button->setStyleSheet(itemQss(active));
        it.button->setIcon(Icons::icon(
            static_cast<Icons::Id>(it.iconId), 18,
            QColor(active ? Theme::ACCENT_TEXT : Theme::TEXT_SECONDARY)));
    }
}
