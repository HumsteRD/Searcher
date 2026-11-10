#include "Shell.h"
#include "../app/Lang.h"

#include <QApplication>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QHelpEvent>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QToolTip>
#include <QVBoxLayout>

namespace Ui {

// ─── TitleBar ───

TitleBar::TitleBar(QWidget* parent) : QWidget(parent) {
    setObjectName("titleBar");
    setAttribute(Qt::WA_StyledBackground, true);
    setFixedHeight(40);

    auto* row = new QHBoxLayout(this);
    row->setContentsMargins(14, 0, 0, 0);
    row->setSpacing(10);

    auto* logo = new QLabel(this);
    logo->setPixmap(Icons::logo(18));
    logo->setFixedSize(18, 18);
    row->addWidget(logo);

    auto* name = new QLabel("Threat Scanner", this);
    name->setObjectName("appName");
    row->addWidget(name);
    row->addStretch(1);

    min_ = new IconButton(Icons::Id::WinMinimize, TR("Minimize"), this, 40);
    max_ = new IconButton(Icons::Id::WinMaximize, TR("Maximize"), this, 40);
    close_ = new IconButton(Icons::Id::WinClose, TR("Close"), this, 40);
    for (IconButton* b : { min_, max_, close_ }) {
        b->setFixedSize(46, 40);
        b->setFocusPolicy(Qt::NoFocus);
        row->addWidget(b);
    }
    close_->setDanger(true);

    connect(min_, &QAbstractButton::clicked, this, &TitleBar::minimizeRequested);
    connect(max_, &QAbstractButton::clicked, this, &TitleBar::maximizeRequested);
    connect(close_, &QAbstractButton::clicked, this, &TitleBar::closeRequested);
}

void TitleBar::setMaximized(bool maximized) {
    max_->setIconId(maximized ? Icons::Id::WinRestore : Icons::Id::WinMaximize);
    max_->setToolTip(maximized ? TR("Restore") : TR("Maximize"));
}

void TitleBar::setMaximizeHovered(bool hovered) {
    max_->setForcedHover(hovered);
}

// ─── Sidebar ───

namespace {
constexpr int kItemH = 38;
constexpr int kTop = 12;
}

Sidebar::Sidebar(QWidget* parent) : QWidget(parent) {
    setObjectName("sidebar");
    setAttribute(Qt::WA_StyledBackground, true);
    setMouseTracking(true);
    setCompact(false);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void Sidebar::setItems(const QList<Item>& items) {
    items_ = items;
    update();
}

void Sidebar::setActive(int id) {
    active_ = id;
    update();
}

void Sidebar::setBadge(int id, int count, const QString& tone) {
    badges_[id] = { count, tone };
    update();
}

void Sidebar::setCompact(bool compact) {
    compact_ = compact;
    setFixedWidth(compact ? 64 : 232);
    update();
}

void Sidebar::setFooter(const QString& line1, const QString& line2) {
    footer1_ = line1;
    footer2_ = line2;
    update();
}

QRect Sidebar::itemRect(int index) const {
    int topCount = 0, bottomCount = 0;
    for (const Item& it : items_) (it.bottom ? bottomCount : topCount)++;
    const int x = 10, w = width() - 20;
    int topIndex = 0, bottomIndex = 0;
    for (int i = 0; i < items_.size(); ++i) {
        if (!items_[i].bottom) {
            if (i == index) return QRect(x, kTop + topIndex * (kItemH + 2), w, kItemH);
            ++topIndex;
        } else {
            if (i == index) {
                const int footer = compact_ ? 16 : 64;
                const int y = height() - footer - (bottomCount - bottomIndex) * (kItemH + 2);
                return QRect(x, y, w, kItemH);
            }
            ++bottomIndex;
        }
    }
    return {};
}

int Sidebar::itemAt(const QPoint& p) const {
    for (int i = 0; i < items_.size(); ++i)
        if (itemRect(i).contains(p)) return i;
    return -1;
}

void Sidebar::mouseMoveEvent(QMouseEvent* e) {
    const int h = itemAt(e->position().toPoint());
    if (h != hover_) {
        hover_ = h;
        setCursor(h >= 0 ? Qt::PointingHandCursor : Qt::ArrowCursor);
        update();
    }
}

void Sidebar::mousePressEvent(QMouseEvent* e) {
    const int i = itemAt(e->position().toPoint());
    if (i >= 0 && e->button() == Qt::LeftButton) emit pageRequested(items_[i].id);
}

void Sidebar::leaveEvent(QEvent*) {
    hover_ = -1;
    update();
}

bool Sidebar::event(QEvent* e) {
    // В свёрнутом виде названий нет — подсказка по наведению.
    if (e->type() == QEvent::ToolTip && compact_) {
        auto* he = static_cast<QHelpEvent*>(e);
        const int i = itemAt(he->pos());
        if (i >= 0) QToolTip::showText(he->globalPos(), items_[i].label, this);
        else QToolTip::hideText();
        return true;
    }
    return QWidget::event(e);
}

void Sidebar::paintEvent(QPaintEvent* e) {
    QWidget::paintEvent(e);
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();

    for (int i = 0; i < items_.size(); ++i) {
        const Item& it = items_[i];
        const QRect r = itemRect(i);
        const bool active = it.id == active_;
        const bool hover = i == hover_;

        if (active || hover) {
            p.setPen(Qt::NoPen);
            p.setBrush(active ? c.accentSoft : c.hover);
            p.drawRoundedRect(r, 8, 8);
        }
        if (active) {
            p.setBrush(c.accent);
            p.drawRoundedRect(QRectF(r.left() - 6, r.top() + 10, 3, r.height() - 20), 1.5, 1.5);
        }

        const QColor fg = active ? c.accentText : (hover ? c.text : c.text2);
        const int iconX = compact_ ? r.left() + (r.width() - 20) / 2 : r.left() + 12;
        p.drawPixmap(iconX, r.top() + (r.height() - 20) / 2, Icons::pixmap(it.icon, 20, fg));

        const Badge b = badges_.value(it.id);
        if (!compact_) {
            p.setPen(active ? c.accentText : (hover ? c.text : c.text2));
            p.setFont(Font::make(Font::Body, active ? QFont::DemiBold : QFont::Medium));
            const int textX = r.left() + 44;
            const int badgeW = b.count > 0 ? 28 : 0;
            const QFontMetrics fm(p.font());
            p.drawText(QRect(textX, r.top(), r.width() - 52 - badgeW, r.height()),
                       Qt::AlignVCenter | Qt::AlignLeft,
                       fm.elidedText(it.label, Qt::ElideRight, r.width() - 52 - badgeW));
        }
        if (b.count > 0) {
            const Tone t = Theme::instance().tone(b.tone);
            const QString txt = b.count > 99 ? "99+" : QString::number(b.count);
            const QFont bf = Font::make(Font::Micro, QFont::DemiBold);
            const int bw = std::max(20, QFontMetrics(bf).horizontalAdvance(txt) + 10);
            const QRect br = compact_ ? QRect(r.right() - bw - 2, r.top() + 2, bw, 16)
                                      : QRect(r.right() - bw - 8, r.center().y() - 9, bw, 18);
            p.setPen(Qt::NoPen);
            p.setBrush(t.solid);
            p.drawRoundedRect(br, 9, 9);
            p.setPen(c.textOnAccent);
            p.setFont(bf);
            p.drawText(br, Qt::AlignCenter, txt);
        }
    }

    if (!compact_ && !footer1_.isEmpty()) {
        const QRect fr(22, height() - 56, width() - 44, 44);
        p.setPen(c.text3);
        p.setFont(Font::make(Font::Caption));
        const QFontMetrics fm(p.font());
        p.drawText(QRect(fr.left(), fr.top(), fr.width(), 18), Qt::AlignLeft | Qt::AlignVCenter,
                   fm.elidedText(footer1_, Qt::ElideRight, fr.width()));
        p.drawText(QRect(fr.left(), fr.top() + 18, fr.width(), 18), Qt::AlignLeft | Qt::AlignVCenter,
                   fm.elidedText(footer2_, Qt::ElideRight, fr.width()));
    }
}

// ─── Toast ───

QList<QPointer<Toast>>& Toast::active() {
    static QList<QPointer<Toast>> list;
    return list;
}

Toast::Toast(QWidget* host, const QString& tone) : QFrame(host), tone_(tone) {
    setAttribute(Qt::WA_DeleteOnClose);
    host->installEventFilter(this);
    timer_.setSingleShot(true);
    connect(&timer_, &QTimer::timeout, this, &QWidget::close);
}

void Toast::show(QWidget* host, const QString& tone, const QString& title, const QString& text,
                 const QString& action, std::function<void()> onAction, int ms)
{
    if (!host) return;
    auto* t = new Toast(host, tone);
    auto* row = new QHBoxLayout(t);
    row->setContentsMargins(16, 12, 10, 12);
    row->setSpacing(12);

    ColorRole role = ColorRole::AccentText;
    Icons::Id icon = Icons::Id::Info;
    if (tone == "OK")   { role = ColorRole::Ok; icon = Icons::Id::ShieldCheck; }
    if (tone == "CRIT") { role = ColorRole::Danger; icon = Icons::Id::ShieldAlert; }
    if (tone == "MED" || tone == "HIGH") { role = ColorRole::Warn; icon = Icons::Id::Alert; }
    row->addWidget(new IconLabel(icon, 20, role), 0, Qt::AlignTop);

    auto* col = new QVBoxLayout();
    col->setSpacing(2);
    auto* tl = makeLabel(title, "subheading");
    tl->setWordWrap(true);
    col->addWidget(tl);
    if (!text.isEmpty()) col->addWidget(makeLabel(text, "muted"));
    row->addLayout(col, 1);

    if (!action.isEmpty()) {
        auto* b = new Button(action, Button::Variant::Secondary);
        b->setSize(Button::Size::Small);
        connect(b, &QPushButton::clicked, t, [t, onAction]() {
            if (onAction) onAction();
            t->close();
        });
        row->addWidget(b, 0, Qt::AlignVCenter);
    }
    auto* x = new IconButton(Icons::Id::Close, TR("Close"), t, 28);
    connect(x, &QAbstractButton::clicked, t, &QWidget::close);
    row->addWidget(x, 0, Qt::AlignTop);

    t->setFixedWidth(std::min(420, host->width() - 48));
    t->adjustSize();
    active().removeAll(QPointer<Toast>());
    // Больше трёх уведомлений сразу — шум: старые уходят.
    while (active().size() >= 3) {
        if (active().first()) active().first()->close();
        active().removeFirst();
    }
    active().append(t);
    t->place();
    t->QFrame::show();
    t->raise();
    if (ms > 0) t->timer_.start(ms);
}

void Toast::place() {
    auto* host = parentWidget();
    if (!host) return;
    int y = host->height() - 24;
    for (int i = active().size() - 1; i >= 0; --i) {
        Toast* t = active()[i];
        if (!t) continue;
        y -= t->height();
        t->move(host->width() - t->width() - 24, y);
        y -= 10;
    }
}

bool Toast::eventFilter(QObject* o, QEvent* e) {
    if (o == parentWidget() && e->type() == QEvent::Resize) place();
    return QFrame::eventFilter(o, e);
}

void Toast::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    // Тень рисуем сами: QGraphicsEffect размывает текст.
    for (int i = 6; i >= 1; --i) {
        QColor s(0, 0, 0, c.dark ? 18 : 8);
        p.setPen(Qt::NoPen);
        p.setBrush(s);
        p.drawRoundedRect(QRectF(rect()).adjusted(-i + 6, -i + 8, i - 6, i - 4), 12 + i, 12 + i);
    }
    p.setPen(QPen(c.borderStrong, 1));
    p.setBrush(c.raised);
    p.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 12, 12);
}

// ─── Modal ───

Modal::Modal(QWidget* host, const QString& title, const QString& text) : QWidget(host) {
    setAttribute(Qt::WA_DeleteOnClose);
    setFocusPolicy(Qt::StrongFocus);
    host->installEventFilter(this);

    card_ = new QFrame(this);
    card_->setObjectName("modal");
    auto* col = new QVBoxLayout(card_);
    col->setContentsMargins(24, 22, 24, 20);
    col->setSpacing(12);

    header_ = new QHBoxLayout();
    header_->setSpacing(12);
    auto* tl = makeLabel(title, "heading");
    tl->setWordWrap(true);
    header_->addWidget(tl, 1);
    col->addLayout(header_);

    content_ = new QVBoxLayout();
    content_->setSpacing(10);
    if (!text.isEmpty()) content_->addWidget(makeLabel(text, "muted"));
    col->addLayout(content_);

    buttons_ = new QHBoxLayout();
    buttons_->setSpacing(8);
    buttons_->addStretch(1);
    col->addSpacing(6);
    col->addLayout(buttons_);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void Modal::setIcon(Icons::Id icon, ColorRole role) {
    if (!icon_) {
        icon_ = new IconLabel(icon, 20, role);
        icon_->setTile(true, 36);
        header_->insertWidget(0, icon_, 0, Qt::AlignTop);
    } else {
        icon_->set(icon, role);
    }
}

Button* Modal::addButton(const QString& text, Button::Variant variant, std::function<void()> onClick,
                         bool closes)
{
    auto* b = new Button(text, variant);
    buttons_->addWidget(b);
    // Enter нажимает основную кнопку. Опасную (удаление) — нет: её
    // подтверждают осознанно, мышью или Tab + пробел.
    if (variant == Button::Variant::Primary) default_ = b;
    connect(b, &QPushButton::clicked, this, [this, onClick, closes]() {
        if (closes) close();
        if (onClick) onClick();
    });
    return b;
}

void Modal::open() {
    place();
    show();
    raise();
    setFocus();
}

void Modal::close() {
    emit closed();
    QWidget::close();
}

void Modal::place() {
    auto* host = parentWidget();
    if (!host) return;
    setGeometry(host->rect());
    const int w = std::min(maxWidth_, width() - 48);
    card_->setFixedWidth(w);
    card_->adjustSize();
    // Высота — под эту ширину. sizeHint у раскладки с переносимым текстом
    // считается для «удобной» ширины и выходит с запасом: заголовок
    // повисал посреди пустой полосы, ниже своей иконки.
    int wanted = card_->layout() ? card_->layout()->totalHeightForWidth(w) : -1;
    if (wanted <= 0) wanted = card_->sizeHint().height();
    const int h = std::min(wanted, height() - 48);
    card_->setFixedHeight(h);
    card_->move((width() - w) / 2, std::max(24, (height() - h) / 2 - 20));
}

bool Modal::eventFilter(QObject* o, QEvent* e) {
    if (o == parentWidget() && e->type() == QEvent::Resize) place();
    return QWidget::eventFilter(o, e);
}

void Modal::keyPressEvent(QKeyEvent* e) {
    if (e->key() == Qt::Key_Escape) { close(); return; }
    if ((e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter) && default_) {
        default_->click();
        return;
    }
    QWidget::keyPressEvent(e);
}

void Modal::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.fillRect(rect(), QColor(0, 0, 0, pal().dark ? 140 : 90));
}

void Modal::confirm(QWidget* host, const QString& title, const QString& text, const QString& okText,
                    bool danger, std::function<void()> onOk)
{
    auto* m = new Modal(host, title, text);
    m->addButton(TR("Cancel"), Button::Variant::Secondary);
    m->addButton(okText, danger ? Button::Variant::Danger : Button::Variant::Primary, onOk);
    m->open();
}

void Modal::info(QWidget* host, const QString& title, const QString& text) {
    auto* m = new Modal(host, title, text);
    m->addButton(TR("OK"), Button::Variant::Primary);
    m->open();
}

} // namespace Ui
