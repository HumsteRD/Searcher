#include "Widgets.h"
#include "../app/Lang.h"

#include <QEnterEvent>
#include <QGridLayout>
#include <QLocale>
#include <QHBoxLayout>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QStyle>
#include <QVBoxLayout>

namespace Ui {

QColor color(ColorRole role) {
    const Palette& p = pal();
    switch (role) {
    case ColorRole::Text:       return p.text;
    case ColorRole::Text2:      return p.text2;
    case ColorRole::Text3:      return p.text3;
    case ColorRole::Accent:     return p.accent;
    case ColorRole::AccentText: return p.accentText;
    case ColorRole::OnAccent:   return p.textOnAccent;
    case ColorRole::Ok:         return p.okText;
    case ColorRole::Warn:       return p.warnText;
    case ColorRole::High:       return p.highText;
    case ColorRole::Danger:     return p.dangerText;
    case ColorRole::Low:        return p.lowText;
    }
    return p.text;
}

static QColor softFor(ColorRole role) {
    const Palette& p = pal();
    switch (role) {
    case ColorRole::Ok:     return p.okSoft;
    case ColorRole::Warn:   return p.warnSoft;
    case ColorRole::High:   return p.highSoft;
    case ColorRole::Danger: return p.dangerSoft;
    case ColorRole::Low:    return p.lowSoft;
    case ColorRole::Accent:
    case ColorRole::AccentText: return p.accentSoft;
    default:                return p.infoSoft;
    }
}

void setStyleProp(QWidget* w, const char* name, const QVariant& value) {
    if (!w) return;
    w->setProperty(name, value);
    w->style()->unpolish(w);
    w->style()->polish(w);
    w->update();
}

QLabel* makeLabel(const QString& text, const char* role, QWidget* parent) {
    auto* l = new QLabel(text, parent);
    l->setProperty("role", role);
    if (qstrcmp(role, "body") == 0 || qstrcmp(role, "muted") == 0 || qstrcmp(role, "caption") == 0)
        l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::NoTextInteraction);
    return l;
}

QFrame* makeDivider(QWidget* parent) {
    auto* f = new QFrame(parent);
    f->setProperty("divider", true);
    f->setFixedHeight(1);
    return f;
}

QString breakable(const QString& text) {
    QString out;
    out.reserve(text.size() + text.size() / 8);
    int run = 0;
    for (const QChar ch : text) {
        out += ch;
        if (ch.isSpace()) { run = 0; continue; }
        ++run;
        if (ch == '\\' || ch == '/' || ch == '_' || run >= 18) {
            out += QChar(0x200B);
            run = 0;
        }
    }
    return out;
}

void clearLayout(QLayout* layout) {
    if (!layout) return;
    while (QLayoutItem* item = layout->takeAt(0)) {
        if (QWidget* w = item->widget()) {
            w->hide();
            w->deleteLater();
        } else if (QLayout* sub = item->layout()) {
            clearLayout(sub);
        }
        delete item;
    }
}

// ─── FlowLayout ───

FlowLayout::FlowLayout(QWidget* parent, int hSpacing, int vSpacing)
    : QLayout(parent), hSpace_(hSpacing), vSpace_(vSpacing)
{
    setContentsMargins(0, 0, 0, 0);
}

FlowLayout::~FlowLayout() {
    while (QLayoutItem* item = takeAt(0)) delete item;
}

void FlowLayout::addItem(QLayoutItem* item) { items_.append(item); }

QLayoutItem* FlowLayout::takeAt(int index) {
    return index >= 0 && index < items_.size() ? items_.takeAt(index) : nullptr;
}

QSize FlowLayout::minimumSize() const {
    QSize size;
    for (const QLayoutItem* item : items_) size = size.expandedTo(item->minimumSize());
    const QMargins m = contentsMargins();
    return size + QSize(m.left() + m.right(), m.top() + m.bottom());
}

void FlowLayout::setGeometry(const QRect& rect) {
    QLayout::setGeometry(rect);
    doLayout(rect, false);
}

int FlowLayout::doLayout(const QRect& rect, bool testOnly) const {
    const QMargins m = contentsMargins();
    const QRect area = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom());
    int x = area.x(), y = area.y(), lineHeight = 0;
    for (QLayoutItem* item : items_) {
        if (item->widget() && !item->widget()->isVisibleTo(item->widget()->parentWidget())) continue;
        const QSize hint = item->sizeHint();
        int nextX = x + hint.width() + hSpace_;
        if (nextX - hSpace_ > area.right() + 1 && lineHeight > 0) {
            x = area.x();
            y += lineHeight + vSpace_;
            nextX = x + hint.width() + hSpace_;
            lineHeight = 0;
        }
        if (!testOnly) item->setGeometry(QRect(QPoint(x, y), hint));
        x = nextX;
        lineHeight = std::max(lineHeight, hint.height());
    }
    return y + lineHeight - rect.y() + m.bottom();
}

// ─── DropZone ───

DropZone::DropZone(const QString& text, QWidget* parent) : QWidget(parent), text_(text) {
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void DropZone::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    QPen pen(c.borderStrong, 1.2, Qt::DashLine);
    pen.setDashPattern({ 4, 4 });
    p.setPen(pen);
    p.setBrush(c.surfaceAlt);
    p.drawRoundedRect(QRectF(rect()).adjusted(1, 1, -1, -1), 10, 10);
    const QPixmap icon = Icons::pixmap(Icons::Id::Download, 20, c.text3);
    const QFont f = Font::make(Font::Control, QFont::Medium);
    const QFontMetrics fm(f);
    const int textW = std::min(fm.horizontalAdvance(text_), width() - 60);
    const int total = 20 + 10 + textW;
    const int x = (width() - total) / 2;
    p.drawPixmap(x, (height() - 20) / 2, icon);
    p.setPen(c.text2);
    p.setFont(f);
    p.drawText(QRect(x + 30, 0, textW, height()), Qt::AlignVCenter | Qt::AlignLeft,
               fm.elidedText(text_, Qt::ElideRight, textW));
}

// ─── Button ───

Button::Button(const QString& text, Variant variant, QWidget* parent)
    : QPushButton(text, parent), variant_(variant)
{
    setVariant(variant);
    setFocusPolicy(Qt::StrongFocus);
    connect(&Theme::instance(), &Theme::changed, this, &Button::refreshIcon);
}

void Button::setVariant(Variant v) {
    variant_ = v;
    const char* name = "secondary";
    switch (v) {
    case Variant::Primary: name = "primary"; break;
    case Variant::Ghost:   name = "ghost"; break;
    case Variant::Danger:  name = "danger"; break;
    case Variant::Link:    name = "link"; setCursor(Qt::PointingHandCursor); break;
    default: break;
    }
    setStyleProp(this, "variant", name);
    refreshIcon();
}

void Button::setSize(Size s) {
    size_ = s;
    setStyleProp(this, "size", s == Size::Small ? "small" : s == Size::Large ? "large" : "medium");
    refreshIcon();
}

void Button::setIconId(std::optional<Icons::Id> id) {
    icon_ = id;
    refreshIcon();
}

void Button::refreshIcon() {
    if (!icon_) { setIcon(QIcon()); return; }
    QColor c;
    switch (variant_) {
    case Variant::Primary:
    case Variant::Danger: c = pal().textOnAccent; break;
    case Variant::Ghost:  c = pal().text2; break;
    case Variant::Link:   c = pal().accentText; break;
    default:              c = pal().text; break;
    }
    const int sz = size_ == Size::Small ? 14 : 16;
    setIcon(Icons::icon(*icon_, sz, c, pal().textDisabled));
    setIconSize(QSize(sz, sz));
}

// ─── IconButton ───

IconButton::IconButton(Icons::Id id, const QString& tooltip, QWidget* parent, int box)
    : QAbstractButton(parent), id_(id), box_(box)
{
    setToolTip(tooltip);
    setAccessibleName(tooltip);
    setFixedSize(box, box);
    setFocusPolicy(Qt::TabFocus);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void IconButton::setIconId(Icons::Id id) {
    id_ = id;
    update();
}

void IconButton::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    const bool hot = (underMouse() || forcedHover_) && isEnabled();
    QColor iconColor = isEnabled() ? c.text2 : c.textDisabled;
    if (hot) {
        const QColor bg = danger_ ? c.danger : (isDown() ? c.pressed : c.hover);
        p.setPen(Qt::NoPen);
        p.setBrush(bg);
        p.drawRoundedRect(rect().adjusted(1, 1, -1, -1), Radius::Small, Radius::Small);
        iconColor = danger_ ? c.textOnAccent : c.text;
    }
    if (isChecked()) iconColor = c.accentText;
    const int icon = box_ >= 36 ? 20 : (box_ >= 28 ? 18 : 16);
    const QPixmap pm = Icons::pixmap(id_, icon, iconColor);
    p.drawPixmap((width() - icon) / 2, (height() - icon) / 2, pm);
}

// ─── Toggle ───

Toggle::Toggle(QWidget* parent) : QAbstractButton(parent) {
    setCheckable(true);
    setFixedSize(40, 22);
    setFocusPolicy(Qt::StrongFocus);
    setCursor(Qt::PointingHandCursor);
    anim_.setDuration(140);
    anim_.setEasingCurve(QEasingCurve::OutCubic);
    connect(&anim_, &QVariantAnimation::valueChanged, this, [this](const QVariant& v) {
        pos_ = v.toReal();
        update();
    });
    connect(this, &QAbstractButton::toggled, this, [this](bool on) {
        anim_.stop();
        anim_.setStartValue(pos_);
        anim_.setEndValue(on ? 1.0 : 0.0);
        anim_.start();
    });
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void Toggle::setCheckedNoAnim(bool on) {
    const bool blocked = blockSignals(true);
    setChecked(on);
    blockSignals(blocked);
    pos_ = on ? 1.0 : 0.0;
    update();
}

void Toggle::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    if (!isEnabled()) p.setOpacity(0.45);

    const QRectF track(0.5, 0.5, width() - 1.0, height() - 1.0);
    QColor off = c.borderStrong;
    QColor on = underMouse() ? c.accentHover : c.accent;
    QColor mix;
    mix.setRgbF(off.redF() + (on.redF() - off.redF()) * pos_,
                off.greenF() + (on.greenF() - off.greenF()) * pos_,
                off.blueF() + (on.blueF() - off.blueF()) * pos_);
    p.setPen(Qt::NoPen);
    p.setBrush(mix);
    p.drawRoundedRect(track, track.height() / 2, track.height() / 2);

    const qreal d = height() - 6.0;
    const qreal x = 3.0 + (width() - 6.0 - d) * pos_;
    p.setBrush(QColor(255, 255, 255));
    p.drawEllipse(QRectF(x, 3.0, d, d));

    if (hasFocus() && focusPolicy() != Qt::NoFocus) {
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(c.focus, 1.5));
        p.drawRoundedRect(track.adjusted(-0.0, -0.0, 0.0, 0.0), track.height() / 2, track.height() / 2);
    }
}

// ─── Pill ───

Pill::Pill(const QString& text, const QString& tone, QWidget* parent)
    : QWidget(parent), text_(text), tone_(tone)
{
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void Pill::set(const QString& text, const QString& tone) {
    text_ = text;
    tone_ = tone;
    updateGeometry();
    update();
}

QSize Pill::sizeHint() const {
    const QFontMetrics fm(Font::make(Font::Caption, QFont::DemiBold));
    return { fm.horizontalAdvance(text_) + (dot_ ? 26 : 16), 22 };
}

void Pill::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Tone t = Theme::instance().tone(tone_);
    const QRectF r(0, (height() - 22) / 2.0, width(), 22);
    p.setPen(Qt::NoPen);
    p.setBrush(t.background);
    p.drawRoundedRect(r, 6, 6);
    int x = 8;
    if (dot_) {
        p.setBrush(t.solid);
        p.drawEllipse(QRectF(x, r.center().y() - 3, 6, 6));
        x += 12;
    }
    p.setPen(t.text);
    p.setFont(Font::make(Font::Caption, QFont::DemiBold));
    p.drawText(QRectF(x, r.top(), width() - x - 6, r.height()), Qt::AlignVCenter | Qt::AlignLeft, text_);
}

// ─── ProgressBar ───

ProgressBar::ProgressBar(QWidget* parent) : QWidget(parent) {
    setFixedHeight(8);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    sweep_.setStartValue(0.0);
    sweep_.setEndValue(1.0);
    sweep_.setDuration(1400);
    sweep_.setLoopCount(-1);
    connect(&sweep_, &QVariantAnimation::valueChanged, this, qOverload<>(&QWidget::update));
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void ProgressBar::setValue(double fraction) {
    value_ = fraction;
    if (fraction < 0) {
        if (sweep_.state() != QAbstractAnimation::Running) sweep_.start();
    } else {
        sweep_.stop();
    }
    update();
}

void ProgressBar::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    const QRectF r(0, 0, width(), height());
    const qreal radius = height() / 2.0;
    p.setPen(Qt::NoPen);
    p.setBrush(c.hover.darker(c.dark ? 80 : 104));
    p.drawRoundedRect(r, radius, radius);

    p.setBrush(c.accent);
    if (value_ < 0) {
        const qreal t = sweep_.currentValue().toReal();
        const qreal seg = r.width() * 0.28;
        const qreal x = -seg + (r.width() + seg) * t;
        QPainterPath clip;
        clip.addRoundedRect(r, radius, radius);
        p.setClipPath(clip);
        p.drawRoundedRect(QRectF(x, 0, seg, r.height()), radius, radius);
    } else if (value_ > 0) {
        const qreal w = std::max(r.height(), r.width() * std::min(value_, 1.0));
        p.drawRoundedRect(QRectF(0, 0, w, r.height()), radius, radius);
    }
}

// ─── Spinner ───

Spinner::Spinner(int size, QWidget* parent) : QWidget(parent), size_(size) {
    setFixedSize(size, size);
    anim_.setStartValue(0.0);
    anim_.setEndValue(360.0);
    anim_.setDuration(900);
    anim_.setLoopCount(-1);
    connect(&anim_, &QVariantAnimation::valueChanged, this, qOverload<>(&QWidget::update));
}

void Spinner::setRunning(bool running) {
    if (running) anim_.start();
    else anim_.stop();
    setVisible(running);
}

void Spinner::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const qreal w = 2.0;
    const QRectF r(w, w, width() - 2 * w, height() - 2 * w);
    p.setPen(QPen(pal().hover.darker(pal().dark ? 70 : 110), w));
    p.drawEllipse(r);
    p.setPen(QPen(pal().accent, w, Qt::SolidLine, Qt::RoundCap));
    const int start = static_cast<int>(-anim_.currentValue().toReal() * 16);
    p.drawArc(r, start, 100 * 16);
}

// ─── Segmented ───

Segmented::Segmented(const QStringList& options, QWidget* parent)
    : QWidget(parent), options_(options)
{
    setMouseTracking(true);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setFocusPolicy(Qt::StrongFocus);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

QSize Segmented::sizeHint() const {
    const QFontMetrics fm(Font::make(Font::Control, QFont::DemiBold));
    int w = 6;
    for (const QString& o : options_) w += fm.horizontalAdvance(o) + 28;
    return { w, 34 };
}

void Segmented::setCurrent(int index) {
    if (index < 0 || index >= options_.size() || index == current_) return;
    current_ = index;
    update();
    emit currentChanged(index);
}

int Segmented::indexAt(const QPoint& pt) const {
    const QFontMetrics fm(Font::make(Font::Control, QFont::DemiBold));
    int x = 3;
    for (int i = 0; i < options_.size(); ++i) {
        const int w = fm.horizontalAdvance(options_[i]) + 28;
        if (pt.x() >= x && pt.x() < x + w) return i;
        x += w;
    }
    return -1;
}

void Segmented::mousePressEvent(QMouseEvent* e) {
    const int i = indexAt(e->position().toPoint());
    if (i >= 0) setCurrent(i);
}

void Segmented::mouseMoveEvent(QMouseEvent* e) {
    const int i = indexAt(e->position().toPoint());
    if (i != hover_) { hover_ = i; update(); }
}

void Segmented::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    p.setPen(Qt::NoPen);
    p.setBrush(c.dark ? c.input : c.hover);
    p.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 8, 8);

    const QFont font = Font::make(Font::Control, QFont::DemiBold);
    const QFontMetrics fm(font);
    p.setFont(font);
    int x = 3;
    for (int i = 0; i < options_.size(); ++i) {
        const int w = fm.horizontalAdvance(options_[i]) + 28;
        const QRectF seg(x, 3, w, height() - 6);
        if (i == current_) {
            p.setPen(QPen(c.border, 1));
            p.setBrush(c.dark ? c.raised : c.surface);
            p.drawRoundedRect(seg, 6, 6);
            p.setPen(c.text);
        } else {
            p.setPen(i == hover_ ? c.text : c.text2);
        }
        p.drawText(seg, Qt::AlignCenter, options_[i]);
        x += w;
    }
}

// ─── IconLabel ───

IconLabel::IconLabel(Icons::Id id, int size, ColorRole role, QWidget* parent)
    : QWidget(parent), id_(id), size_(size), role_(role)
{
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void IconLabel::set(Icons::Id id, ColorRole role) {
    id_ = id;
    role_ = role;
    update();
}

void IconLabel::setTile(bool tile, int box) {
    tile_ = tile;
    box_ = box;
    updateGeometry();
    update();
}

QSize IconLabel::sizeHint() const {
    return tile_ ? QSize(box_, box_) : QSize(size_, size_);
}

void IconLabel::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    if (tile_) {
        p.setPen(Qt::NoPen);
        p.setBrush(softFor(role_));
        p.drawRoundedRect(QRectF(0, 0, box_, box_), 10, 10);
    }
    const QPixmap pm = Icons::pixmap(id_, size_, color(role_));
    p.drawPixmap((width() - size_) / 2, (height() - size_) / 2, pm);
}

// ─── ElidedLabel ───

ElidedLabel::ElidedLabel(const QString& text, Qt::TextElideMode mode, QWidget* parent)
    : QLabel(parent), full_(text), mode_(mode)
{
    setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    refresh();
}

void ElidedLabel::setFullText(const QString& text) {
    full_ = text;
    refresh();
}

QSize ElidedLabel::minimumSizeHint() const {
    return { 24, QLabel::minimumSizeHint().height() };
}

QSize ElidedLabel::sizeHint() const {
    const QFontMetrics fm(font());
    return { fm.horizontalAdvance(full_) + 4, QLabel::sizeHint().height() };
}

void ElidedLabel::resizeEvent(QResizeEvent* e) {
    QLabel::resizeEvent(e);
    refresh();
}

void ElidedLabel::changeEvent(QEvent* e) {
    QLabel::changeEvent(e);
    if (e->type() == QEvent::FontChange || e->type() == QEvent::StyleChange) refresh();
}

void ElidedLabel::refresh() {
    const QFontMetrics fm(font());
    const QString shown = fm.elidedText(full_, mode_, std::max(0, width() - 2));
    if (shown != text()) QLabel::setText(shown);
    setToolTip(shown != full_ ? full_ : QString());
}

// ─── Card ───

Card::Card(QWidget* parent, int padding) : QFrame(parent) {
    setObjectName("card");
    body_ = new QVBoxLayout(this);
    body_->setContentsMargins(padding, padding, padding, padding);
    body_->setSpacing(Space::M);
}

// ─── StatTile ───

StatTile::StatTile(Icons::Id icon, const QString& label, QWidget* parent) : Card(parent, 18) {
    body()->setSpacing(6);
    auto* head = new QHBoxLayout();
    head->setSpacing(8);
    head->addWidget(new IconLabel(icon, 16, ColorRole::Text3));
    auto* l = makeLabel(label, "label");
    l->setWordWrap(false);
    head->addWidget(l, 1);
    body()->addLayout(head);
    value_ = makeLabel(QString(), "metric");
    value_->setWordWrap(false);
    body()->addWidget(value_);
    caption_ = makeLabel(QString(), "caption");
    body()->addWidget(caption_);
    body()->addStretch(1);
    setMinimumHeight(118);
}

void StatTile::set(const QString& value, const QString& caption, ColorRole valueRole) {
    value_->setText(value);
    caption_->setText(caption);
    caption_->setVisible(!caption.isEmpty());
    const char* tone = valueRole == ColorRole::Danger ? "danger"
                     : valueRole == ColorRole::Ok     ? "ok"
                     : valueRole == ColorRole::Warn   ? "warn"
                     : valueRole == ColorRole::AccentText ? "accent" : "";
    setStyleProp(value_, "tone", tone);
}

void StatTile::setClickable(bool on) {
    clickable_ = on;
    setCursor(on ? Qt::PointingHandCursor : Qt::ArrowCursor);
}

void StatTile::mouseReleaseEvent(QMouseEvent* e) {
    if (clickable_ && e->button() == Qt::LeftButton && rect().contains(e->position().toPoint()))
        emit clicked();
    Card::mouseReleaseEvent(e);
}

void StatTile::enterEvent(QEnterEvent*) {
    if (clickable_) setStyleProp(this, "card", "hover");
}

void StatTile::leaveEvent(QEvent*) {
    if (clickable_) setStyleProp(this, "card", QVariant());
}

// ─── SettingRow ───

SettingRow::SettingRow(const QString& title, const QString& description, QWidget* control,
                       QWidget* parent)
    : QWidget(parent)
{
    auto* row = new QHBoxLayout(this);
    row->setContentsMargins(0, Space::M, 0, Space::M);
    row->setSpacing(Space::L);

    auto* text = new QVBoxLayout();
    text->setSpacing(2);
    auto* t = makeLabel(title, "body");
    t->setWordWrap(true);
    text->addWidget(t);
    desc_ = makeLabel(description, "muted");
    desc_->setVisible(!description.isEmpty());
    text->addWidget(desc_);
    row->addLayout(text, 1);
    if (control) row->addWidget(control, 0, Qt::AlignVCenter | Qt::AlignRight);
}

// ─── EmptyState ───

EmptyState::EmptyState(Icons::Id icon, const QString& title, const QString& text, QWidget* parent)
    : QWidget(parent)
{
    auto* col = new QVBoxLayout(this);
    col->setContentsMargins(Space::XL, Space::XXL, Space::XL, Space::XXL);
    col->setSpacing(Space::S);
    col->setAlignment(Qt::AlignCenter);

    auto* ic = new IconLabel(icon, 24, ColorRole::Text2);
    ic->setTile(true, 48);
    col->addWidget(ic, 0, Qt::AlignHCenter);
    col->addSpacing(Space::S);

    auto* t = makeLabel(title, "heading");
    t->setAlignment(Qt::AlignHCenter);
    t->setWordWrap(true);
    col->addWidget(t);

    auto* d = makeLabel(text, "muted");
    d->setAlignment(Qt::AlignHCenter);
    d->setMinimumWidth(280);
    d->setMaximumWidth(460);
    col->addWidget(d, 0, Qt::AlignHCenter);

    actions_ = new QHBoxLayout();
    actions_->setSpacing(Space::S);
    actions_->setAlignment(Qt::AlignHCenter);
    col->addSpacing(Space::S);
    col->addLayout(actions_);
}

Button* EmptyState::addAction(const QString& text, Button::Variant variant) {
    auto* b = new Button(text, variant);
    actions_->addWidget(b);
    return b;
}

// ─── Banner ───

Banner::Banner(const QString& tone, Icons::Id icon, const QString& title, const QString& text,
               QWidget* parent)
    : QFrame(parent), tone_(tone)
{
    auto* row = new QHBoxLayout(this);
    row->setContentsMargins(Space::L, Space::M, Space::M, Space::M);
    row->setSpacing(Space::M);

    ColorRole role = ColorRole::Text2;
    if (tone == "CRIT") role = ColorRole::Danger;
    else if (tone == "HIGH") role = ColorRole::High;
    else if (tone == "MED") role = ColorRole::Warn;
    else if (tone == "OK") role = ColorRole::Ok;
    else if (tone == "ACCENT") role = ColorRole::AccentText;
    icon_ = new IconLabel(icon, 20, role);
    row->addWidget(icon_, 0, Qt::AlignTop);

    auto* text_col = new QVBoxLayout();
    text_col->setSpacing(2);
    title_ = makeLabel(title, "subheading");
    title_->setWordWrap(true);
    text_ = makeLabel(text, "muted");
    text_col->addWidget(title_);
    text_col->addWidget(text_);
    title_->setVisible(!title.isEmpty());
    text_->setVisible(!text.isEmpty());
    row->addLayout(text_col, 1);

    actions_ = new QHBoxLayout();
    actions_->setSpacing(Space::S);
    row->addLayout(actions_);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

Button* Banner::addAction(const QString& text, Button::Variant variant) {
    auto* b = new Button(text, variant);
    b->setSize(Button::Size::Small);
    actions_->addWidget(b, 0, Qt::AlignVCenter);
    return b;
}

void Banner::setText(const QString& title, const QString& text) {
    title_->setText(title);
    text_->setText(text);
    title_->setVisible(!title.isEmpty());
    text_->setVisible(!text.isEmpty());
}

void Banner::setTone(const QString& tone) {
    tone_ = tone;
    ColorRole role = ColorRole::Text2;
    if (tone == "CRIT") role = ColorRole::Danger;
    else if (tone == "HIGH") role = ColorRole::High;
    else if (tone == "MED") role = ColorRole::Warn;
    else if (tone == "OK") role = ColorRole::Ok;
    else if (tone == "ACCENT") role = ColorRole::AccentText;
    icon_->set(Icons::Id::Info, role);
    update();
}

void Banner::setClosable(bool closable) {
    if (closable && !close_) {
        close_ = new IconButton(Icons::Id::Close, TR("Close"), this, 28);
        actions_->addWidget(close_, 0, Qt::AlignTop);
        connect(close_, &QAbstractButton::clicked, this, [this]() {
            hide();
            emit closed();
        });
    }
    if (close_) close_->setVisible(closable);
}

void Banner::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Tone t = Theme::instance().tone(tone_);
    p.setPen(QPen(t.solid.lighter(pal().dark ? 60 : 160), 1));
    QColor border = t.solid;
    border.setAlphaF(0.35);
    p.setPen(QPen(border, 1));
    p.setBrush(t.background);
    p.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 10, 10);
}

// ─── AdaptiveGrid ───

AdaptiveGrid::AdaptiveGrid(int minColumnWidth, int maxColumns, QWidget* parent)
    : QWidget(parent), minColumn_(minColumnWidth), maxColumns_(maxColumns)
{
    grid_ = new QGridLayout(this);
    grid_->setContentsMargins(0, 0, 0, 0);
    grid_->setHorizontalSpacing(Space::L);
    grid_->setVerticalSpacing(Space::L);
}

void AdaptiveGrid::addWidget(QWidget* w) {
    items_.append(w);
    columns_ = 0;
    relayout(width() > 0 ? width() : minColumn_ * maxColumns_);
}

void AdaptiveGrid::resizeEvent(QResizeEvent* e) {
    QWidget::resizeEvent(e);
    relayout(width());
}

void AdaptiveGrid::relayout(int w) {
    const int spacing = grid_->horizontalSpacing();
    int cols = std::clamp((w + spacing) / (minColumn_ + spacing), 1, maxColumns_);
    // Неполный последний ряд (3+1 карточки) смотрится как ошибка вёрстки:
    // берём число колонок, на которое карточки делятся ровно.
    const int n = static_cast<int>(items_.size());
    while (cols > 1 && n > cols && n % cols != 0) --cols;
    if (cols == columns_) return;
    columns_ = cols;
    for (QWidget* item : items_) grid_->removeWidget(item);
    for (int c = 0; c < maxColumns_; ++c) grid_->setColumnStretch(c, c < cols ? 1 : 0);
    for (int i = 0; i < items_.size(); ++i) grid_->addWidget(items_[i], i / cols, i % cols);
}

// ─── Форматирование ───

QString formatDuration(qint64 ms) {
    if (ms < 0) return QStringLiteral("—");
    const qint64 s = ms / 1000;
    if (s < 60) return TR("%1 s").arg(std::max<qint64>(s, ms > 0 ? 1 : 0));
    const qint64 m = s / 60;
    if (m < 60) return TR("%1 min %2 s").arg(m).arg(s % 60, 2, 10, QChar('0'));
    return TR("%1 h %2 min").arg(m / 60).arg(m % 60, 2, 10, QChar('0'));
}

QString formatBytes(qint64 bytes) {
    // Десятичный разделитель — по языку интерфейса: «1,5 МБ», но «1.5 MB».
    const QLocale loc(Lang::instance().current() == Lang::Id::Ru ? QLocale::Russian : QLocale::English);
    const double b = static_cast<double>(bytes);
    if (b < 1024) return TR("%1 B").arg(bytes);
    if (b < 1024.0 * 1024) return TR("%1 KB").arg(loc.toString(b / 1024, 'f', 0));
    if (b < 1024.0 * 1024 * 1024) return TR("%1 MB").arg(loc.toString(b / 1048576.0, 'f', 1));
    return TR("%1 GB").arg(loc.toString(b / 1073741824.0, 'f', 1));
}

QString formatCount(qint64 n) {
    // Разделитель разрядов — узкий неразрывный пробел, как в русской типографике.
    QString s = QString::number(n);
    for (int i = s.size() - 3; i > 0; i -= 3) s.insert(i, QChar(0x202F));
    return s;
}

} // namespace Ui
