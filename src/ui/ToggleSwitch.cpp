#include "ToggleSwitch.h"
#include "../theme.h"

#include <QPainter>
#include <QPropertyAnimation>
#include <QEnterEvent>

namespace {

constexpr int kW = 44;
constexpr int kH = 24;
constexpr int kKnob = 16;
constexpr int kPad = 4;

QColor mix(const QColor& a, const QColor& b, qreal t) {
    return QColor(int(a.red()   + (b.red()   - a.red())   * t),
                  int(a.green() + (b.green() - a.green()) * t),
                  int(a.blue()  + (b.blue()  - a.blue())  * t));
}

} // namespace

ToggleSwitch::ToggleSwitch(QWidget* parent)
    : QAbstractButton(parent)
{
    setCheckable(true);
    setCursor(Qt::PointingHandCursor);
    setAttribute(Qt::WA_Hover, true);
    setFixedSize(kW, kH);

    anim_ = new QPropertyAnimation(this, "position", this);
    anim_->setDuration(140);
    anim_->setEasingCurve(QEasingCurve::InOutQuad);
}

QSize ToggleSwitch::sizeHint() const {
    return QSize(kW, kH);
}

void ToggleSwitch::setPosition(qreal p) {
    position_ = p;
    update();
}

void ToggleSwitch::animateTo(bool on) {
    anim_->stop();
    anim_->setStartValue(position_);
    anim_->setEndValue(on ? 1.0 : 0.0);
    anim_->start();
}

void ToggleSwitch::checkStateSet() {
    QAbstractButton::checkStateSet();
    // Программная установка (загрузка настроек) — без анимации.
    position_ = isChecked() ? 1.0 : 0.0;
    update();
}

void ToggleSwitch::nextCheckState() {
    QAbstractButton::nextCheckState();
    animateTo(isChecked());
}

void ToggleSwitch::enterEvent(QEnterEvent* e) {
    QAbstractButton::enterEvent(e);
    hovered_ = true;
    update();
}

void ToggleSwitch::leaveEvent(QEvent* e) {
    QAbstractButton::leaveEvent(e);
    hovered_ = false;
    update();
}

void ToggleSwitch::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const bool on = isEnabled();
    const QRectF track = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);

    QColor trackFill = on
        ? mix(QColor(Theme::SUNKEN), QColor(Theme::ACCENT), position_)
        : QColor(Theme::FILL_DISABLED);

    QColor border = !on ? QColor(Theme::BORDER_DISABLED)
                        : (position_ > 0.5 ? QColor(Theme::ACCENT)
                                           : QColor(hovered_ ? Theme::BORDER_CONTROL_HOVER
                                                             : Theme::BORDER_CONTROL));

    p.setBrush(trackFill);
    p.setPen(QPen(border, 1));
    p.drawRoundedRect(track, kH / 2.0, kH / 2.0);

    // Бегунок едет от kPad до kW - kKnob - kPad.
    const qreal x = kPad + position_ * (kW - kKnob - 2 * kPad);
    const QRectF knob(x, kPad, kKnob, kKnob);

    p.setPen(Qt::NoPen);
    p.setBrush(on ? QColor(position_ > 0.5 ? "#FFFFFF" : Theme::TEXT_SECONDARY)
                  : QColor(Theme::TEXT_DISABLED));
    p.drawEllipse(knob);
}
