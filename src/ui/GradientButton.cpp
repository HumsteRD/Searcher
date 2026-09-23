#include "GradientButton.h"
#include "../theme.h"

#include <QPainter>
#include <QPainterPath>
#include <QLinearGradient>
#include <QPropertyAnimation>
#include <QEnterEvent>
#include <QFontMetrics>

namespace {

// Запас по краям, ниже которого подпись начинает сокращаться.
constexpr int kElideMargin = 10;

QColor lighten(const QColor& c, qreal amount) {
    QColor r = c;
    r.setRed(  qMin(255, int(c.red()   + (255 - c.red())   * amount)));
    r.setGreen(qMin(255, int(c.green() + (255 - c.green()) * amount)));
    r.setBlue( qMin(255, int(c.blue()  + (255 - c.blue())  * amount)));
    return r;
}

} // namespace

GradientButton::GradientButton(const QString& text, Style style, QWidget* parent)
    : QPushButton(text, parent)
    , style_(style)
    , from_(Theme::ACCENT)
    , to_(Theme::ACCENT_GRAD_END)
{
    setCursor(Qt::PointingHandCursor);
    setAttribute(Qt::WA_Hover, true);
    // Preferred, а не Minimum по умолчанию от QPushButton: с Minimum
    // раскладка не имеет права сжать кнопку ниже желаемой ширины и
    // вместо этого выпускает её за край окна.
    setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    // Фон и рамку рисуем сами — иначе стиль подложит своё под наш градиент.
    setStyleSheet("background: transparent; border: none;");
}

QSize GradientButton::sizeHint() const {
    QFont f = font();
    f.setWeight(QFont::DemiBold);          // текст рисуется полужирным

    const int textW = QFontMetrics(f).horizontalAdvance(text());
    const int padX  = (style_ == Style::Filled) ? 28 : 24;

    return QSize(textW + padX * 2, qMax(height(), 28));
}

QSize GradientButton::minimumSizeHint() const {
    const QSize wanted = sizeHint();
    // Ниже этого кнопка перестаёт быть читаемой: остаётся пара букв
    // и многоточие. Дальше сжимать её бессмысленно.
    constexpr int kFloor = 96;
    return QSize(qMin(wanted.width(), kFloor), wanted.height());
}

void GradientButton::setGradient(const QColor& from, const QColor& to) {
    from_ = from;
    to_   = to;
    update();
}

QLinearGradient GradientButton::gradientFor(const QRectF& r, qreal amount) const {
    QLinearGradient g(r.topLeft(), r.topRight());
    g.setColorAt(0.0, lighten(from_, amount));
    g.setColorAt(1.0, lighten(to_,   amount));
    return g;
}

void GradientButton::enterEvent(QEnterEvent* event) {
    QPushButton::enterEvent(event);
    auto* a = new QPropertyAnimation(this, "hoverAmount", this);
    a->setDuration(140);
    a->setStartValue(hover_);
    a->setEndValue(1.0);
    a->start(QAbstractAnimation::DeleteWhenStopped);
}

void GradientButton::leaveEvent(QEvent* event) {
    QPushButton::leaveEvent(event);
    auto* a = new QPropertyAnimation(this, "hoverAmount", this);
    a->setDuration(140);
    a->setStartValue(hover_);
    a->setEndValue(0.0);
    a->start(QAbstractAnimation::DeleteWhenStopped);
}

void GradientButton::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const bool on      = isEnabled();
    const bool pressed = isDown();

    // Обводка рисуется по центру линии, поэтому отступаем на полпикселя,
    // иначе край получается мыльным.
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    QPainterPath path;
    path.addRoundedRect(r, radius_, radius_);

    if (!on) {
        p.setPen(QPen(QColor(Theme::BORDER_DISABLED), 1));
        p.setBrush(QColor(Theme::FILL_DISABLED));
        p.drawPath(path);
        p.setPen(QColor(Theme::TEXT_DISABLED));

        QFont disabledFont = font();
        disabledFont.setWeight(QFont::DemiBold);
        p.setFont(disabledFont);
        p.drawText(rect(), Qt::AlignCenter,
                   QFontMetrics(disabledFont).elidedText(
                       text(), Qt::ElideRight,
                       qMax(0, rect().width() - kElideMargin)));
        return;
    }

    // Свечение под кнопкой при наведении — вместо запрещённой в QSS тени.
    if (hover_ > 0.01) {
        QColor glow = lighten(from_, 0.1);
        glow.setAlphaF(0.28 * hover_);
        p.setPen(QPen(glow, 3));
        p.setBrush(Qt::NoBrush);
        p.drawPath(path);
    }

    const qreal amount = (pressed ? -0.0 : 0.12 * hover_);

    if (style_ == Style::Filled) {
        p.setPen(Qt::NoPen);
        QLinearGradient g = gradientFor(r, amount);
        if (pressed) {
            g.setColorAt(0.0, from_.darker(115));
            g.setColorAt(1.0, to_.darker(115));
        }
        p.setBrush(g);
        p.drawPath(path);
        p.setPen(QColor("#FFFFFF"));
    } else {
        // Обводка — сам градиент; заливка появляется только при наведении.
        if (hover_ > 0.01 || pressed) {
            QColor fill = from_;
            fill.setAlphaF(pressed ? 0.28 : 0.16 * hover_);
            p.setBrush(fill);
        } else {
            p.setBrush(Qt::NoBrush);
        }
        p.setPen(QPen(QBrush(gradientFor(r, amount)), 1.4));
        p.drawPath(path);

        // Текст подтягиваем к светлому концу градиента — так он читается
        // и на тёмной подложке, и поверх появившейся заливки.
        p.setPen(lighten(to_, 0.25 * hover_));
    }

    QFont f = font();
    f.setWeight(QFont::DemiBold);
    p.setFont(f);

    // Если подпись не влезла — сокращаем её многоточием. Обрезка рамкой
    // выглядит как сломанная вёрстка: кнопка будто продолжается за краем.
    // Запас берём минимальный: если вычитать здесь полные поля кнопки,
    // сокращаться начнут даже те подписи, которые прекрасно помещаются.
    const QString shown = QFontMetrics(f).elidedText(
        text(), Qt::ElideRight, qMax(0, rect().width() - kElideMargin));
    p.drawText(rect(), Qt::AlignCenter, shown);
}
