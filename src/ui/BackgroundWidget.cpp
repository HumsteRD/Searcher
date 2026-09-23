#include "BackgroundWidget.h"
#include "../theme.h"

#include <QPainter>
#include <QPaintEvent>
#include <QRadialGradient>

namespace {

// Параметры пятен ровно из спеки: центр и радиус в долях размера окна.
struct Spot {
    qreal   cx, cy;    // центр, доля ширины/высоты
    qreal   radius;    // доля max(w, h)
    QRgb    rgb;
    int     alpha;     // 0..255 в центре
};

constexpr Spot kSpots[] = {
    { 0.10, 0.04, 0.48, 0x3E2F9E, 165 },  // S1 violet — тепло за логотипом и героем
    { 0.82, 0.02, 0.42, 0x1D5AA8, 120 },  // S2 blue   — чтобы полоса заголовка не была плоской
    { 0.96, 0.96, 0.55, 0x2A2F7A, 105 },  // S3 indigo — держит правый нижний угол под таблицами
    { 0.26, 0.88, 0.45, 0x14456E,  80 },  // S4 steel  — охлаждает низ сайдбара
};

// Все пятна используют одни и те же четыре стопа — так они читаются
// как мягкий свет, а не как диск.
void addStops(QRadialGradient& g, QRgb rgb, int alpha) {
    QColor c = QColor::fromRgb(rgb);

    auto at = [&](qreal factor) {
        QColor s = c;
        s.setAlpha(static_cast<int>(alpha * factor));
        return s;
    };

    g.setColorAt(0.00, at(1.00));
    g.setColorAt(0.40, at(0.55));
    g.setColorAt(0.70, at(0.20));
    g.setColorAt(1.00, at(0.00));
}

} // namespace

BackgroundWidget::BackgroundWidget(QWidget* parent)
    : QWidget(parent)
{
    setAutoFillBackground(false);
}

void BackgroundWidget::paintEvent(QPaintEvent* event) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const qreal w = width();
    const qreal h = height();

    p.fillRect(rect(), QColor(Theme::WINDOW_BASE));

    const qreal span = qMax(w, h);
    for (const Spot& s : kSpots) {
        QRadialGradient g(w * s.cx, h * s.cy, span * s.radius);
        addStops(g, s.rgb, s.alpha);
        p.fillRect(rect(), g);
    }

    QWidget::paintEvent(event);
}
