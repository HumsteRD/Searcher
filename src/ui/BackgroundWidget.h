#pragma once

#include <QWidget>

// Фон окна: базовая заливка + четыре радиальных пятна, заданные в % от
// текущего размера окна. Никакого растра и никакого блюра — мягкость даёт
// растяжка стоп-точек, поэтому фон остаётся чётким на любом масштабе
// и сам следует за окном от 1100×720 до 1920×1080.
class BackgroundWidget : public QWidget {
    Q_OBJECT

public:
    explicit BackgroundWidget(QWidget* parent = nullptr);

protected:
    void paintEvent(QPaintEvent* event) override;
};
