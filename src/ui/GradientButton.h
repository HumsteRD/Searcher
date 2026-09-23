#pragma once

#include <QPushButton>
#include <QColor>

// Кнопка с градиентом. Рисуется целиком в paintEvent, потому что QSS
// умеет градиент только в фоне: border там принимает лишь сплошной цвет,
// а градиентная обводка средствами стилей недостижима в принципе.
class GradientButton : public QPushButton {
    Q_OBJECT
    Q_PROPERTY(qreal hoverAmount READ hoverAmount WRITE setHoverAmount)

public:
    enum class Style {
        Filled,   // градиентная заливка, белый текст
        Outline   // градиентная обводка, прозрачный фон
    };

    explicit GradientButton(const QString& text, Style style,
                            QWidget* parent = nullptr);

    void setGradient(const QColor& from, const QColor& to);
    void setRadius(int r) { radius_ = r; update(); }

    qreal hoverAmount() const { return hover_; }
    void  setHoverAmount(qreal v) { hover_ = v; update(); }

public:
    // Текст рисуется по центру всего прямоугольника, поэтому поля
    // должны быть в самом размере — иначе подпись липнет к краям.
    QSize sizeHint() const override;

    // Минимум заметно меньше желаемого: кнопке с длинной подписью в
    // тесной строке лучше сжаться и сократить текст многоточием, чем
    // уехать за край окна. Раньше минимум равнялся желаемому, и в узком
    // окне кнопка обрезалась рамкой — без всякого признака, что она
    // вообще продолжается.
    QSize minimumSizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;
    void enterEvent(QEnterEvent* event) override;
    void leaveEvent(QEvent* event) override;

private:
    QLinearGradient gradientFor(const QRectF& r, qreal lighten) const;

    Style  style_;
    QColor from_;
    QColor to_;
    int    radius_ = 8;
    qreal  hover_  = 0.0;   // 0..1, анимируется при наведении
};
