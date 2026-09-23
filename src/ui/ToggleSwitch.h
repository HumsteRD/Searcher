#pragma once

#include <QAbstractButton>

class QPropertyAnimation;

// Переключатель 44×24 с бегунком 16. Рисуется целиком в paintEvent:
// QSS умеет стилизовать только индикатор QCheckBox, а скользящий
// бегунок и перетекающий цвет дорожки средствами стилей не сделать.
class ToggleSwitch : public QAbstractButton {
    Q_OBJECT
    Q_PROPERTY(qreal position READ position WRITE setPosition)

public:
    explicit ToggleSwitch(QWidget* parent = nullptr);

    QSize sizeHint() const override;

    qreal position() const { return position_; }
    void  setPosition(qreal p);

protected:
    void paintEvent(QPaintEvent* event) override;
    void enterEvent(QEnterEvent* event) override;
    void leaveEvent(QEvent* event) override;
    void checkStateSet() override;
    void nextCheckState() override;

private:
    void animateTo(bool checked);

    QPropertyAnimation* anim_;
    qreal position_ = 0.0;   // 0 = выключен, 1 = включён
    bool  hovered_  = false;
};
