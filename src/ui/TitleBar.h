#pragma once

#include <QWidget>

class QLabel;
class QPushButton;

// Полоса заголовка 56px: хлебная крошка «Threat Scanner / <страница>»
// слева и три кнопки окна справа.
class TitleBar : public QWidget {
    Q_OBJECT

public:
    explicit TitleBar(QWidget* parent = nullptr);

    void setPageName(const QString& page);

    // Нужны окну: кнопки должны оставаться кликабельными внутри полосы,
    // а «развернуть» дополнительно отдаётся системе ради Snap Layouts.
    QPushButton* minimizeButton() const { return minBtn_; }
    QPushButton* maximizeButton() const { return maxBtn_; }
    QPushButton* closeButton()    const { return closeBtn_; }

    // Подсветка кнопки «развернуть», когда курсор над ней ведёт система.
    void setMaximizeHovered(bool hovered);

    // Иконка меняется между «развернуть» и «восстановить».
    void setMaximized(bool maximized);

signals:
    void minimizeRequested();
    void maximizeRequested();
    void closeRequested();

private:
    QPushButton* makeSystemButton(int iconId, bool danger);

    QLabel*      pageLabel_;
    QPushButton* minBtn_;
    QPushButton* maxBtn_;
    QPushButton* closeBtn_;
};
