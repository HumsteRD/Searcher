#pragma once

#include <QMainWindow>
#include <QPointer>

struct HWND__;

// Окно без системной рамки, но остающееся «настоящим» окном Windows.
//
// Рамка убирается обработкой WM_NCCALCSIZE, а не просто флагом
// FramelessWindowHint: благодаря этому продолжают работать перетаскивание
// к краю экрана, Aero Shake, тень и скругление углов, которые Windows 11
// рисует сама. Поэтому радиус окна НЕ надо подделывать в QSS.
class FramelessWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit FramelessWindow(QWidget* parent = nullptr);

    // Полоса, за которую окно таскают. Всё, что внутри неё, работает как
    // системный заголовок: перетаскивание, двойной клик — развернуть.
    void setCaptionWidget(QWidget* caption);

    // Виджеты, которые должны оставаться кликабельными внутри полосы.
    void addCaptionExclusion(QWidget* w);

    // Кнопка «развернуть». Отдаётся системе как HTMAXBUTTON — это включает
    // всплывающие макеты Snap Layouts при наведении (Windows 11).
    void setMaximizeButton(QWidget* button);

protected:
    bool nativeEvent(const QByteArray& eventType, void* message,
                     qintptr* result) override;

    // Нативная настройка окна делается при первом показе, а не в
    // конструкторе: раньше платформенного окна ещё не существует.
    void showEvent(QShowEvent* event) override;

    // Вызывается, когда система наводит/уводит курсор с кнопки «развернуть»:
    // Qt в этот момент мышь не видит, подсветку рисуем сами.
    virtual void onMaximizeButtonHover(bool hovered);

private:
    void installNativeFrame();
    // Снимает блокировку UIPI на перетаскивание в окно,
    // запущенное с правами администратора.
    static void allowDragAndDropFromLowerPrivilege(HWND__* hwnd);
    bool handleNativeEvent(const QByteArray& eventType, void* message,
                           qintptr* result);
    bool hitTest(const QPoint& globalPos, qintptr* result) const;

    QPointer<QWidget>        caption_;
    QPointer<QWidget>        maxButton_;
    QList<QPointer<QWidget>> exclusions_;
    bool                     maxHovered_ = false;
    bool                     nativeFrameReady_ = false;
};
