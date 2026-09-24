#pragma once

#include "../ui/Shell.h"
#include "../ui/Widgets.h"

#include <QWidget>

class QHBoxLayout;
class QScrollArea;
class QVBoxLayout;

class MainWindow;

// Основа страницы: заголовок с пояснением и действиями справа, ниже —
// прокручиваемое содержимое. Ширина содержимого ограничена: на широком
// мониторе строки текста не растягиваются на весь экран.
class Page : public QWidget {
    Q_OBJECT

public:
    Page(MainWindow* window, const QString& title, const QString& subtitle, QWidget* parent = nullptr);

    QVBoxLayout* body() const { return body_; }
    QHBoxLayout* actions() const { return actions_; }
    void setSubtitle(const QString& text);

    // Страница стала видимой — обновить то, что могло устареть.
    virtual void onShown() {}

protected:
    MainWindow* window() const { return window_; }
    // Отключить прокрутку: страница сама управляет высотой (таблицы).
    void setScrollable(bool scrollable);

private:
    MainWindow*  window_;
    QLabel*      subtitle_;
    QVBoxLayout* body_;
    QHBoxLayout* actions_;
    QScrollArea* scroll_ = nullptr;
    QWidget*     column_ = nullptr;
};
