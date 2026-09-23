#pragma once

#include <QWidget>
#include <QString>

class QFrame;
class QLabel;
class QPushButton;
class QVBoxLayout;

namespace PageHelpers {

// Надзаголовок секции: 12px/600, трекинг +1.1. Капс набирается прямо
// в строке — в QSS нет text-transform.
QLabel* sectionTitle(const QString& text, QWidget* parent);

QLabel* pageTitle(const QString& text, QWidget* parent);
QLabel* pageSubtitle(const QString& text, QWidget* parent);

// Карточка: заливка + волосок 1px. Тени нет — глубину даёт ступень
// заливки относительно фона окна.
QFrame* card(QWidget* parent, int radius = 12);

enum class BtnStyle {
    Primary,     // 40px, акцент, с тенью
    Secondary,   // 32px, обводка
    Danger,      // 32px, обводка цветом опасности
    Row          // 28px, компактная кнопка в строке таблицы
};

QPushButton* button(const QString& text, BtnStyle style, QWidget* parent);

// Пилюля уровня опасности: цвет + слово, никогда не только цвет.
QLabel* severityPill(const QString& severity, QWidget* parent);

// Корневая раскладка страницы с отступами по спеке.
QVBoxLayout* pageLayout(QWidget* page);

// Страница с прокруткой. Использовать везде, где число карточек может
// вырасти: без прокрутки layout сжимает содержимое и текст срезается.
QVBoxLayout* scrollablePageLayout(QWidget* page);

// Тени из спеки — всего три набора на всё приложение.
void applyHeroShadow(QWidget* w);
void applyPrimaryButtonShadow(QWidget* w);
void applyModalShadow(QWidget* w);

// Трекинг (letter-spacing) в QSS отсутствует — задаётся через шрифт.
void setTracking(QWidget* w, qreal px);

// Цвета уровня опасности: текст / фон / граница.
struct SeverityColors { QString fg, bg, border; };
SeverityColors severityColors(const QString& severity);

} // namespace PageHelpers
