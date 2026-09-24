#pragma once

#include "Icons.h"
#include "Theme.h"

#include <QAbstractButton>
#include <QFrame>
#include <QLabel>
#include <QLayout>
#include <QPushButton>
#include <QVariantAnimation>
#include <QWidget>

#include <functional>
#include <optional>

class QGridLayout;
class QHBoxLayout;
class QVBoxLayout;

namespace Ui {

// Цвет по смыслу, а не по значению: разворачивается в текущей палитре,
// поэтому иконки перекрашиваются вместе с темой.
enum class ColorRole { Text, Text2, Text3, Accent, AccentText, OnAccent, Ok, Warn, High, Danger, Low };
QColor color(ColorRole role);

// Динамическое свойство для таблицы стилей + перерасчёт стиля. Без
// перерасчёта Qt не замечает смены свойства у уже показанного виджета.
void setStyleProp(QWidget* w, const char* name, const QVariant& value);

QLabel* makeLabel(const QString& text, const char* role = "body", QWidget* parent = nullptr);
QFrame* makeDivider(QWidget* parent = nullptr);

// Текст, который можно переносить внутри длинных путей и хэшей: после
// разделителей вставляется невидимая точка переноса. Иначе QLabel не
// может перенести «слово» из сотни символов и раздвигает всю панель.
QString breakable(const QString& text);

// Очистить раскладку: виджеты сразу прячутся и удаляются позже. Просто
// deleteLater оставляет старые виджеты на экране до следующего прохода
// цикла событий — поверх новых.
void clearLayout(QLayout* layout);

// Раскладка с переносом: элементы идут в строку, а не помещающиеся
// переходят на следующую. Для рядов кнопок в узких панелях — иначе ряд
// задаёт минимальную ширину всей панели и текст обрезается справа.
class FlowLayout : public QLayout {
public:
    explicit FlowLayout(QWidget* parent = nullptr, int hSpacing = 8, int vSpacing = 8);
    ~FlowLayout() override;
    void addItem(QLayoutItem* item) override;
    int count() const override { return items_.size(); }
    QLayoutItem* itemAt(int index) const override { return items_.value(index); }
    QLayoutItem* takeAt(int index) override;
    Qt::Orientations expandingDirections() const override { return {}; }
    bool hasHeightForWidth() const override { return true; }
    int heightForWidth(int width) const override { return doLayout(QRect(0, 0, width, 0), true); }
    QSize minimumSize() const override;
    QSize sizeHint() const override { return minimumSize(); }
    void setGeometry(const QRect& rect) override;

private:
    int doLayout(const QRect& rect, bool testOnly) const;
    QList<QLayoutItem*> items_;
    int hSpace_, vSpace_;
};

// Зона «перетащите файл сюда»: пунктирная рамка с подсказкой.
class DropZone : public QWidget {
    Q_OBJECT
public:
    DropZone(const QString& text, QWidget* parent = nullptr);
    QSize sizeHint() const override { return { 300, 96 }; }
    QSize minimumSizeHint() const override { return { 160, 72 }; }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString text_;
};

// Кнопка с иконкой, которая перекрашивается при смене темы.
class Button : public QPushButton {
    Q_OBJECT
public:
    enum class Variant { Primary, Secondary, Ghost, Danger, Link };
    enum class Size { Small, Medium, Large };

    Button(const QString& text, Variant variant = Variant::Secondary, QWidget* parent = nullptr);
    void setIconId(std::optional<Icons::Id> id);
    void setVariant(Variant v);
    void setSize(Size s);

private:
    void refreshIcon();
    Variant variant_;
    std::optional<Icons::Id> icon_;
    Size size_ = Size::Medium;
};

// Кнопка-иконка без текста (заголовок окна, строки списков).
class IconButton : public QAbstractButton {
    Q_OBJECT
public:
    IconButton(Icons::Id id, const QString& tooltip, QWidget* parent = nullptr, int box = 32);
    void setIconId(Icons::Id id);
    void setDanger(bool danger) { danger_ = danger; update(); }
    void setForcedHover(bool hover) { forcedHover_ = hover; update(); }
    QSize sizeHint() const override { return { box_, box_ }; }

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override { update(); }
    void leaveEvent(QEvent*) override { update(); }

private:
    Icons::Id id_;
    int  box_;
    bool danger_ = false;
    bool forcedHover_ = false;
};

// Переключатель вкл/выкл.
class Toggle : public QAbstractButton {
    Q_OBJECT
public:
    explicit Toggle(QWidget* parent = nullptr);
    QSize sizeHint() const override { return { 40, 22 }; }
    void setCheckedNoAnim(bool on);

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override { update(); }
    void leaveEvent(QEvent*) override { update(); }

private:
    QVariantAnimation anim_;
    qreal pos_ = 0.0;   // 0 — выкл, 1 — вкл
};

// Пилюля: уровень находки, статус, счётчик.
class Pill : public QWidget {
    Q_OBJECT
public:
    Pill(const QString& text, const QString& tone, QWidget* parent = nullptr);
    void set(const QString& text, const QString& tone);
    void setDot(bool dot) { dot_ = dot; updateGeometry(); update(); }
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString text_, tone_;
    bool    dot_ = true;
};

// Тонкая полоса прогресса. Отрицательное значение — «неизвестно»:
// бегущий отрезок вместо шкалы, пока идёт подсчёт объёма.
class ProgressBar : public QWidget {
    Q_OBJECT
public:
    explicit ProgressBar(QWidget* parent = nullptr);
    void setValue(double fraction);   // 0..1, <0 — неизвестно
    QSize sizeHint() const override { return { 200, 8 }; }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    double value_ = 0.0;
    QVariantAnimation sweep_;
};

// Круглый индикатор «идёт работа».
class Spinner : public QWidget {
    Q_OBJECT
public:
    explicit Spinner(int size = 18, QWidget* parent = nullptr);
    QSize sizeHint() const override { return { size_, size_ }; }
    void setRunning(bool running);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    int size_;
    QVariantAnimation anim_;
};

// Сегментный выбор из нескольких вариантов.
class Segmented : public QWidget {
    Q_OBJECT
public:
    explicit Segmented(const QStringList& options, QWidget* parent = nullptr);
    void setCurrent(int index);
    int  current() const { return current_; }
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override { return sizeHint(); }

signals:
    void currentChanged(int index);

protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void leaveEvent(QEvent*) override { hover_ = -1; update(); }

private:
    int indexAt(const QPoint& p) const;
    QStringList options_;
    int current_ = 0;
    int hover_ = -1;
};

// Иконка, перекрашиваемая вместе с темой.
class IconLabel : public QWidget {
    Q_OBJECT
public:
    IconLabel(Icons::Id id, int size, ColorRole role, QWidget* parent = nullptr);
    void set(Icons::Id id, ColorRole role);
    // Плитка: иконка на мягкой подложке тона (как в заголовках карточек).
    void setTile(bool tile, int box = 40);
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    Icons::Id id_;
    int size_;
    ColorRole role_;
    bool tile_ = false;
    int box_ = 40;
};

// Текст, который сокращается многоточием, а не вылезает за край.
// Для путей — многоточие в середине: важны и диск, и имя файла.
class ElidedLabel : public QLabel {
    Q_OBJECT
public:
    explicit ElidedLabel(const QString& text = {}, Qt::TextElideMode mode = Qt::ElideRight,
                         QWidget* parent = nullptr);
    void setFullText(const QString& text);
    QString fullText() const { return full_; }
    QSize minimumSizeHint() const override;
    QSize sizeHint() const override;

protected:
    void resizeEvent(QResizeEvent*) override;
    void changeEvent(QEvent*) override;

private:
    void refresh();
    QString full_;
    Qt::TextElideMode mode_;
};

// Карточка: поверхность с рамкой и внутренними отступами.
class Card : public QFrame {
    Q_OBJECT
public:
    explicit Card(QWidget* parent = nullptr, int padding = 20);
    QVBoxLayout* body() const { return body_; }

private:
    QVBoxLayout* body_;
};

// Плитка показателя: подпись, крупное значение, пояснение.
class StatTile : public Card {
    Q_OBJECT
public:
    StatTile(Icons::Id icon, const QString& label, QWidget* parent = nullptr);
    void set(const QString& value, const QString& caption, ColorRole valueRole = ColorRole::Text);
    void setClickable(bool on);

signals:
    void clicked();

protected:
    void mouseReleaseEvent(QMouseEvent* e) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;

private:
    QLabel* value_;
    QLabel* caption_;
    bool clickable_ = false;
};

// Строка настройки: название, пояснение, элемент управления справа.
class SettingRow : public QWidget {
    Q_OBJECT
public:
    SettingRow(const QString& title, const QString& description, QWidget* control,
               QWidget* parent = nullptr);
    QLabel* descriptionLabel() const { return desc_; }

private:
    QLabel* desc_;
};

// Пустое состояние: иконка, заголовок, пояснение, действие.
class EmptyState : public QWidget {
    Q_OBJECT
public:
    EmptyState(Icons::Id icon, const QString& title, const QString& text, QWidget* parent = nullptr);
    Button* addAction(const QString& text, Button::Variant variant = Button::Variant::Secondary);

private:
    QHBoxLayout* actions_;
};

// Плашка с сообщением в потоке страницы.
class Banner : public QFrame {
    Q_OBJECT
public:
    Banner(const QString& tone, Icons::Id icon, const QString& title, const QString& text,
           QWidget* parent = nullptr);
    Button* addAction(const QString& text, Button::Variant variant = Button::Variant::Secondary);
    void setText(const QString& title, const QString& text);
    void setTone(const QString& tone);
    void setClosable(bool closable);

signals:
    void closed();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString tone_;
    IconLabel* icon_;
    QLabel* title_;
    QLabel* text_;
    QHBoxLayout* actions_;
    IconButton* close_ = nullptr;
};

// Сетка, которая сама выбирает число колонок по ширине: карточки не
// наезжают друг на друга при узком окне и не растягиваются на весь
// экран при развёрнутом.
class AdaptiveGrid : public QWidget {
    Q_OBJECT
public:
    AdaptiveGrid(int minColumnWidth, int maxColumns, QWidget* parent = nullptr);
    void addWidget(QWidget* w);
    int columns() const { return columns_; }

protected:
    void resizeEvent(QResizeEvent*) override;

private:
    void relayout(int width);
    QGridLayout* grid_;
    QList<QWidget*> items_;
    int minColumn_, maxColumns_;
    int columns_ = 0;
};

// Короткие форматтеры для чисел, времени и размеров.
QString formatDuration(qint64 ms);
QString formatBytes(qint64 bytes);
QString formatCount(qint64 n);

} // namespace Ui
