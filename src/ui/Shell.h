#pragma once

#include "Widgets.h"

#include <QFrame>
#include <QList>
#include <QPointer>
#include <QTimer>
#include <QWidget>

#include <functional>

class QLabel;
class QVBoxLayout;

namespace Ui {

// Полоса заголовка окна: логотип, название, кнопки окна.
class TitleBar : public QWidget {
    Q_OBJECT
public:
    explicit TitleBar(QWidget* parent = nullptr);
    IconButton* minimizeButton() const { return min_; }
    IconButton* maximizeButton() const { return max_; }
    IconButton* closeButton() const { return close_; }
    void setMaximized(bool maximized);
    void setMaximizeHovered(bool hovered);

signals:
    void minimizeRequested();
    void maximizeRequested();
    void closeRequested();

private:
    IconButton* min_;
    IconButton* max_;
    IconButton* close_;
};

// Боковая навигация. На узком окне сворачивается до иконок.
class Sidebar : public QWidget {
    Q_OBJECT
public:
    struct Item { int id; Icons::Id icon; QString label; bool bottom = false; };

    explicit Sidebar(QWidget* parent = nullptr);
    void setItems(const QList<Item>& items);
    void setActive(int id);
    int  active() const { return active_; }
    void setBadge(int id, int count, const QString& tone);
    void setCompact(bool compact);
    bool compact() const { return compact_; }
    void setFooter(const QString& line1, const QString& line2);

signals:
    void pageRequested(int id);

protected:
    void paintEvent(QPaintEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void leaveEvent(QEvent*) override;
    bool event(QEvent*) override;

private:
    QRect itemRect(int index) const;
    int   itemAt(const QPoint& p) const;

    struct Badge { int count = 0; QString tone; };
    QList<Item> items_;
    QHash<int, Badge> badges_;
    int  active_ = -1;
    int  hover_ = -1;
    bool compact_ = false;
    QString footer1_, footer2_;
};

// Уведомление в углу окна, исчезает само.
class Toast : public QFrame {
    Q_OBJECT
public:
    static void show(QWidget* host, const QString& tone, const QString& title, const QString& text,
                     const QString& action = {}, std::function<void()> onAction = {}, int ms = 6000);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    Toast(QWidget* host, const QString& tone);
    void place();
    bool eventFilter(QObject* o, QEvent* e) override;
    QString tone_;
    QTimer timer_;
    static QList<QPointer<Toast>>& active();
};

// Модальное окно внутри главного: затемнение и карточка по центру.
// Системные QMessageBox выглядят чужеродно и не подхватывают тему.
class Modal : public QWidget {
    Q_OBJECT
public:
    Modal(QWidget* host, const QString& title, const QString& text = {});
    QVBoxLayout* content() const { return content_; }
    Button* addButton(const QString& text, Button::Variant variant, std::function<void()> onClick = {},
                      bool closes = true);
    void setIcon(Icons::Id icon, ColorRole role);
    void setMaxWidth(int w) { maxWidth_ = w; place(); }
    void open();
    void close();

    // Короткие формы.
    static void confirm(QWidget* host, const QString& title, const QString& text,
                        const QString& okText, bool danger, std::function<void()> onOk);
    static void info(QWidget* host, const QString& title, const QString& text);

signals:
    void closed();

protected:
    void paintEvent(QPaintEvent*) override;
    bool eventFilter(QObject* o, QEvent* e) override;
    void keyPressEvent(QKeyEvent* e) override;

private:
    void place();
    QFrame* card_;
    IconLabel* icon_ = nullptr;
    QVBoxLayout* content_;
    QHBoxLayout* buttons_;
    QHBoxLayout* header_;
    int maxWidth_ = 520;
};

} // namespace Ui
