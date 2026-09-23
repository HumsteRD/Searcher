#pragma once

#include <QWidget>
#include <QList>

class QVBoxLayout;
class QPushButton;
class QLabel;
class QFrame;
class QPropertyAnimation;

class Sidebar : public QWidget {
    Q_OBJECT

public:
    enum Page {
        Home = 0,
        Scan,
        Threats,
        Quarantine,
        Behavior,
        Logs,
        History,
        Help,
        Settings
    };

    explicit Sidebar(QWidget* parent = nullptr);

    void setActivePage(int page);

    // Счётчик рядом с пунктом Threats; 0 — бейдж скрыт.
    void setThreatCount(int count);
    // Обновляет подписи после смены языка, не пересоздавая панель.
    void retranslate();

signals:
    void pageRequested(int page);

private:
    struct Item {
        QPushButton* button = nullptr;
        QLabel*      badge  = nullptr;
        int          iconId = 0;
        int          pageId = 0;
        QString      key;      // английский оригинал подписи
    };

    QPushButton* addItem(int iconId, const QString& key, int pageId,
                         QVBoxLayout* target, bool withBadge = false);
    void updateItemStyles();
    void moveIndicatorTo(int pageId, bool animate);

    QVBoxLayout*        layout_;
    QList<Item>         items_;
    QFrame*             indicator_;
    QPropertyAnimation* indicatorAnim_;
    int                 activePage_ = 0;
};
