#pragma once

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>

class QFileSystemWatcher;
class QTimer;

// Мониторинг загрузок: новый файл в «Загрузках» или на рабочем столе
// проверяется сразу, как только браузер его докачал. Пока приложение
// работает (в том числе свёрнутым в трей).
class DownloadGuard : public QObject {
    Q_OBJECT

public:
    explicit DownloadGuard(QObject* parent = nullptr);

    void setEnabled(bool on);
    bool enabled() const { return enabled_; }
    QStringList folders() const;

private:
    void scanFolders();
    void checkReady();

    QFileSystemWatcher* watcher_ = nullptr;
    QTimer* debounce_ = nullptr;
    QTimer* settle_ = nullptr;
    bool enabled_ = false;

    struct Pending { qint64 size = -1; int stableTicks = 0; };
    QHash<QString, qint64> known_;          // путь → время изменения, уже видели
    QHash<QString, Pending> pending_;       // ждём, пока докачается
};
