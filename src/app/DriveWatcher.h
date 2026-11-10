#pragma once

#include <QList>
#include <QObject>
#include <QString>

class QTimer;

// Диски компьютера и появление новых.
//
// Флешка или внешний диск — второй после загрузок путь, которым на
// компьютер попадает вредоносное ПО. Программа не проверяет носитель сама
// (это долго и требует прав администратора), а предлагает это сделать
// в момент, когда о нём ещё помнят: сразу после подключения.
//
// Слежение — опросом раз в три секунды, а не по WM_DEVICECHANGE: окно,
// запущенное свёрнутым в трей, ещё не создано в системе и сообщений
// не получает, а монитор должен работать и тогда.
class DriveWatcher : public QObject {
    Q_OBJECT

public:
    struct Drive {
        QString root;        // «E:\»
        QString label;       // метка тома, может быть пустой
        bool    removable = false;
        qint64  totalBytes = 0;
        qint64  freeBytes = 0;

        QString title() const;   // «KINGSTON (E:)» или «Диск (E:)»
    };

    explicit DriveWatcher(QObject* parent = nullptr);

    void setEnabled(bool on);
    bool enabled() const { return enabled_; }

    // Локальные и съёмные диски с носителем, по порядку букв.
    static QList<Drive> drives();

signals:
    // Появился диск, которого не было при прошлом опросе.
    void driveArrived(DriveWatcher::Drive drive);

private:
    void poll();

    QTimer*  timer_ = nullptr;
    bool     enabled_ = false;
    quint32  known_ = 0;     // маска букв: бит 0 — «A:»
};
