#pragma once

#include "../core/ThreatReport.h"

#include <QObject>
#include <QString>
#include <QStringList>

// Проверка отдельных файлов прямо в процессе интерфейса — без помощника
// и без запроса UAC. Для перетащенного файла, кнопки «Проверить файл»
// и мониторинга загрузок: читать свои файлы права администратора не нужны.
class LocalCheck : public QObject {
    Q_OBJECT

public:
    static LocalCheck& instance();

    struct Result {
        QString path;
        bool    clean = true;
        bool    skipped = false;      // не прочитан, пустой, слишком большой
        QString skipReason;
        Threat  threat;               // заполнен, если не clean
        QString sha256;
        QString signer;
        qint64  size = 0;
        QString container;
    };

    // Асинхронно. tag возвращается в сигнале — по нему вызывающий
    // отличает свои запросы (перетаскивание, монитор загрузок).
    void check(const QStringList& files, const QString& tag);
    bool busy() const { return running_ > 0; }

signals:
    void started(QString tag, int count);
    void fileChecked(QString tag, LocalCheck::Result result);
    void finished(QString tag);

private:
    LocalCheck();
    int running_ = 0;
};

Q_DECLARE_METATYPE(LocalCheck::Result)
