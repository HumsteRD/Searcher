#pragma once

#include <QObject>
#include <QString>
#include <QQueue>
#include <QSet>
#include <QPair>

class QNetworkAccessManager;
class QTimer;

// Клиент VirusTotal API v3: GET /api/v3/files/{sha256}.
// Бесплатный ключ — 4 запроса в минуту, поэтому запросы идут не напрямую,
// а через очередь с интервалом kMinIntervalMs.
class VirusTotalClient : public QObject {
    Q_OBJECT

public:
    static VirusTotalClient& instance();

    // Есть ли сохранённый API-ключ.
    bool hasApiKey() const;

    // Поставить хэш в очередь. index — id строки в UI, вернётся в ответе.
    void lookup(int index, const QString& sha256);

    // Сколько запросов ждёт отправки (включая текущий).
    int pendingCount() const;

    // Разовая проверка валидности ключа (в обход очереди).
    void testApiKey();

signals:
    // found=false — файл валиден, но VirusTotal его не знает.
    // ok=false — запрос не удался, причина в error.
    void lookupFinished(int index, QString sha256, int malicious, int total,
                        bool found, bool ok, QString error);
    void queueSizeChanged(int pending);
    void apiKeyTested(bool ok, QString message);

private:
    explicit VirusTotalClient(QObject* parent = nullptr);

    void pump();
    void sendNext();
    void emitQueueSize();

    // Минимальный интервал между запросами: 4 запроса/мин у бесплатного ключа.
    static constexpr int kMinIntervalMs = 16000;

    QNetworkAccessManager*        nam_;
    QTimer*                       timer_;
    QQueue<QPair<int, QString>>   queue_;
    QSet<int>                     queued_;      // защита от дублей по index
    bool                          inFlight_ = false;
};
