#pragma once

#include <QObject>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;
class QFile;

// Обновление программы через релизы GitHub (HumsteRD/Searcher).
//
// Проверка — при запуске и раз в шесть часов. Если в настройках включена
// автоматическая установка, новая версия скачивается и ставится сама;
// если выключена (по умолчанию) — интерфейс предлагает обновиться.
// Загрузка возобновляемая: оборвалась — следующая попытка докачивает
// остаток, а не начинает заново.
class Updater : public QObject {
    Q_OBJECT

public:
    static Updater& instance();

    static QString currentVersion();
    static bool isNewer(const QString& candidate, const QString& current);

    struct Release {
        QString version;      // без буквы v
        QString notes;
        QString pageUrl;
        QString assetUrl;
        QString assetName;
        qint64  assetSize = 0;
        QString sha256;       // из файла .sha256 рядом или из описания релиза
    };

    bool busy() const { return checking_ || downloading_; }
    const Release& latest() const { return latest_; }
    bool hasUpdate() const { return available_; }
    QString downloadedPath() const { return downloaded_; }

    void check(bool manual);
    void download();
    // Запустить установщик и закрыть программу. silent — без мастера
    // (автоматическое обновление), после установки программа запустится сама.
    bool installAndQuit(bool silent);

signals:
    void checkFinished(bool available, bool manual);
    void checkFailed(QString error, bool manual);
    void downloadProgress(qint64 received, qint64 total);
    void downloadFinished(QString path);
    void downloadFailed(QString error);

private:
    Updater();
    QString cacheDir() const;

    QNetworkAccessManager* nam_;
    Release latest_;
    bool    available_ = false;
    bool    checking_ = false;
    bool    downloading_ = false;
    QString downloaded_;
    QFile*  partFile_ = nullptr;
};
