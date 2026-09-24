#pragma once

#include <QObject>
#include <QString>

class QNetworkAccessManager;

// Обновление баз сигнатур.
//
// Три источника:
//  • правила YARA-Forge — последний релиз на GitHub; перед заменой рабочего
//    файла скачанные правила компилируются, битое обновление не ставится;
//  • полная база хэшей — ресурс signatures-latest в релизах Searcher,
//    её раз в неделю пересобирает GitHub Actions из выгрузки MalwareBazaar;
//  • свежие хэши за последние двое суток — прямо из MalwareBazaar.
class SignatureUpdater : public QObject {
    Q_OBJECT

public:
    static SignatureUpdater& instance();

    bool busy() const { return pending_ > 0; }
    // manual — нажата кнопка: сообщаем результат, даже если нового нет.
    void updateAll(bool manual);

signals:
    void started();
    void finished(bool changed, QString summary, bool manual);
    void progressText(QString text);

private:
    SignatureUpdater();
    void updateRules(bool extended);
    void updateBaseHashes();
    void updateRecentHashes();
    void doneOne(bool changed, const QString& note);

    QNetworkAccessManager* nam_;
    int     pending_ = 0;
    bool    changed_ = false;
    bool    manual_ = false;
    QStringList notes_;
};
