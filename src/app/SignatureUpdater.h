#pragma once

#include <QObject>
#include <QString>
#include <QStringList>

class QJsonArray;
class QNetworkAccessManager;

// Обновление баз сигнатур.
//
// Источники:
//  • правила YARA-Forge — последний релиз на GitHub; перед заменой рабочего
//    файла скачанные правила компилируются, битое обновление не ставится;
//  • базы хэшей — ресурсы релиза signatures-latest в Searcher: полная
//    (base.tsdb, раз в неделю) и свежие записи (recent.tsdb, раз в сутки).
//    Обе собирает GitHub Actions из выгрузок MalwareBazaar.
//
// У MalwareBazaar программа напрямую ничего не берёт: с осени 2026 года
// выгрузки там выдаются только по личному ключу Auth-Key, а ключ в
// программе, которая стоит у всех, — это чужой ключ у каждого.
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
    void updateHashDatabases();
    // Один файл базы из релиза: скачать, если он новее разобранного,
    // проверить и поставить на место. Ровно один вызов doneOne.
    void fetchDatabase(const QJsonArray& assets, const QString& name);
    void doneOne(bool changed, const QString& note);

    QNetworkAccessManager* nam_;
    int     pending_ = 0;
    bool    changed_ = false;
    bool    manual_ = false;
    QStringList notes_;
};
