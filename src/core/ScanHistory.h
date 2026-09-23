#pragma once

#include <QString>
#include <QVector>
#include <QDateTime>

// История проверок. Хранится в JSON рядом с настройками, поэтому
// результаты переживают закрытие приложения — до этого каждая проверка
// исчезала вместе с окном.
struct ScanRecord {
    QDateTime when;
    QString   mode;             // Quick / Full / Folder
    int       durationMs = 0;
    qint64    objectsScanned = 0;
    int       totalThreats = 0;
    int       criticalThreats = 0;
    bool      cancelled = false;

    // Краткая выжимка находок: уровень, имя, расположение.
    struct Finding { QString severity, name, source; };
    QVector<Finding> findings;

    // Полный отчёт наблюдения, если запись сделана сеансом песочницы.
    // Выжимки в findings мало: дерево процессов и лента событий живут
    // только в этом файле, а рабочая папка сеанса удаляется вместе с
    // копией образца.
    QString reportPath;
};

class ScanHistory {
public:
    static ScanHistory& instance();

    const QVector<ScanRecord>& records() const { return records_; }

    void add(const ScanRecord& r);
    void clear();

    // Подобрать проверки, сделанные фоновой службой. Она работает под
    // SYSTEM и о нашей истории ничего не знает — складывает результаты
    // в общий файл в %ProgramData%, откуда их и забираем.
    void importServiceScans();

    // Отчёт по одной проверке в виде читаемого текста.
    QString exportText(const ScanRecord& r) const;

    QString filePath() const;

private:
    ScanHistory();
    void load();
    void save() const;

    // Больше не храним: файл не должен расти бесконечно.
    static constexpr int kMaxRecords = 50;

    QVector<ScanRecord> records_;
};
