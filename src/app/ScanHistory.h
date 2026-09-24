#pragma once

#include "../core/ThreatReport.h"

#include <QDateTime>
#include <QObject>
#include <QString>
#include <QVector>

// История проверок: переживает перезапуск, хранится в JSON в папке
// данных пользователя. Туда же подтягиваются проверки фоновой службы.
struct ScanRecord {
    QDateTime when;
    int       mode = 0;               // ScanConfig::Mode; 3 — песочница
    bool      bySchedule = false;     // запущена службой или расписанием
    int       durationMs = 0;
    qint64    objects = 0;
    int       threats = 0;
    int       critical = 0;
    bool      cancelled = false;
    QVector<Threat> findings;
    QString   reportPath;             // отчёт песочницы, если есть
    QString   target;                 // разовая проверка файла
};

class ScanHistory : public QObject {
    Q_OBJECT

public:
    static ScanHistory& instance();

    const QVector<ScanRecord>& records() const { return records_; }
    void add(const ScanRecord& r);
    void clear();

    // Проверки, сделанные службой, пока окно было закрыто.
    int importServiceScans();

    // Подменить записи в памяти без записи на диск (снимки экрана).
    void setTransient(const QVector<ScanRecord>& records);

    // Отчёт по одной проверке — читаемый текст на текущем языке.
    QString exportText(const ScanRecord& r) const;

signals:
    void changed();

private:
    ScanHistory();
    void load();
    void save() const;
    QString filePath() const;

    static constexpr int kMaxRecords = 100;
    QVector<ScanRecord> records_;
    bool transient_ = false;
};
