#pragma once

#include "../core/ThreatReport.h"

#include <QDateTime>
#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QVector>

// Общее состояние интерфейса: ход проверки и список находок.
//
// Страницы только показывают это состояние — сами его не хранят. Поэтому
// их можно пересоздать при смене языка, не потеряв ни находок, ни хода
// проверки.
class AppState : public QObject {
    Q_OBJECT

public:
    static AppState& instance();

    struct Item {
        int    index = -1;        // номер у помощника, по нему применяются действия
        Threat threat;
        bool   busy = false;      // действие в процессе
        bool   carried = false;   // найдена до текущей проверки и перенесена в её список
        QString vtText;           // результат VirusTotal
        int    vtState = 0;       // 0 нет, 1 ждём, 2 чисто, 3 опасно, 4 неизвестно, 5 ошибка
    };

    struct Scan {
        bool      running = false;
        bool      paused = false;     // идёт, но приостановлена пользователем
        bool      finished = false;   // хотя бы одна проверка завершилась в этом запуске
        bool      cancelled = false;
        int       mode = 0;           // ScanConfig::Mode
        bool      singleTarget = false;
        QString   target;             // для разовой проверки файла
        QVector<int> stages;          // включённые модули (ScanConfig::Module) в порядке выполнения
        int       percent = 0;        // -1 — считаем объём
        QString   stage;
        QString   currentItem;
        qint64    objects = 0;
        int       elapsedMs = 0;
        int       etaMs = -1;
        QDateTime startedAt;
        QDateTime finishedAt;
    };

    const Scan& scan() const { return scan_; }
    const QVector<Item>& items() const { return items_; }
    int  pendingCount() const;       // находки без принятого решения
    int  criticalCount() const;
    int  foundInScan() const;        // найдено текущей (последней) проверкой, без перенесённых

    // Изменения — только отсюда (зовёт MainWindow по событиям моста).
    void beginScan(int mode, bool singleTarget, const QString& target, const QVector<int>& stages = {});
    // Имя этапа, которое присылает помощник, для модуля; и обратно — номер
    // текущего этапа в scan().stages (−1 — ещё подготовка, размер — всё пройдено).
    static QString stageName(int module);
    int currentStageIndex() const;
    void setProgress(int percent, const QString& stage);
    void setPaused(bool paused);
    void setDetail(const QString& item, qint64 objects, int elapsedMs, int etaMs);
    void finishScan(bool cancelled);
    void addThreat(int index, const QJsonObject& payload);
    void addLocalThreat(const Threat& threat);   // находка вне проверки (без действий через помощник)
    void clearItems();                           // убрать все находки (демонстрационный режим)
    void setBusy(int row, bool busy);
    void setThreat(int row, const Threat& threat);
    void applyActionResult(int helperIndex, const QString& status, const QString& message, bool ok);
    void setVirusTotal(int row, int state, const QString& text);
    int  rowForHelperIndex(int index) const;

signals:
    void scanChanged();      // старт, конец, прогресс
    void itemsReset();
    void itemAdded(int row);
    void itemChanged(int row);

private:
    AppState() = default;

    Scan          scan_;
    QVector<Item> items_;
};
