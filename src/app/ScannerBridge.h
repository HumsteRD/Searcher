#pragma once

#include "../ipc/HelperClient.h"

#include <QJsonObject>
#include <QObject>
#include <QString>
#include <functional>

// Мост между интерфейсом и привилегированным помощником.
//
// Проверка и все действия над системой выполняются в помощнике: интерфейс
// работает от обычного пользователя. Помощник поднимается через UAC при
// первой операции, которой нужны права, и живёт до закрытия окна.
class ScannerBridge : public QObject {
    Q_OBJECT

public:
    explicit ScannerBridge(QObject* parent = nullptr);
    ~ScannerBridge() override;

    bool ensureHelper(QString* error = nullptr);
    bool helperReady() const;

    // args — AppSettings::scanArgs(). false — помощник не поднялся,
    // причина уходит в error.
    bool startScan(const QJsonObject& args, QString* error = nullptr);
    void cancelScan();
    void setScanPaused(bool paused);

    // action: 0 — карантин, 1 — удаление, 2 — пропустить.
    void applyAction(int index, int action);
    void reportThreat(const QJsonObject& threat);

    using DoneCallback = std::function<void(bool done, const QString& error)>;
    // При успехе вторым аргументом приходит путь, куда файл восстановлен:
    // он отличается от исходного, если то место уже занято.
    void restoreFromQuarantine(const QString& id, DoneCallback callback);
    void deleteFromQuarantine(const QString& id, DoneCallback callback);
    void quarantineFile(const QString& path, const QString& name, const QString& severity,
                        DoneCallback callback);

    bool startSandbox(const QJsonObject& options, QString* error);
    void cancelSandbox();
    // Включить компонент Windows Sandbox (DISM). Нужна перезагрузка.
    void enableSandboxFeature(std::function<void(bool ok, int code, const QString& error)> cb);

    using ServiceCallback = std::function<void(bool ok, const QString& status, const QString& error)>;
    void queryService(ServiceCallback callback);
    void setServiceEnabled(bool enabled, int intervalHours, bool full, ServiceCallback callback);

signals:
    void threatReported(int index, QJsonObject threat);
    void actionApplied(int index, QString status, QString message, bool success);
    void progressChanged(int percent, QString stage);
    void pausedChanged(bool paused);
    void scanDetail(QString currentItem, qint64 objectsScanned, int elapsedMs, int etaMs);
    void stateChanged(int state, bool cancelled);
    void statsChanged(int totalThreats, int criticalThreats);
    void logLine(QString message, int level);

    void sandboxStage(QString stage);
    void sandboxFinished(int result, QString message, QString howToFix, QString reportPath);

    void helperLost();

private:
    void onEvent(const QString& name, const QJsonObject& payload);

    Ipc::HelperClient* helper_ = nullptr;
    bool lastCancelled_ = false;
    bool lastPaused_ = false;
};
