#pragma once

#include "ThreatReport.h"
#include "../ipc/HelperClient.h"

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <functional>

// Мост между интерфейсом и проверкой.
//
// Сама проверка живёт в привилегированном помощнике: интерфейс работает
// от обычного пользователя и перечислить чужие процессы или вычистить
// ключ в HKLM не может. Сигналы остались прежними — для страниц ничего
// не изменилось, изменилось только то, откуда приходят данные.
class ScannerBridge : public QObject {
    Q_OBJECT

public:
    explicit ScannerBridge(QObject* parent = nullptr);
    ~ScannerBridge() override;

    // Поднять помощника, если он ещё не поднят. Здесь пользователь
    // видит запрос UAC. false — причина в error, её надо показать.
    bool ensureHelper(QString* error = nullptr);
    bool helperReady() const;

    void startScan();
    void cancelScan();

    // action: 0 = Quarantine, 1 = Delete, 2 = Ignore.
    // Результат приходит сигналом actionApplied().
    void applyAction(int index, int action);

    // Добавить в общий список угрозу, найденную не проверкой
    // (сейчас — наблюдением за поведением в песочнице).
    void reportThreat(const Threat& threat);

    // Операции над хранилищем карантина. Результат приходит колбэком:
    // done говорит, получилось ли, error — почему нет.
    using DoneCallback = std::function<void(bool done, const QString& error)>;
    void restoreFromQuarantine(const QString& id, DoneCallback callback);
    void deleteFromQuarantine(const QString& id, DoneCallback callback);

    // Сеанс песочницы. Держит его помощник — Windows Sandbox без прав
    // администратора не запускается. Ход и итог приходят сигналами.
    bool startSandbox(const QJsonObject& options, QString* error);
    void cancelSandbox();

    // Фоновая служба. status — "running" / "stopped" / "not installed".
    using ServiceCallback =
        std::function<void(bool ok, const QString& status, const QString& error)>;
    void queryService(ServiceCallback callback);
    void setServiceEnabled(bool enabled, int intervalHours,
                           ServiceCallback callback);

signals:
    // index — позиция угрозы в списке помощника, нужна для действий над ней.
    // kind — значение ThreatKind: от него зависит, обратимо ли действие.
    void threatReported(int index, int kind, QString severity, QString name,
                        QString source, QString why, QString evidence);
    void actionApplied(int index, QString statusText, QString message, bool success);
    void progressChanged(int percent, QString stage);
    // Детали хода сканирования: что проверяется сейчас, сколько уже
    // проверено, сколько прошло и сколько примерно осталось (мс, -1 = неизвестно).
    void scanDetail(QString currentItem, qint64 objectsScanned,
                    int elapsedMs, int etaMs);
    void stateChanged(int state);
    void statsChanged(int totalThreats, int criticalThreats);
    void logLine(QString message, int level);

    void sandboxStage(QString stage);
    // result — SandboxSession::Result. reportPath пуст, если отчёта нет.
    void sandboxFinished(int result, QString message, QString howToFix,
                         QString reportPath);

    // Помощник отвалился посреди работы. Интерфейс обязан это показать:
    // молча замерший прогресс выглядит как зависшее приложение.
    void helperLost();

private:
    void onEvent(const QString& name, const QJsonObject& payload);

    Ipc::HelperClient* helper_ = nullptr;
};
