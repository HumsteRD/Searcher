#include "ScannerBridge.h"
#include "Scanner.h"          // ScanState
#include "SandboxSession.h"   // SandboxSession::Result
#include "AppSettings.h"
#include "Logger.h"
#include "../ipc/HelperProtocol.h"

#include <QJsonArray>

ScannerBridge::ScannerBridge(QObject* parent)
    : QObject(parent)
    , helper_(new Ipc::HelperClient(this))
{
    connect(helper_, &Ipc::HelperClient::eventReceived,
            this, &ScannerBridge::onEvent);

    connect(helper_, &Ipc::HelperClient::disconnected, this, [this]() {
        Logger::Instance().Warn("[Bridge] helper disconnected");
        emit helperLost();
        // Проверка вместе с помощником закончилась, чем бы она ни была
        // занята: интерфейс должен выйти из состояния «идёт проверка».
        emit stateChanged(static_cast<int>(ScanState::Done));
    });
}

ScannerBridge::~ScannerBridge() = default;

bool ScannerBridge::helperReady() const {
    return helper_->isConnected();
}

bool ScannerBridge::ensureHelper(QString* error) {
    return helper_->ensureRunning(error);
}

void ScannerBridge::startScan() {
    QString error;
    if (!ensureHelper(&error)) {
        Logger::Instance().Error("[Bridge] " + error.toStdString());
        emit logLine(error, static_cast<int>(LogLevel::Error));
        // Без помощника проверка не начнётся — интерфейс не должен
        // остаться с крутящимся прогрессом навсегда.
        emit stateChanged(static_cast<int>(ScanState::Done));
        return;
    }

    // Настройки едут вместе с командой: помощник поднялся один раз,
    // а пользователь мог поменять их уже после.
    const AppSettings& settings = AppSettings::Get();

    QJsonArray modules;
    for (int i = 0; i < AppSettings::ModuleCount; ++i)
        modules.append(settings.ModuleEnabled(i));

    QJsonObject args;
    args["mode"]       = static_cast<int>(settings.Mode());
    args["customPath"] = QString::fromStdWString(settings.CustomPath());
    args["deepScan"]   = settings.DeepScan();
    args["modules"]    = modules;

    Logger::Instance().Info("[Bridge] startScan() called");
    helper_->send(Ipc::kCmdStartScan, args,
                  [this](bool ok, const QJsonObject&, const QString& error) {
        if (ok) return;
        Logger::Instance().Error("[Bridge] scan refused: " + error.toStdString());
        emit logLine(error, static_cast<int>(LogLevel::Error));
        emit stateChanged(static_cast<int>(ScanState::Done));
    });
}

void ScannerBridge::cancelScan() {
    helper_->send(Ipc::kCmdCancelScan);
}

void ScannerBridge::applyAction(int index, int action) {
    if (index < 0) return;

    QJsonObject args;
    args["index"]  = index;
    args["action"] = action;

    const bool sent = helper_->send(Ipc::kCmdApplyAction, args,
        [this, index](bool ok, const QJsonObject& result, const QString& error) {
            if (!ok) {
                emit actionApplied(index, "Failed", error, false);
                return;
            }
            emit actionApplied(index,
                               result["status"].toString(),
                               result["message"].toString(),
                               result["success"].toBool());
        });

    if (!sent) {
        emit actionApplied(index, "Failed",
                           tr("The helper is not running."), false);
    }
}

void ScannerBridge::reportThreat(const Threat& threat) {
    QString error;
    if (!ensureHelper(&error)) {
        Logger::Instance().Error("[Bridge] " + error.toStdString());
        emit logLine(error, static_cast<int>(LogLevel::Error));
        return;
    }

    QJsonObject args;
    args["severity"]    = static_cast<int>(threat.severity);
    args["kind"]        = static_cast<int>(threat.kind);
    args["category"]    = static_cast<int>(threat.category);
    args["name"]        = QString::fromStdWString(threat.name);
    args["source"]      = QString::fromStdWString(threat.source);
    args["description"] = QString::fromStdWString(threat.description);
    args["evidence"]    = QString::fromStdWString(threat.evidence);
    args["suggestion"]  = QString::fromStdWString(threat.suggestion);
    args["filePath"]    = QString::fromStdWString(threat.filePath);

    helper_->send(Ipc::kCmdAddThreat, args);
}

void ScannerBridge::restoreFromQuarantine(const QString& id,
                                          DoneCallback callback)
{
    QString error;
    if (!ensureHelper(&error)) { callback(false, error); return; }

    QJsonObject args;
    args["id"] = id;
    helper_->send(Ipc::kCmdQuarantineRestore, args,
                  [callback](bool ok, const QJsonObject& result,
                             const QString& error) {
        callback(ok && result["success"].toBool(), error);
    });
}

void ScannerBridge::deleteFromQuarantine(const QString& id,
                                         DoneCallback callback)
{
    QString error;
    if (!ensureHelper(&error)) { callback(false, error); return; }

    QJsonObject args;
    args["id"] = id;
    helper_->send(Ipc::kCmdQuarantineDelete, args,
                  [callback](bool ok, const QJsonObject& result,
                             const QString& error) {
        callback(ok && result["success"].toBool(), error);
    });
}

bool ScannerBridge::startSandbox(const QJsonObject& options, QString* error) {
    if (!ensureHelper(error)) return false;

    bool accepted = false;
    if (!helper_->send(Ipc::kCmdSandboxRun, options,
        [this](bool ok, const QJsonObject&, const QString& error) {
            if (ok) return;
            // Отказ на самом старте — не событие сеанса, но интерфейс
            // ждёт именно его, иначе кнопка останется заблокированной.
            emit sandboxFinished(
                static_cast<int>(SandboxSession::Result::LaunchFailed),
                error, QString(), QString());
        })) {
        if (error) *error = tr("The helper is not running.");
        return false;
    }
    accepted = true;
    return accepted;
}

void ScannerBridge::cancelSandbox() {
    if (helper_->isConnected()) helper_->send(Ipc::kCmdSandboxCancel);
}

void ScannerBridge::queryService(ServiceCallback callback) {
    QString error;
    if (!ensureHelper(&error)) { callback(false, {}, error); return; }

    helper_->send(Ipc::kCmdServiceStatus, {},
                  [callback](bool ok, const QJsonObject& result,
                             const QString& error) {
        callback(ok, result["status"].toString(), error);
    });
}

void ScannerBridge::setServiceEnabled(bool enabled, int intervalHours,
                                      ServiceCallback callback)
{
    QString error;
    if (!ensureHelper(&error)) { callback(false, {}, error); return; }

    QJsonObject args;
    args["enabled"]       = enabled;
    args["intervalHours"] = intervalHours;
    args["deepScan"]      = false;

    helper_->send(enabled ? Ipc::kCmdServiceInstall : Ipc::kCmdServiceUninstall,
                  args, [this, callback](bool ok, const QJsonObject&,
                                         const QString& error) {
        if (!ok) { callback(false, {}, error); return; }
        // Состояние перечитываем у самого диспетчера служб: «команда
        // прошла» и «служба работает» — разные утверждения.
        queryService(callback);
    });
}

void ScannerBridge::onEvent(const QString& name, const QJsonObject& payload) {
    if (name == Ipc::kEventSandboxStage) {
        emit sandboxStage(payload["stage"].toString());
        return;
    }

    if (name == Ipc::kEventSandboxDone) {
        emit sandboxFinished(payload["result"].toInt(),
                             payload["message"].toString(),
                             payload["howToFix"].toString(),
                             payload["reportPath"].toString());
        return;
    }

    if (name == Ipc::kEventThreat) {
        emit threatReported(payload["index"].toInt(),
                            payload["kind"].toInt(),
                            payload["severity"].toString(),
                            payload["name"].toString(),
                            payload["source"].toString(),
                            payload["why"].toString(),
                            payload["evidence"].toString());
        return;
    }

    if (name == Ipc::kEventProgress) {
        emit progressChanged(payload["percent"].toInt(),
                             payload["stage"].toString());
        return;
    }

    if (name == Ipc::kEventDetail) {
        emit scanDetail(payload["item"].toString(),
                        static_cast<qint64>(payload["objects"].toDouble()),
                        payload["elapsedMs"].toInt(),
                        payload["etaMs"].toInt(-1));
        return;
    }

    if (name == Ipc::kEventState) {
        emit stateChanged(payload["state"].toInt());
        return;
    }

    if (name == Ipc::kEventStats) {
        emit statsChanged(payload["total"].toInt(), payload["critical"].toInt());
        return;
    }

    if (name == Ipc::kEventLog) {
        emit logLine(payload["message"].toString(), payload["level"].toInt());
        return;
    }
}
