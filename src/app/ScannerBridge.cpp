#include "ScannerBridge.h"

#include "../core/Logger.h"
#include "../core/SandboxSession.h"
#include "../core/Scanner.h"
#include "../ipc/HelperProtocol.h"

ScannerBridge::ScannerBridge(QObject* parent)
    : QObject(parent), helper_(new Ipc::HelperClient(this))
{
    connect(helper_, &Ipc::HelperClient::eventReceived, this, &ScannerBridge::onEvent);
    connect(helper_, &Ipc::HelperClient::disconnected, this, [this]() {
        Logger::Instance().Warn("[Bridge] helper disconnected");
        emit helperLost();
        emit stateChanged(static_cast<int>(ScanState::Done), true);
    });
}

ScannerBridge::~ScannerBridge() = default;

bool ScannerBridge::helperReady() const { return helper_->isConnected(); }

bool ScannerBridge::ensureHelper(QString* error) { return helper_->ensureRunning(error); }

bool ScannerBridge::startScan(const QJsonObject& args, QString* error) {
    QString err;
    if (!ensureHelper(&err)) {
        Logger::Instance().Error("[Bridge] " + err.toStdString());
        if (error) *error = err;
        return false;
    }
    lastCancelled_ = false;
    lastPaused_ = false;
    helper_->send(Ipc::kCmdStartScan, args, [this](bool ok, const QJsonObject&, const QString& e) {
        if (ok) return;
        Logger::Instance().Error("[Bridge] scan refused: " + e.toStdString());
        emit logLine(e, static_cast<int>(LogLevel::Error));
        emit stateChanged(static_cast<int>(ScanState::Done), true);
    });
    return true;
}

void ScannerBridge::cancelScan() {
    if (helper_->isConnected()) helper_->send(Ipc::kCmdCancelScan);
}

void ScannerBridge::setScanPaused(bool paused) {
    if (!helper_->isConnected()) return;
    QJsonObject args;
    args["paused"] = paused;
    helper_->send(Ipc::kCmdPauseScan, args);
}

void ScannerBridge::applyAction(int index, int action) {
    if (index < 0) return;
    QJsonObject args;
    args["index"] = index;
    args["action"] = action;
    const bool sent = helper_->send(Ipc::kCmdApplyAction, args,
        [this, index](bool ok, const QJsonObject& result, const QString& error) {
            if (!ok) {
                emit actionApplied(index, "failed", error, false);
                return;
            }
            emit actionApplied(index, result["status"].toString(), result["message"].toString(),
                               result["success"].toBool());
        });
    if (!sent) emit actionApplied(index, "failed", "helper-gone", false);
}

void ScannerBridge::reportThreat(const QJsonObject& threat) {
    QString error;
    if (!ensureHelper(&error)) {
        emit logLine(error, static_cast<int>(LogLevel::Error));
        return;
    }
    helper_->send(Ipc::kCmdAddThreat, threat);
}

void ScannerBridge::restoreFromQuarantine(const QString& id, DoneCallback callback) {
    QString error;
    if (!ensureHelper(&error)) { callback(false, error); return; }
    QJsonObject args;
    args["id"] = id;
    helper_->send(Ipc::kCmdQuarantineRestore, args,
                  [callback](bool ok, const QJsonObject& result, const QString& e) {
                      const bool done = ok && result["success"].toBool();
                      callback(done, done ? result["path"].toString() : e);
                  });
}

void ScannerBridge::deleteFromQuarantine(const QString& id, DoneCallback callback) {
    QString error;
    if (!ensureHelper(&error)) { callback(false, error); return; }
    QJsonObject args;
    args["id"] = id;
    helper_->send(Ipc::kCmdQuarantineDelete, args,
                  [callback](bool ok, const QJsonObject& result, const QString& e) {
                      callback(ok && result["success"].toBool(), e);
                  });
}

void ScannerBridge::quarantineFile(const QString& path, const QString& name,
                                   const QString& severity, DoneCallback callback)
{
    QString error;
    if (!ensureHelper(&error)) { callback(false, error); return; }
    QJsonObject args;
    args["path"] = path;
    args["name"] = name;
    args["severity"] = severity;
    helper_->send(Ipc::kCmdQuarantineFile, args,
                  [callback](bool ok, const QJsonObject& result, const QString& e) {
                      callback(ok && result["success"].toBool(), e);
                  });
}

bool ScannerBridge::startSandbox(const QJsonObject& options, QString* error) {
    if (!ensureHelper(error)) return false;
    const bool sent = helper_->send(Ipc::kCmdSandboxRun, options,
        [this](bool ok, const QJsonObject&, const QString& e) {
            if (ok) return;
            emit sandboxFinished(static_cast<int>(SandboxSession::Result::LaunchFailed), e, {}, {});
        });
    if (!sent && error) *error = "helper-gone";
    return sent;
}

void ScannerBridge::cancelSandbox() {
    if (helper_->isConnected()) helper_->send(Ipc::kCmdSandboxCancel);
}

void ScannerBridge::enableSandboxFeature(std::function<void(bool, int, const QString&)> cb) {
    QString error;
    if (!ensureHelper(&error)) { cb(false, -1, error); return; }
    helper_->send(Ipc::kCmdSandboxEnable, {},
                  [cb](bool ok, const QJsonObject& result, const QString& e) {
                      cb(ok && result["success"].toBool(), result["code"].toInt(-1), e);
                  });
}

void ScannerBridge::queryService(ServiceCallback callback) {
    QString error;
    if (!ensureHelper(&error)) { callback(false, {}, error); return; }
    helper_->send(Ipc::kCmdServiceStatus, {},
                  [callback](bool ok, const QJsonObject& result, const QString& e) {
                      callback(ok, result["status"].toString(), e);
                  });
}

void ScannerBridge::setServiceEnabled(bool enabled, int intervalHours, bool full,
                                      ServiceCallback callback)
{
    QString error;
    if (!ensureHelper(&error)) { callback(false, {}, error); return; }
    QJsonObject args;
    args["enabled"] = enabled;
    args["intervalHours"] = intervalHours;
    args["deepScan"] = full;
    helper_->send(enabled ? Ipc::kCmdServiceInstall : Ipc::kCmdServiceUninstall, args,
                  [this, callback, enabled, intervalHours, full](bool ok, const QJsonObject&,
                                                                 const QString& e) {
                      if (!ok) { callback(false, {}, e); return; }
                      if (!enabled) { queryService(callback); return; }
                      QJsonObject cfg;
                      cfg["enabled"] = true;
                      cfg["intervalHours"] = intervalHours;
                      cfg["deepScan"] = full;
                      helper_->send(Ipc::kCmdServiceConfigure, cfg,
                                    [this, callback](bool, const QJsonObject&, const QString&) {
                                        queryService(callback);
                                    });
                  });
}

void ScannerBridge::onEvent(const QString& name, const QJsonObject& payload) {
    if (name == Ipc::kEventThreat) {
        emit threatReported(payload["index"].toInt(-1), payload);
    } else if (name == Ipc::kEventProgress) {
        lastCancelled_ = payload["cancelled"].toBool();
        emit progressChanged(payload["percent"].toInt(), payload["stage"].toString());
        const bool paused = payload["paused"].toBool();
        if (paused != lastPaused_) {
            lastPaused_ = paused;
            emit pausedChanged(paused);
        }
    } else if (name == Ipc::kEventDetail) {
        emit scanDetail(payload["item"].toString(), static_cast<qint64>(payload["objects"].toDouble()),
                        payload["elapsedMs"].toInt(), payload["etaMs"].toInt(-1));
    } else if (name == Ipc::kEventState) {
        emit stateChanged(payload["state"].toInt(), lastCancelled_);
    } else if (name == Ipc::kEventStats) {
        emit statsChanged(payload["total"].toInt(), payload["critical"].toInt());
    } else if (name == Ipc::kEventLog) {
        emit logLine(payload["message"].toString(), payload["level"].toInt());
    } else if (name == Ipc::kEventSandboxStage) {
        emit sandboxStage(payload["stage"].toString());
    } else if (name == Ipc::kEventSandboxDone) {
        emit sandboxFinished(payload["result"].toInt(), payload["message"].toString(),
                             payload["howToFix"].toString(), payload["reportPath"].toString());
    }
}
