#include "ScanService.h"
#include "HelperProtocol.h"

#include "../core/AppSettings.h"
#include "../core/Logger.h"
#include "../core/Quarantine.h"
#include "../core/RegistryScanner.h"
#include "../core/FileSystemScanner.h"
#include "../core/ProcessScanner.h"
#include "../core/NetworkScanner.h"
#include "../core/TaskSchedulerScanner.h"
#include "../core/ScriptScanner.h"
#include "../core/PersistenceScanner.h"

#include <QJsonArray>
#include <memory>

namespace Ipc {
namespace {

constexpr int kPollIntervalMs = 80;

QString SeverityCode(Severity severity) {
    switch (severity) {
    case Severity::Critical: return "CRIT";
    case Severity::High:     return "HIGH";
    case Severity::Medium:   return "MED";
    case Severity::Low:      return "LOW";
    default:                 return "INFO";
    }
}

QString StatusName(ThreatStatus status) {
    switch (status) {
    case ThreatStatus::Quarantined: return "Quarantined";
    case ThreatStatus::Deleted:     return "Deleted";
    case ThreatStatus::Ignored:     return "Ignored";
    case ThreatStatus::Restored:    return "Restored";
    case ThreatStatus::Failed:      return "Failed";
    default:                        return "Pending";
    }
}

QString FromWide(const std::wstring& text) {
    return QString::fromStdWString(text);
}

} // namespace

ScanService::ScanService(HelperServer& server) : server_(server) {
    lastLogIndex_ = Logger::Instance().TotalWritten();
}

ScanService::~ScanService() {
    StopPolling();
}

void ScanService::RegisterModules() {
    scanner_.RegisterModule(std::make_shared<RegistryScanner>());
    scanner_.RegisterModule(std::make_shared<FileSystemScanner>());
    scanner_.RegisterModule(std::make_shared<ProcessScanner>());
    scanner_.RegisterModule(std::make_shared<NetworkScanner>());
    scanner_.RegisterModule(std::make_shared<TaskSchedulerScanner>());
    scanner_.RegisterModule(std::make_shared<ScriptScanner>());
    scanner_.RegisterModule(std::make_shared<PersistenceScanner>());
}

void ScanService::ApplySettings(const QJsonObject& args) {
    // Настройки приезжают с командой, а не читаются из реестра: помощник
    // поднялся один раз, а пользователь мог поменять их в окне уже после.
    AppSettings& settings = AppSettings::Get();

    settings.SetMode(static_cast<AppSettings::ScanMode>(
        args["mode"].toInt(static_cast<int>(AppSettings::ScanMode::Full))));
    settings.SetCustomPath(args["customPath"].toString().toStdWString());
    settings.SetDeepScan(args["deepScan"].toBool());

    const QJsonArray modules = args["modules"].toArray();
    for (int i = 0; i < AppSettings::ModuleCount && i < modules.size(); ++i)
        settings.SetModuleEnabled(i, modules.at(i).toBool(true));
}

bool ScanService::Handle(const QString& command, const QJsonObject& args,
                         QString* error, QJsonObject* result)
{
    if (command == kCmdStartScan) {
        if (scanner_.State() == ScanState::Running) {
            *error = "a scan is already running";
            return true;
        }
        ApplySettings(args);

        // Счётчики сбрасываем здесь: Scanner чистит свой список угроз
        // при старте, и без сброса первые угрозы новой проверки уедут
        // как «уже отправленные».
        lastThreatCount_ = 0;
        lastTotal_ = lastCritical_ = -1;
        lastObjects_ = -1;
        lastPercent_ = -1;
        lastStage_.clear();

        scanner_.Start();
        return true;
    }

    if (command == kCmdCancelScan) {
        scanner_.Cancel();
        return true;
    }

    if (command == kCmdApplyAction) {
        const int index = args["index"].toInt(-1);
        const int action = args["action"].toInt(-1);
        if (index < 0 || action < 0) {
            *error = "index and action are required";
            return true;
        }

        const ActionResult applied =
            scanner_.ApplyAction(static_cast<size_t>(index), action);

        Threat threat;
        (*result)["status"] = scanner_.GetThreat(static_cast<size_t>(index), threat)
            ? StatusName(threat.status) : QString("Failed");
        (*result)["success"] = applied.success;
        (*result)["message"] = FromWide(applied.message);
        return true;
    }

    if (command == kCmdQuarantineRestore || command == kCmdQuarantineDelete) {
        const std::string id = args["id"].toString().toStdString();
        if (id.empty()) {
            *error = "id is required";
            return true;
        }

        const bool done = (command == kCmdQuarantineRestore)
            ? Quarantine::Instance().Restore(id)
            : Quarantine::Instance().DeletePermanently(id);

        (*result)["success"] = done;
        if (!done) *error = "the quarantine store refused the operation";
        return true;
    }

    if (command == kCmdAddThreat) {
        // Находка приходит снаружи — её нашла страница поведения, а не
        // проверка. Список угроз один на всех, и действия к ней должны
        // применяться так же, как к остальным.
        Threat threat;
        threat.severity = static_cast<Severity>(args["severity"].toInt());
        threat.kind     = static_cast<ThreatKind>(args["kind"].toInt());
        threat.category = static_cast<ThreatCategory>(args["category"].toInt());
        threat.name        = args["name"].toString().toStdWString();
        threat.source      = args["source"].toString().toStdWString();
        threat.description = args["description"].toString().toStdWString();
        threat.evidence    = args["evidence"].toString().toStdWString();
        threat.suggestion  = args["suggestion"].toString().toStdWString();
        threat.filePath    = args["filePath"].toString().toStdWString();

        scanner_.Report(threat);
        return true;
    }

    return false;   // не наша команда
}

void ScanService::StartPolling() {
    if (polling_.exchange(true)) return;

    poller_ = std::thread([this] {
        while (polling_.load()) {
            PollOnce();
            Sleep(kPollIntervalMs);
        }
    });
}

void ScanService::StopPolling() {
    if (!polling_.exchange(false)) return;
    if (poller_.joinable()) poller_.join();
}

void ScanService::PollOnce() {
    // 1. Журнал. У помощника нет своего окна, и всё, что он делает
    //    с системой, должно быть видно там, откуда его позвали.
    const size_t written = Logger::Instance().TotalWritten();
    if (written != lastLogIndex_) {
        for (const auto& entry : Logger::Instance().Since(lastLogIndex_)) {
            QJsonObject payload;
            payload["message"] = QString::fromStdString(entry.message);
            payload["level"] = static_cast<int>(entry.level);
            server_.SendEvent(kEventLog, payload);
        }
        lastLogIndex_ = written;
    }

    // 2. Новые угрозы.
    const std::vector<Threat> threats = scanner_.Snapshot();
    if (threats.size() > lastThreatCount_) {
        for (size_t i = lastThreatCount_; i < threats.size(); ++i) {
            const Threat& threat = threats[i];
            QJsonObject payload;
            payload["index"]    = static_cast<int>(i);
            payload["kind"]     = static_cast<int>(threat.kind);
            payload["severity"] = SeverityCode(threat.severity);
            payload["name"]     = FromWide(threat.name);
            payload["source"]   = FromWide(threat.source);
            payload["why"]      = FromWide(threat.description);
            payload["evidence"] = FromWide(threat.evidence);
            server_.SendEvent(kEventThreat, payload);
        }
        lastThreatCount_ = threats.size();
    }

    // 3. Ход проверки. Обязательно ДО состояния: на «проверка окончена»
    //    интерфейс записывает результат в историю, и счётчики к этому
    //    моменту должны быть свежими. Иначе в истории окажется меньше
    //    угроз, чем в самом списке находок.
    const ScanStats stats = scanner_.Stats();

    if (stats.objectsScanned != lastObjects_) {
        lastObjects_ = stats.objectsScanned;
        QJsonObject payload;
        payload["item"]      = FromWide(stats.currentItem);
        payload["objects"]   = static_cast<double>(stats.objectsScanned);
        payload["elapsedMs"] = stats.elapsedMs;
        payload["etaMs"]     = stats.etaMs;
        server_.SendEvent(kEventDetail, payload);
    }

    if (stats.progressPercent != lastPercent_ || stats.currentStage != lastStage_) {
        lastPercent_ = stats.progressPercent;
        lastStage_   = stats.currentStage;
        QJsonObject payload;
        payload["percent"] = stats.progressPercent;
        payload["stage"]   = QString::fromStdString(stats.currentStage);
        server_.SendEvent(kEventProgress, payload);
    }

    if (stats.totalThreats != lastTotal_ || stats.criticalThreats != lastCritical_) {
        lastTotal_    = stats.totalThreats;
        lastCritical_ = stats.criticalThreats;
        QJsonObject payload;
        payload["total"]    = stats.totalThreats;
        payload["critical"] = stats.criticalThreats;
        server_.SendEvent(kEventStats, payload);
    }

    // 4. Состояние — последним.
    const int state = static_cast<int>(scanner_.State());
    if (state != lastState_) {
        lastState_ = state;
        QJsonObject payload;
        payload["state"] = state;
        server_.SendEvent(kEventState, payload);
    }
}

} // namespace Ipc
