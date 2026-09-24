#include "ScanService.h"
#include "HelperProtocol.h"

#include "../core/Logger.h"
#include "../core/Quarantine.h"
#include "../core/ThreatJson.h"
#include "../core/FileSystemScanner.h"
#include "../core/ProcessScanner.h"
#include "../core/AutorunScanner.h"
#include "../core/TaskSchedulerScanner.h"
#include "../core/PersistenceScanner.h"
#include "../core/NetworkScanner.h"

#include <QJsonArray>
#include <algorithm>
#include <memory>

namespace Ipc {
namespace {

constexpr int kPollIntervalMs = 80;

QString FromWide(const std::wstring& text) {
    return QString::fromStdWString(text);
}

std::vector<std::wstring> WideList(const QJsonValue& v) {
    std::vector<std::wstring> out;
    for (const auto& x : v.toArray()) out.push_back(x.toString().toStdWString());
    return out;
}

} // namespace

ScanService::ScanService(HelperServer& server) : server_(server) {
    lastLogIndex_ = Logger::Instance().TotalWritten();
}

ScanService::~ScanService() {
    StopPolling();
}

void ScanService::RegisterModules() {
    // Порядок выполнения: быстрые модули первыми — работающая угроза
    // найдётся за секунды, а не после получаса обхода диска.
    scanner_.RegisterModule(std::make_shared<ProcessScanner>());
    scanner_.RegisterModule(std::make_shared<AutorunScanner>());
    scanner_.RegisterModule(std::make_shared<TaskSchedulerScanner>());
    scanner_.RegisterModule(std::make_shared<PersistenceScanner>());
    scanner_.RegisterModule(std::make_shared<NetworkScanner>());
    scanner_.RegisterModule(std::make_shared<FileSystemScanner>());
}

ScanConfig ScanService::ConfigFromArgs(const QJsonObject& args) {
    // Настройки приезжают с командой: помощник поднялся один раз, а
    // пользователь мог поменять их в окне уже после.
    ScanConfig c;
    c.mode = static_cast<ScanConfig::Mode>(std::clamp(args["mode"].toInt(0), 0, 2));
    c.paths = WideList(args["paths"]);
    const QJsonArray modules = args["modules"].toArray();
    for (int i = 0; i < ScanConfig::ModuleCount && i < modules.size(); ++i)
        c.modules[i] = modules.at(i).toBool(true);
    c.extendedRules  = args["extendedRules"].toBool(false);
    c.reportPua      = args["reportPua"].toBool(false);
    c.unpackArchives = args["unpackArchives"].toBool(true);
    c.excludedPaths  = WideList(args["excludedPaths"]);
    for (const auto& h : args["allowedHashes"].toArray())
        c.allowedHashes.push_back(h.toString().toLower().toStdString());
    return c;
}

bool ScanService::Handle(const QString& command, const QJsonObject& args,
                         QString* error, QJsonObject* result)
{
    if (command == kCmdStartScan) {
        if (scanner_.State() == ScanState::Running) {
            *error = "a scan is already running";
            return true;
        }
        const ScanConfig config = ConfigFromArgs(args);

        // Счётчики сбрасываем здесь: Scanner чистит свой список угроз
        // при старте, и без сброса первые угрозы новой проверки уедут
        // как «уже отправленные».
        lastThreatCount_ = 0;
        lastTotal_ = lastCritical_ = -1;
        lastObjects_ = -1;
        lastPercent_ = -2;
        lastStage_.clear();
        lastStatuses_.clear();

        scanner_.Start(config);
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
            ? ThreatJson::StatusCode(threat.status) : QString("failed");
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

    if (command == kCmdQuarantineFile) {
        const std::wstring path = args["path"].toString().toStdWString();
        if (path.empty()) {
            *error = "path is required";
            return true;
        }
        const auto id = Quarantine::Instance().QuarantineFile(
            path, args["name"].toString().toStdWString(), args["severity"].toString().toStdWString());
        (*result)["success"] = id.has_value();
        (*result)["reboot"] = Quarantine::Instance().LastPendingReboot();
        if (!id) *error = "the file could not be moved to quarantine";
        return true;
    }

    if (command == kCmdAddThreat) {
        // Находка приходит снаружи — её нашла страница поведения, а не
        // проверка. Список угроз один на всех, и действия к ней должны
        // применяться так же, как к остальным.
        const Threat threat = ThreatJson::FromJson(args);
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
            QJsonObject payload = ThreatJson::ToJson(threats[i]);
            payload["index"] = static_cast<int>(i);
            server_.SendEvent(kEventThreat, payload);
        }
        lastThreatCount_ = threats.size();
    }

    // 3. Ход проверки. Обязательно ДО состояния: на «проверка окончена»
    //    интерфейс записывает результат в историю, и счётчики к этому
    //    моменту должны быть свежими. Иначе в истории окажется меньше
    //    угроз, чем в самом списке находок.
    const ScanStats stats = scanner_.Stats();

    if (stats.objectsScanned != lastObjects_ || stats.currentItem != lastItem_) {
        lastItem_ = stats.currentItem;
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
        payload["cancelled"] = stats.cancelled;
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
