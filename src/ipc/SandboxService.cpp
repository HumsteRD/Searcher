#include "SandboxService.h"
#include "HelperProtocol.h"

#include "../core/BehaviorReportJson.h"
#include "../core/Logger.h"

#include <Windows.h>

#include <QStandardPaths>
#include <QDir>
#include <QDateTime>

namespace Ipc {
namespace {

// Столько отчётов держим на диске: строка в истории весит байты,
// отчёт — десятки килобайт, и расти без предела он не должен.
constexpr int kMaxKeptReports = 20;

} // namespace

SandboxService::SandboxService(HelperServer& server) : server_(server) {}

SandboxService::~SandboxService() {
    Stop();
}

bool SandboxService::Handle(const QString& command, const QJsonObject& args,
                            QString* error, QJsonObject* result)
{
    if (command == kCmdSandboxCancel) {
        cancel_.Cancel();
        return true;
    }

    if (command == kCmdSandboxEnable) {
        // DISM ставит компонент и просит перезагрузку (код 3010).
        wchar_t system[MAX_PATH] = {};
        GetSystemDirectoryW(system, MAX_PATH);
        std::wstring cmd = std::wstring(L"\"") + system + L"\\dism.exe\" /online "
                           L"/enable-feature /featurename:Containers-DisposableClientVM /all /norestart /quiet";
        STARTUPINFOW si{ sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &si, &pi)) {
            *error = "cannot start DISM";
            return true;
        }
        WaitForSingleObject(pi.hProcess, 10 * 60 * 1000);
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Logger::Instance().Info("[Sandbox] DISM enable-feature exit code " + std::to_string(code));
        (*result)["code"] = static_cast<int>(code);
        (*result)["success"] = code == 0 || code == 3010;
        (*result)["reboot"] = code == 3010;
        return true;
    }

    if (command != kCmdSandboxRun) return false;

    if (running_.load()) {
        *error = "a sandbox session is already running";
        return true;
    }

    SandboxSession::Options options;
    options.samplePath       = args["samplePath"].toString().toStdWString();
    options.sampleArguments  = args["sampleArguments"].toString().toStdWString();
    options.observeTimeoutMs = args["observeTimeoutMs"].toInt(30000);
    options.waitForReportMs  = args["waitForReportMs"].toInt(300000);
    options.networking       = args["networking"].toBool();
    options.memoryMb         = args["memoryMb"].toInt(4096);
    options.closeWhenDone    = args["closeWhenDone"].toBool(true);

    if (options.samplePath.empty()) {
        *error = "samplePath is required";
        return true;
    }

    if (worker_.joinable()) worker_.join();   // хвост прошлого сеанса
    cancel_.requested.store(false);
    running_ = true;

    // Сеанс идёт минутами: держать на нём поток чтения команд нельзя,
    // иначе помощник перестанет отвечать на отмену.
    worker_ = std::thread([this, options] { Run(options); });

    (*result)["started"] = true;
    return true;
}

void SandboxService::Run(const SandboxSession::Options& options) {
    SandboxSession session;

    const auto outcome = session.Run(options, cancel_,
        [this](const std::wstring& stage) {
            QJsonObject payload;
            payload["stage"] = QString::fromStdWString(stage);
            server_.SendEvent(kEventSandboxStage, payload);
        });

    QJsonObject payload;
    payload["result"]   = static_cast<int>(outcome.result);
    payload["message"]  = QString::fromStdWString(outcome.message);
    payload["howToFix"] = QString::fromStdWString(outcome.howToFix);

    if (outcome.result == SandboxSession::Result::Completed) {
        // Отчёт сохраняем здесь же: рабочая папка сеанса уже удалена
        // вместе с копией образца, и другого экземпляра отчёта нет.
        payload["reportPath"] = SaveReport(outcome.report);
    }

    running_ = false;
    server_.SendEvent(kEventSandboxDone, payload);
}

QString SandboxService::SaveReport(const BehaviorReport& report) {
    const QString base =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (base.isEmpty()) return {};

    const QString folder = base + "/sandbox/reports";
    QDir().mkpath(folder);

    const QString path = folder + "/behaviour-" +
        QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss-zzz") + ".json";

    std::wstring error;
    if (!WriteBehaviorReportJson(report, path.toStdWString(), &error)) {
        Logger::Instance().Warn("[Sandbox] cannot keep the report: " +
                                QString::fromStdWString(error).toStdString());
        return {};
    }

    // Имя начинается с метки времени, поэтому сортировка по имени —
    // она же хронологическая.
    QDir dir(folder);
    QStringList kept = dir.entryList({ "behaviour-*.json" }, QDir::Files, QDir::Name);
    while (kept.size() > kMaxKeptReports) dir.remove(kept.takeFirst());

    return QDir::toNativeSeparators(path);
}

void SandboxService::Stop() {
    cancel_.Cancel();
    if (worker_.joinable()) worker_.join();
    running_ = false;
}

} // namespace Ipc
