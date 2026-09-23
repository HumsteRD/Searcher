#include "SandboxSession.h"
#include "SandboxEnvironment.h"
#include "WsbGenerator.h"
#include "BehaviorReportJson.h"
#include "Logger.h"

#include <QCoreApplication>
#include <QStandardPaths>
#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonParseError>

#include <Windows.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

// Как часто заглядывать в папку отчёта. Сеанс идёт минутами, чаще
// смотреть незачем.
constexpr DWORD kPollMs = 500;

const wchar_t* kAgentExeName = L"ThreatAgent.exe";
const wchar_t* kReportName   = L"report.json";

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring SandboxExePath() {
    wchar_t sys[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sys, _countof(sys))) return {};
    return std::wstring(sys) + L"\\WindowsSandbox.exe";
}

std::wstring MakeWorkFolderName() {
    return QDateTime::currentDateTime()
               .toString("yyyyMMdd-HHmmss-zzz").toStdWString();
}

} // namespace

bool SandboxSession::ReadReportJson(const std::wstring& path,
                                    BehaviorReport& out, std::wstring* error)
{
    QFile file(QString::fromStdWString(path));
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = L"Cannot open report: " + path;
        return false;
    }

    QJsonParseError parseError{};
    const QJsonDocument document =
        QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) {
            *error = L"Report is not valid JSON: " +
                     parseError.errorString().toStdWString();
        }
        return false;
    }

    const QJsonObject root = document.object();

    out = BehaviorReport{};
    out.target        = root["target"].toString().toStdWString();
    out.arguments     = root["arguments"].toString().toStdWString();
    out.durationMs    = root["durationMs"].toInt();
    out.timedOut      = root["timedOut"].toBool();
    out.killed        = root["killed"].toBool();
    out.launchFailed  = root["launchFailed"].toBool();
    out.failureReason = root["failureReason"].toString().toStdWString();
    out.rootExitCode  = static_cast<DWORD>(root["rootExitCode"].toDouble());

    for (const QJsonValue& value : root["processes"].toArray()) {
        const QJsonObject item = value.toObject();
        ObservedProcess process;
        process.pid         = static_cast<DWORD>(item["pid"].toDouble());
        process.parentPid   = static_cast<DWORD>(item["parentPid"].toDouble());
        process.image       = item["image"].toString().toStdWString();
        process.commandLine = item["commandLine"].toString().toStdWString();
        process.startedAtMs = item["startedAtMs"].toInt();
        process.exitedAtMs  = item["exitedAtMs"].toInt(-1);
        process.exitCode    = static_cast<DWORD>(item["exitCode"].toDouble());
        process.isRoot      = item["isRoot"].toBool();
        out.processes.push_back(std::move(process));
    }

    for (const QJsonValue& value : root["events"].toArray()) {
        const QJsonObject item = value.toObject();
        BehaviorEvent event;

        const QByteArray slug = item["type"].toString().toUtf8();
        bool known = false;
        event.type   = BehaviorEventTypeFromSlug(slug.constData(), &known);
        event.atMs   = item["atMs"].toInt();
        event.pid    = static_cast<DWORD>(item["pid"].toDouble());
        event.target = item["target"].toString().toStdWString();
        event.detail = item["detail"].toString().toStdWString();

        // Отчёт от более новой версии агента: тип нам незнаком, но
        // выбрасывать событие нельзя — пусть будет видно как есть.
        if (!known && !slug.isEmpty()) {
            event.detail = L"[" + QString::fromUtf8(slug).toStdWString() +
                           L"] " + event.detail;
        }
        out.events.push_back(std::move(event));
    }

    for (const QJsonValue& value : root["limitations"].toArray())
        out.limitations.push_back(value.toString().toStdWString());

    return true;
}

SandboxSession::Outcome SandboxSession::Run(const Options& options,
                                            CancelToken& cancel,
                                            ProgressSink onProgress)
{
    Outcome outcome;
    auto progress = [&](const wchar_t* stage) {
        if (onProgress) onProgress(stage);
    };

    // --- есть ли вообще во что запускать ---------------------------------
    const auto& environment = SandboxEnvironment::Get();
    if (environment.status != SandboxEnvironment::Status::Available) {
        outcome.result   = Result::Unavailable;
        outcome.message  = environment.reason;
        outcome.howToFix = environment.howToFix;
        return outcome;
    }

    // --- раскладка --------------------------------------------------------
    progress(L"Preparing the isolated session");
    std::error_code ec;

    const QString appData =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (appData.isEmpty()) {
        outcome.result  = Result::StagingFailed;
        outcome.message = L"Cannot determine the application data folder.";
        return outcome;
    }

    const fs::path work = fs::path(appData.toStdWString()) / L"sandbox" /
                          MakeWorkFolderName();
    const fs::path sampleDir = work / L"sample";
    const fs::path agentDir  = work / L"agent";
    const fs::path reportDir = work / L"report";

    outcome.workFolder = work.wstring();

    // Убрать за собой надо в любом случае: в рабочей папке лежит копия
    // образца, а это ровно тот файл, который мы считаем опасным.
    struct Cleanup {
        fs::path path;
        bool     keep = false;
        ~Cleanup() {
            if (keep || path.empty()) return;
            std::error_code ec;
            fs::remove_all(path, ec);
        }
    } cleanup{ work, options.keepWorkFolder };

    for (const auto& dir : { sampleDir, agentDir, reportDir }) {
        fs::create_directories(dir, ec);
        if (ec) {
            outcome.result  = Result::StagingFailed;
            outcome.message = L"Cannot create " + dir.wstring();
            return outcome;
        }
    }

    const fs::path sampleName = fs::path(options.samplePath).filename();
    const fs::path stagedSample = sampleDir / sampleName;
    fs::copy_file(options.samplePath, stagedSample,
                  fs::copy_options::overwrite_existing, ec);
    if (ec) {
        outcome.result  = Result::StagingFailed;
        outcome.message = L"Cannot copy the sample into the session folder: " +
                          options.samplePath;
        return outcome;
    }

    const fs::path agentSource =
        fs::path(QCoreApplication::applicationDirPath().toStdWString()) /
        kAgentExeName;
    if (!fs::exists(agentSource, ec)) {
        outcome.result  = Result::StagingFailed;
        outcome.message = std::wstring(kAgentExeName) +
                          L" is missing next to the application.";
        return outcome;
    }
    fs::copy_file(agentSource, agentDir / kAgentExeName,
                  fs::copy_options::overwrite_existing, ec);
    if (ec) {
        outcome.result  = Result::StagingFailed;
        outcome.message = L"Cannot copy the observer into the session folder.";
        return outcome;
    }

    WsbGenerator::Options wsb;
    wsb.samplePath      = stagedSample.wstring();
    wsb.sampleArguments = options.sampleArguments;
    wsb.sampleDir       = sampleDir.wstring();
    wsb.agentDir        = agentDir.wstring();
    wsb.reportDir       = reportDir.wstring();
    wsb.agentExeName    = kAgentExeName;
    wsb.reportName      = kReportName;
    wsb.networking      = options.networking;
    wsb.memoryMb        = options.memoryMb;
    wsb.timeoutMs       = options.observeTimeoutMs;
    wsb.closeWhenDone   = options.closeWhenDone;

    const std::wstring wsbPath = (work / L"session.wsb").wstring();
    const auto written = WsbGenerator::Write(wsb, wsbPath);
    if (!written.ok) {
        outcome.result  = Result::StagingFailed;
        outcome.message = written.error;
        return outcome;
    }
    outcome.wsbPath = written.wsbPath;

    // --- запуск -----------------------------------------------------------
    progress(L"Starting Windows Sandbox");

    std::wstring commandLine = L"\"" + SandboxExePath() + L"\" \"" +
                               written.wsbPath + L"\"";
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};

    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
                        0, nullptr, nullptr, &startup, &process)) {
        outcome.result  = Result::LaunchFailed;
        outcome.message = L"Cannot start Windows Sandbox, error " +
                          std::to_wstring(GetLastError());
        return outcome;
    }
    CloseHandle(process.hThread);

    Logger::Instance().Info("[Sandbox] session started: " +
                            WideToUtf8(written.wsbPath));

    // --- ожидание отчёта --------------------------------------------------
    progress(L"Waiting for the sandbox to finish");

    const ULONGLONG deadline =
        GetTickCount64() + static_cast<ULONGLONG>(options.waitForReportMs);
    bool haveReport = false;

    for (;;) {
        if (fs::exists(written.reportPath, ec)) {
            haveReport = true;
            break;
        }
        if (cancel.IsCancelled()) {
            outcome.result = Result::Cancelled;
            break;
        }
        if (GetTickCount64() >= deadline) {
            outcome.result = Result::TimedOut;
            break;
        }
        Sleep(kPollMs);
    }

    if (!haveReport) {
        // Windows Sandbox запускается через посредника, и снятие того,
        // что мы запустили, не гарантирует закрытия самой машины.
        // Обещать пользователю больше, чем делаем, не будем.
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hProcess);

        if (outcome.result == Result::Cancelled) {
            outcome.message = L"The session was cancelled. If the sandbox "
                              L"window is still open, close it manually.";
        } else {
            outcome.message =
                L"The sandbox did not produce a report within the time limit. "
                L"Windows Sandbox runs only one session at a time — if another "
                L"one is open, close it and try again.";
        }
        return outcome;
    }

    CloseHandle(process.hProcess);

    // --- разбор -----------------------------------------------------------
    progress(L"Reading the report");

    std::wstring error;
    if (!ReadReportJson(written.reportPath, outcome.report, &error)) {
        outcome.result  = Result::ReportUnreadable;
        outcome.message = error;
        // Отчёт непрочитан — рабочую папку оставляем, иначе разбираться
        // будет уже не с чем.
        cleanup.keep = true;
        return outcome;
    }

    outcome.result = Result::Completed;
    Logger::Instance().Info(
        "[Sandbox] report read: " +
        std::to_string(outcome.report.events.size()) + " events, " +
        std::to_string(outcome.report.processes.size()) + " processes");

    return outcome;
}
