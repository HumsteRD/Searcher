#include "TaskSchedulerScanner.h"
#include "SignatureDB.h"
#include "Logger.h"
#include "SignatureVerifier.h"
#include "PublisherWhitelist.h"

#include <Windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

namespace fs = std::filesystem;

namespace {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

// Достаём содержимое первого тега <Command>...</Command> из XML.
std::wstring ExtractCommand(const std::wstring& xml) {
    auto lowXml = ToLower(xml);
    const std::wstring openTag  = L"<command>";
    const std::wstring closeTag = L"</command>";

    size_t a = lowXml.find(openTag);
    if (a == std::wstring::npos) return {};
    a += openTag.size();
    size_t b = lowXml.find(closeTag, a);
    if (b == std::wstring::npos) return {};

    // Берём из оригинального xml (с регистром), но по тем же позициям
    std::wstring cmd = xml.substr(a, b - a);

    // Подчищаем пробелы
    while (!cmd.empty() && (cmd.front() == L' ' || cmd.front() == L'\t' ||
                            cmd.front() == L'\n' || cmd.front() == L'\r'))
        cmd.erase(cmd.begin());
    while (!cmd.empty() && (cmd.back() == L' ' || cmd.back() == L'\t' ||
                            cmd.back() == L'\n' || cmd.back() == L'\r'))
        cmd.pop_back();

    // Разворачиваем переменные среды (%ProgramFiles% и т.п.)
    if (cmd.find(L'%') != std::wstring::npos) {
        wchar_t expanded[MAX_PATH * 2] = {};
        DWORD n = ExpandEnvironmentStringsW(cmd.c_str(), expanded,
                                            MAX_PATH * 2);
        if (n > 0 && n <= MAX_PATH * 2) cmd.assign(expanded);
    }

    // Убираем кавычки
    if (!cmd.empty() && cmd.front() == L'"') cmd.erase(cmd.begin());
    if (!cmd.empty() && cmd.back()  == L'"') cmd.pop_back();

    return cmd;
}

// Проверяет подпись бинарника, запускаемого задачей.
bool IsTaskCommandTrusted(const std::wstring& command) {
    if (command.empty()) return false;

    std::error_code ec;
    if (!fs::exists(command, ec)) return false;

    auto sig = SignatureVerifier::Verify(fs::path(command));
    if (!sig.valid || sig.publisher.empty()) return false;
    return PublisherWhitelist::Get().IsTrusted(sig.publisher);
}

// Подозрительность по содержимому XML.
// Теперь — только реально опасные индикаторы.
bool IsSuspiciousTaskAction(const std::wstring& xml, std::wstring& whyOut) {
    auto low = ToLower(xml);

    // PowerShell с обфускацией — всегда подозрительно
    if (low.find(L"-encodedcommand") != std::wstring::npos ||
        low.find(L"frombase64string") != std::wstring::npos ||
        low.find(L" -enc ") != std::wstring::npos ||
        low.find(L" -e ") != std::wstring::npos) {
        whyOut = L"Task runs PowerShell with an encoded/obfuscated command.";
        return true;
    }

    // mshta с удалённым/инлайн скриптом
    if (low.find(L"mshta") != std::wstring::npos &&
        (low.find(L"http") != std::wstring::npos ||
         low.find(L"javascript:") != std::wstring::npos ||
         low.find(L"vbscript:") != std::wstring::npos)) {
        whyOut = L"Task uses mshta to execute remote/inline script.";
        return true;
    }

    // Запуск напрямую из Temp (не AppData/ProgramData — там много легитимного)
    if (low.find(L"\\temp\\") != std::wstring::npos &&
        (low.find(L".exe") != std::wstring::npos ||
         low.find(L".bat") != std::wstring::npos ||
         low.find(L".ps1") != std::wstring::npos ||
         low.find(L".vbs") != std::wstring::npos ||
         low.find(L".scr") != std::wstring::npos)) {
        whyOut = L"Task executes a file directly from the Temp directory.";
        return true;
    }

    // certutil/bitsadmin — частые загрузчики
    if (low.find(L"certutil") != std::wstring::npos &&
        low.find(L"-urlcache") != std::wstring::npos) {
        whyOut = L"Task uses certutil to download files (common malware technique).";
        return true;
    }

    return false;
}

void EnumerateFolder(ITaskFolder* folder,
                     IReportSink& sink,
                     CancelToken& cancel,
                     int& taskCount,
                     int& flaggedCount,
                     int& skippedBySig)
{
    if (!folder || cancel.IsCancelled()) return;

    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);

        for (LONG i = 1; i <= count; ++i) {
            if (cancel.IsCancelled()) break;

            IRegisteredTask* task = nullptr;
            if (FAILED(tasks->get_Item(_variant_t(i), &task)) || !task)
                continue;

            ++taskCount;

            BSTR name = nullptr;
            task->get_Name(&name);
            std::wstring taskName = name ? name : L"";

            BSTR xml = nullptr;
            task->get_Xml(&xml);
            std::wstring taskXml = xml ? xml : L"";

            std::wstring why;
            bool suspicious = IsSuspiciousTaskAction(taskXml, why);

            if (suspicious) {
                // Прежде чем флагать — проверим подпись запускаемого бинаря.
                std::wstring cmd = ExtractCommand(taskXml);
                if (IsTaskCommandTrusted(cmd)) {
                    ++skippedBySig;
                } else {
                    ++flaggedCount;

                    BSTR path = nullptr;
                    task->get_Path(&path);
                    std::wstring taskPath = path ? path : taskName;
                    if (path) SysFreeString(path);

                    Threat t;
                    t.kind        = ThreatKind::ScheduledTask;
                    t.category    = ThreatCategory::ScheduledTask;
                    t.severity    = Severity::High;
                    t.name        = taskName;
                    t.source      = taskPath;
                    t.description = why;
                    t.taskFullPath= taskPath;
                    t.suggestion  = L"Review the scheduled task. Delete if malicious.";

                    sink.Report(t);
                    Logger::Instance().Warn("[Task] flagged: " + WideToUtf8(taskName));
                }
            }

            if (name) SysFreeString(name);
            if (xml)  SysFreeString(xml);
            task->Release();
        }
        tasks->Release();
    }

    ITaskFolderCollection* subFolders = nullptr;
    if (SUCCEEDED(folder->GetFolders(0, &subFolders)) && subFolders) {
        LONG count = 0;
        subFolders->get_Count(&count);

        for (LONG i = 1; i <= count; ++i) {
            if (count > 0) {
                sink.Progress("Scheduled tasks",
                              static_cast<int>(100LL * i / count));
            }
            if (cancel.IsCancelled()) break;
            ITaskFolder* sub = nullptr;
            if (SUCCEEDED(subFolders->get_Item(_variant_t(i), &sub)) && sub) {
                EnumerateFolder(sub, sink, cancel, taskCount,
                                flaggedCount, skippedBySig);
                sub->Release();
            }
        }
        subFolders->Release();
    }
}

} // namespace

void TaskSchedulerScanner::Scan(IReportSink& sink, CancelToken& cancel) {
    Logger::Instance().Info("[Task] enumerating scheduled tasks...");

    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(hrInit);

    ITaskService* service = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&service);

    if (FAILED(hr) || !service) {
        Logger::Instance().Error("[Task] CoCreateInstance failed");
        if (needUninit) CoUninitialize();
        return;
    }

    hr = service->Connect(_variant_t(), _variant_t(),
                          _variant_t(), _variant_t());
    if (FAILED(hr)) {
        Logger::Instance().Error("[Task] Connect failed");
        service->Release();
        if (needUninit) CoUninitialize();
        return;
    }

    ITaskFolder* rootFolder = nullptr;
    hr = service->GetFolder(_bstr_t(L"\\"), &rootFolder);
    if (FAILED(hr) || !rootFolder) {
        Logger::Instance().Error("[Task] GetFolder failed");
        service->Release();
        if (needUninit) CoUninitialize();
        return;
    }

    int taskCount = 0, flaggedCount = 0, skippedBySig = 0;
    EnumerateFolder(rootFolder, sink, cancel, taskCount,
                    flaggedCount, skippedBySig);

    rootFolder->Release();
    service->Release();
    if (needUninit) CoUninitialize();

    Logger::Instance().Info(
        "[Task] done. Tasks: " + std::to_string(taskCount) +
        ", flagged: " + std::to_string(flaggedCount) +
        ", skipped by signature: " + std::to_string(skippedBySig));
}
