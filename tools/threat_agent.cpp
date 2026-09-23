// Наблюдатель, который запускается ВНУТРИ песочницы.
//
// Отдельная программа, а не режим основного приложения: в песочницу
// отображается только папка с агентом, и тащить туда Qt со всеми
// библиотеками ради одного отчёта незачем. Наружу агент отдаёт ровно
// один файл — JSON в единственной папке, открытой на запись.
//
//   ThreatAgent.exe --observe <файл> --out <отчёт.json> [--timeout <мс>]
//                   [--args "<аргументы образца>"] [--quiet]

#include "core/BehaviorMonitor.h"
#include "core/BehaviorReport.h"
#include "core/BehaviorReportJson.h"

#include <Windows.h>
#include <cstdio>
#include <string>

namespace {

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

void Usage() {
    printf("usage: ThreatAgent.exe --observe <file> --out <report.json>\n"
           "                       [--timeout <ms>] [--args \"<sample args>\"]\n"
           "                       [--shutdown] [--quiet]\n");
}

// Выключение машины песочницы после отчёта. Оставлять её открытой —
// значит оставить работающий образец наедине с системой и ждать, что
// пользователь догадается закрыть окно. Отчёт к этому моменту уже
// лежит в отображённой папке, терять нечего.
bool ShutdownSandbox(std::wstring& error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        error = L"OpenProcessToken failed, error " +
                std::to_wstring(GetLastError());
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME,
                                    &privileges.Privileges[0].Luid) != FALSE;
    if (ok) {
        AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
        // AdjustTokenPrivileges рапортует об успехе и тогда, когда
        // привилегию выдать не удалось: настоящий ответ в GetLastError.
        ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(token);

    if (!ok) {
        error = L"Cannot acquire shutdown privilege, error " +
                std::to_wstring(GetLastError());
        return false;
    }

    if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
                       SHTDN_REASON_MAJOR_APPLICATION |
                       SHTDN_REASON_MINOR_OTHER |
                       SHTDN_REASON_FLAG_PLANNED)) {
        error = L"ExitWindowsEx failed, error " + std::to_wstring(GetLastError());
        return false;
    }
    return true;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    std::wstring target, output, arguments;
    int  timeoutMs = 30000;
    bool quiet = false;
    bool shutdownWhenDone = false;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        const bool hasNext = (i + 1 < argc);

        if (arg == L"--observe" && hasNext)      target    = argv[++i];
        else if (arg == L"--out" && hasNext)     output    = argv[++i];
        else if (arg == L"--args" && hasNext)    arguments = argv[++i];
        else if (arg == L"--timeout" && hasNext) timeoutMs = _wtoi(argv[++i]);
        else if (arg == L"--quiet")              quiet = true;
        else if (arg == L"--shutdown")           shutdownWhenDone = true;
        else {
            printf("unknown argument: %s\n", Utf8(arg).c_str());
            Usage();
            return 2;
        }
    }

    if (target.empty() || output.empty()) {
        Usage();
        return 2;
    }
    if (timeoutMs < 1000) timeoutMs = 1000;

    BehaviorMonitor::Options options;
    options.target    = target;
    options.arguments = arguments;
    options.timeoutMs = timeoutMs;

    if (!quiet) {
        printf("observing %s for up to %d ms\n", Utf8(target).c_str(), timeoutMs);
        fflush(stdout);
    }

    CancelToken     cancel;
    BehaviorReport  report;
    BehaviorMonitor monitor;

    // Значение Run() отдельно не проверяем: неудачный запуск — тоже
    // результат наблюдения, и хост должен узнать о нём из отчёта,
    // а не из отсутствия файла.
    monitor.Run(options, cancel, report);

    std::wstring error;
    if (!WriteBehaviorReportJson(report, output, &error)) {
        printf("cannot write report: %s\n", Utf8(error).c_str());
        // Гасить машину, не отдав отчёт, нельзя: тогда о происшедшем
        // не узнает никто. Пусть окно останется и его будет видно.
        return 4;
    }

    if (!quiet) {
        printf("report written: %s\n", Utf8(output).c_str());
        printf("%zu processes, %zu events, %s\n",
               report.processes.size(), report.events.size(),
               report.launchFailed ? "sample did not start" : "sample observed");
        if (report.launchFailed)
            printf("reason: %s\n", Utf8(report.failureReason).c_str());
    }

    if (shutdownWhenDone) {
        std::wstring shutdownError;
        if (!ShutdownSandbox(shutdownError))
            printf("cannot shut down: %s\n", Utf8(shutdownError).c_str());
    }

    return report.launchFailed ? 3 : 0;
}
