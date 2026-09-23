// Проверка наблюдателя (BehaviorMonitor) на заведомо безвредной мишени.
//
// Песочницы на Windows Home нет, а наблюдатель проверять надо. Поэтому
// программа умеет два режима:
//
//   dynmon_test              — наблюдает за собственной копией, запущенной
//                              с ключом --sample, и печатает отчёт;
//   dynmon_test --sample     — мишень: делает ровно те безвредные действия,
//                              которые наблюдатель обязан заметить.
//
// Мишень ничего не заражает и убирает за собой: файлы создаются в %TEMP%,
// значение автозапуска удаляется через секунду после записи, соединение
// идёт на собственный слушающий сокет на 127.0.0.1.

#include "core/BehaviorMonitor.h"
#include "core/BehaviorReport.h"
#include "core/BehaviorReportJson.h"
#include "core/FileActivityWatcher.h"
#include "core/SandboxEnvironment.h"
#include "core/WsbGenerator.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <cstdio>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

const wchar_t* kRunValue = L"ThreatScannerDynProbe";

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring OwnPath() {
    wchar_t buf[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, buf, _countof(buf));
    return buf;
}

std::wstring TempDir() {
    wchar_t buf[MAX_PATH + 1] = {};
    GetTempPathW(_countof(buf), buf);
    return buf;
}

// ---------------------------------------------------------------- мишень

int RunSample() {
    const DWORD pid = GetCurrentProcessId();
    const std::wstring temp = TempDir();
    const std::wstring file = temp + L"ts-dyn-probe-" + std::to_wstring(pid) + L".txt";

    // 1. Файл: создать, дописать, переименовать.
    {
        HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            const char* text = "harmless probe payload\r\n";
            DWORD written = 0;
            WriteFile(h, text, (DWORD)strlen(text), &written, nullptr);
            FlushFileBuffers(h);
            CloseHandle(h);
        }
    }
    Sleep(400);
    const std::wstring renamed = file + L".dat";
    MoveFileW(file.c_str(), renamed.c_str());

    // 2. Автозапуск: записать значение и через секунду убрать за собой.
    {
        HKEY key = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr)
            == ERROR_SUCCESS)
        {
            std::wstring data = L"\"" + renamed + L"\" --probe";
            RegSetValueExW(key, kRunValue, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(data.c_str()),
                           (DWORD)((data.size() + 1) * sizeof(wchar_t)));
            // Пауза обязательна: наблюдатель сравнивает слепки реестра,
            // и запись, стёртая мгновенно, не попала бы ни в один из них.
            Sleep(1000);
            RegDeleteValueW(key, kRunValue);
            RegCloseKey(key);
        }
    }

    // 3. Дочерний процесс.
    {
        std::wstring cmd = L"cmd.exe /c echo probe > \"" + temp +
                           L"ts-dyn-probe-child.txt\"";
        std::vector<wchar_t> buf(cmd.begin(), cmd.end());
        buf.push_back(L'\0');

        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    // 4. Сеть: слушающий сокет и соединение с самим собой по 127.0.0.1.
    //    Наружу не ходим — проверяется наблюдатель, а не интернет.
    {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
            SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;   // порт назначит система

            if (server != INVALID_SOCKET &&
                bind(server, (sockaddr*)&addr, sizeof(addr)) == 0 &&
                listen(server, 1) == 0)
            {
                int len = sizeof(addr);
                getsockname(server, (sockaddr*)&addr, &len);

                SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                connect(client, (sockaddr*)&addr, sizeof(addr));
                SOCKET accepted = accept(server, nullptr, nullptr);

                // Соединение должно пожить дольше интервала опроса,
                // иначе наблюдатель его законно не увидит.
                Sleep(1500);

                if (accepted != INVALID_SOCKET) closesocket(accepted);
                closesocket(client);
            }
            if (server != INVALID_SOCKET) closesocket(server);
            WSACleanup();
        }
    }

    Sleep(300);
    return 7;   // заметный код возврата: проверяем, что он доехал в отчёт
}

// ---------------------------------------------------------------- отчёт

void PrintReport(const BehaviorReport& r) {
    printf("\n=== BEHAVIOR REPORT ===\n");
    printf("target        : %s\n", Utf8(r.target).c_str());
    printf("arguments     : %s\n", Utf8(r.arguments).c_str());
    printf("duration      : %d ms\n", r.durationMs);
    printf("timed out     : %s\n", r.timedOut ? "yes" : "no");
    printf("tree killed   : %s\n", r.killed ? "yes" : "no");
    printf("root exit code: %lu\n", (unsigned long)r.rootExitCode);
    if (r.launchFailed)
        printf("LAUNCH FAILED : %s\n", Utf8(r.failureReason).c_str());

    printf("\n--- processes (%zu) ---\n", r.processes.size());
    for (const auto& p : r.processes) {
        printf("  [%6d ms] pid %-6lu parent %-6lu %s%s\n",
               p.startedAtMs, (unsigned long)p.pid, (unsigned long)p.parentPid,
               Utf8(p.image).c_str(), p.isRoot ? "   (root)" : "");
        if (!p.commandLine.empty())
            printf("               cmd: %s\n", Utf8(p.commandLine).c_str());
        if (p.exitedAtMs >= 0)
            printf("               exited at %d ms, code %lu\n",
                   p.exitedAtMs, (unsigned long)p.exitCode);
        else
            printf("               still running at end of observation\n");
    }

    printf("\n--- events (%zu) ---\n", r.events.size());
    for (const auto& e : r.events) {
        printf("  [%6d ms] %-24s pid %-6lu %s\n",
               e.atMs, Utf8(BehaviorEventTypeName(e.type)).c_str(),
               (unsigned long)e.pid, Utf8(e.target).c_str());
        if (!e.detail.empty())
            printf("               %s\n", Utf8(e.detail).c_str());
    }

    printf("\n--- limitations (%zu) ---\n", r.limitations.size());
    for (const auto& l : r.limitations)
        printf("  * %s\n", Utf8(l).c_str());
    printf("\n");
}

// Проверяем не «отчёт непустой», а что в нём есть именно те события,
// которые мишень гарантированно произвела.
int CheckExpectations(const BehaviorReport& r) {
    struct Expect {
        const char* what;
        bool        found;
    };

    bool childProcess = false, fileEvent = false, renameEvent = false;
    bool regSet = false, regDeleted = false, netEvent = false;

    for (const auto& p : r.processes) if (!p.isRoot) childProcess = true;

    for (const auto& e : r.events) {
        const bool probe = e.target.find(L"ts-dyn-probe") != std::wstring::npos;
        switch (e.type) {
        case BehaviorEventType::FileCreated:
        case BehaviorEventType::FileModified:
            if (probe) fileEvent = true;
            break;
        case BehaviorEventType::FileRenamed:
            if (probe) renameEvent = true;
            break;
        case BehaviorEventType::RegistryValueSet:
            if (e.target.find(kRunValue) != std::wstring::npos) regSet = true;
            break;
        case BehaviorEventType::RegistryValueDeleted:
            if (e.target.find(kRunValue) != std::wstring::npos) regDeleted = true;
            break;
        case BehaviorEventType::NetworkConnection:
        case BehaviorEventType::NetworkListen:
            netEvent = true;
            break;
        default:
            break;
        }
    }

    Expect checks[] = {
        { "child process observed",          childProcess },
        { "probe file created or modified",  fileEvent    },
        { "probe file rename observed",      renameEvent  },
        { "autorun value added",             regSet       },
        { "autorun value removed",           regDeleted   },
        { "network activity of the sample",  netEvent     },
        { "root exit code is 7",             r.rootExitCode == 7 },
        { "limitations reported",            !r.limitations.empty() },
    };

    int failed = 0;
    printf("--- checks ---\n");
    for (const auto& c : checks) {
        printf("  [%s] %s\n", c.found ? "ok" : "FAIL", c.what);
        if (!c.found) ++failed;
    }
    printf("\n%s (%d failed)\n", failed ? "FAILURES" : "ALL CHECKS PASSED", failed);
    return failed;
}

} // namespace

const char* SandboxStatusName(SandboxEnvironment::Status status) {
    switch (status) {
    case SandboxEnvironment::Status::Available:        return "available";
    case SandboxEnvironment::Status::NotOnThisEdition: return "not on this edition";
    case SandboxEnvironment::Status::ComponentMissing: return "component missing";
    case SandboxEnvironment::Status::NoVirtualization: return "no virtualization";
    case SandboxEnvironment::Status::Unknown:          return "unknown";
    }
    return "unknown";
}

void PrintSandboxState() {
    const auto& info = SandboxEnvironment::Get();
    printf("\n--- windows sandbox ---\n");
    printf("  edition   : %s\n", Utf8(info.editionName).c_str());
    printf("  status    : %s\n", SandboxStatusName(info.status));
    printf("  executable: %s\n", info.hasExecutable ? "found" : "absent");
    if (!info.reason.empty())
        printf("  reason    : %s\n", Utf8(info.reason).c_str());
    if (!info.howToFix.empty())
        printf("  fix       : %s\n", Utf8(info.howToFix).c_str());
}

// Сборка .wsb: раскладываем то, что уедет в песочницу, по трём папкам
// и пишем конфигурацию. Запустить её на домашней редакции нельзя,
// но проверить, что файл получается правильным, — можно.
int RunWsbProbe(const std::wstring& outDir) {
    std::error_code ec;
    const fs::path root      = fs::path(outDir);
    const fs::path sampleDir = root / L"sample";
    const fs::path agentDir  = root / L"agent";
    const fs::path reportDir = root / L"report";

    for (const auto& dir : { sampleDir, agentDir, reportDir })
        fs::create_directories(dir, ec);

    // Образцом притворяется сама проверка — её же и наблюдали бы.
    const fs::path sample = sampleDir / L"sample.exe";
    fs::copy_file(OwnPath(), sample, fs::copy_options::overwrite_existing, ec);

    const fs::path agentSrc = fs::path(OwnPath()).parent_path() / L"ThreatAgent.exe";
    if (!fs::exists(agentSrc, ec)) {
        printf("ThreatAgent.exe not found next to the test binary\n");
        return 2;
    }
    fs::copy_file(agentSrc, agentDir / L"ThreatAgent.exe",
                  fs::copy_options::overwrite_existing, ec);

    WsbGenerator::Options options;
    options.samplePath = sample.wstring();
    // Копия проверки без аргументов сама полезла бы наблюдать —
    // внутри песочницы образец должен вести себя как мишень.
    options.sampleArguments = L"--sample";
    options.sampleDir  = sampleDir.wstring();
    options.agentDir   = agentDir.wstring();
    options.reportDir  = reportDir.wstring();
    options.timeoutMs  = 30000;

    const std::wstring wsbPath = (root / L"session.wsb").wstring();
    auto result = WsbGenerator::Write(options, wsbPath);

    if (!result.ok) {
        printf("wsb generation failed: %s\n", Utf8(result.error).c_str());
        return 1;
    }

    printf("wsb written : %s\n", Utf8(result.wsbPath).c_str());
    printf("report path : %s\n", Utf8(result.reportPath).c_str());
    printf("\n%s\n", Utf8(WsbGenerator::BuildXml(options)).c_str());
    return 0;
}

// Отдельная проверка одного только файлового наблюдателя: полезна,
// когда непонятно, кто виноват — наблюдение за каталогом или всё
// остальное вокруг него.
int RunFsProbe(const std::wstring& dir) {
    FileActivityWatcher watcher;
    printf("watching %s\n", Utf8(dir).c_str());

    if (!watcher.Start({ dir }, [](BehaviorEvent&& e) {
            printf("  %-16s %s\n", Utf8(BehaviorEventTypeName(e.type)).c_str(),
                   Utf8(e.target).c_str());
            fflush(stdout);
        }))
    {
        printf("watcher failed to start\n");
        return 2;
    }

    Sleep(300);
    std::wstring file = dir + L"\\ts-dyn-probe-fs.txt";
    HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        printf("cannot create %s, error %lu\n", Utf8(file).c_str(), GetLastError());
    } else {
        DWORD written = 0;
        WriteFile(h, "probe", 5, &written, nullptr);
        CloseHandle(h);
    }

    Sleep(1500);
    DeleteFileW(file.c_str());
    Sleep(1000);
    watcher.Stop();
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    for (int i = 1; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--sample") return RunSample();
        if (std::wstring(argv[i]) == L"--fswatch" && i + 1 < argc)
            return RunFsProbe(argv[i + 1]);
        if (std::wstring(argv[i]) == L"--wsb" && i + 1 < argc)
            return RunWsbProbe(argv[i + 1]);
    }

    BehaviorMonitor::Options opt;
    opt.target    = OwnPath();
    opt.arguments = L"--sample";
    opt.timeoutMs = 20000;

    printf("watching %s --sample\n", Utf8(opt.target).c_str());
    printf("watched directories:\n");
    for (const auto& d : BehaviorMonitor::DefaultWatchedDirs())
        printf("  %s\n", Utf8(d).c_str());

    CancelToken    cancel;
    BehaviorReport report;
    BehaviorMonitor monitor;

    if (!monitor.Run(opt, cancel, report)) {
        printf("monitor failed to start: %s\n", Utf8(report.failureReason).c_str());
        return 2;
    }

    PrintReport(report);
    PrintSandboxState();

    // Тот же отчёт в том виде, в каком он поедет из песочницы на хост.
    const std::wstring jsonPath = TempDir() + L"ts-dyn-report.json";
    std::wstring jsonError;
    const bool jsonWritten =
        WriteBehaviorReportJson(report, jsonPath, &jsonError);
    printf("\njson report : %s\n",
           jsonWritten ? Utf8(jsonPath).c_str() : Utf8(jsonError).c_str());

    // Мусор мишени в %TEMP% за собой убираем — проверка не должна
    // оставлять следов на машине разработчика.
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(TempDir(), ec)) {
        auto name = entry.path().filename().wstring();
        if (name.rfind(L"ts-dyn-probe", 0) == 0) fs::remove(entry.path(), ec);
    }

    return CheckExpectations(report) == 0 ? 0 : 1;
}
