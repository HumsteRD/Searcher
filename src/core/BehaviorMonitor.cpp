#include "BehaviorMonitor.h"
#include "FileActivityWatcher.h"
#include "RegistryActivityWatcher.h"
#include "NetworkActivityWatcher.h"
#include "Logger.h"

#include <winternl.h>
#include <algorithm>
#include <cwctype>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

// Потолок на число процессов в job: программа, размножающаяся без
// границ, не должна валить машину, на которой её изучают.
constexpr DWORD kMaxProcesses = 128;

// Сколько ждать после остановки образца, прежде чем снимать
// наблюдателей: запись файла и уведомление о ней разъезжаются во времени.
constexpr int kDrainMs = 500;

// Как часто просыпаться в ожидании сообщений job'а, чтобы успевать
// реагировать на отмену и таймаут.
constexpr DWORD kPumpSliceMs = 200;

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
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

std::wstring ExpandEnv(const wchar_t* name) {
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD n = GetEnvironmentVariableW(name, buf, _countof(buf));
    if (n == 0 || n >= _countof(buf)) return {};
    return buf;
}

std::wstring TrimSlash(std::wstring s) {
    while (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
    return s;
}

// Приводим список к пригодному виду: без хвостовых слэшей, без
// несуществующих путей, без точных повторов.
//
// Вложенные корни НЕ схлопываем, хотя соблазн есть. Проверено на
// Windows 11: рекурсивное наблюдение за %LOCALAPPDATA% не приносит
// ни одного события из %LOCALAPPDATA%\Temp, хотя Temp — обычный
// каталог, а не точка повторной обработки. Оставить только родителя
// значило бы молча ослепнуть на самое интересное место — папку,
// куда дропперы пишут в первую очередь. Повторы, которые из-за этого
// возможны на других парах каталогов, гасит FileActivityWatcher.
std::vector<std::wstring> NormalizeRoots(std::vector<std::wstring> dirs) {
    std::vector<std::wstring> out;
    for (auto& d : dirs) {
        d = TrimSlash(d);
        if (d.empty()) continue;
        std::error_code ec;
        if (!fs::is_directory(d, ec)) continue;
        if (std::find(out.begin(), out.end(), d) == out.end()) out.push_back(d);
    }
    return out;
}

std::wstring ProcessImagePath(HANDLE process) {
    wchar_t buf[MAX_PATH * 4] = {};
    DWORD sz = _countof(buf);
    if (QueryFullProcessImageNameW(process, 0, buf, &sz))
        return std::wstring(buf, sz);
    return {};
}

struct ProcBasicInfo {
    LONG      ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

using PfnNtQueryInformationProcess =
    LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

PfnNtQueryInformationProcess NtQip() {
    static PfnNtQueryInformationProcess fn = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<PfnNtQueryInformationProcess>(
                           GetProcAddress(ntdll, "NtQueryInformationProcess"))
                     : nullptr;
    }();
    return fn;
}

bool QueryBasicInfo(HANDLE process, ProcBasicInfo& out) {
    auto fn = NtQip();
    if (!fn) return false;
    ULONG len = 0;
    return fn(process, 0 /*ProcessBasicInformation*/, &out, sizeof(out), &len) >= 0;
}

// Командная строка живёт в блоке параметров процесса, читать её
// приходится из чужой памяти. Не получилось — не беда: путь к образу
// уже есть, а выдумывать содержимое отчёта нельзя.
std::wstring ReadCommandLine(HANDLE process, const ProcBasicInfo& info) {
    if (!info.PebBaseAddress) return {};

    PEB peb{};
    if (!ReadProcessMemory(process, info.PebBaseAddress, &peb, sizeof(peb), nullptr))
        return {};
    if (!peb.ProcessParameters) return {};

    RTL_USER_PROCESS_PARAMETERS params{};
    if (!ReadProcessMemory(process, peb.ProcessParameters, &params,
                           sizeof(params), nullptr))
        return {};

    USHORT bytes = params.CommandLine.Length;
    if (bytes == 0 || bytes > 32 * 1024 || !params.CommandLine.Buffer) return {};

    std::wstring cmd(bytes / sizeof(wchar_t), L'\0');
    if (!ReadProcessMemory(process, params.CommandLine.Buffer,
                           cmd.data(), bytes, nullptr))
        return {};
    return cmd;
}

// Скрипт сам себя не запустит: CreateProcess умеет только образы.
// Интерпретатор становится корнем дерева — это видно в отчёте и
// честнее, чем делать вид, что запущен сам .ps1.
std::wstring BuildCommandLine(const std::wstring& target,
                              const std::wstring& arguments)
{
    std::wstring ext = ToLower(fs::path(target).extension().wstring());
    std::wstring quoted = L"\"" + target + L"\"";
    std::wstring tail = arguments.empty() ? L"" : L" " + arguments;

    if (ext == L".bat" || ext == L".cmd")
        return L"cmd.exe /c " + quoted + tail;
    if (ext == L".ps1")
        return L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
               + quoted + tail;
    if (ext == L".vbs" || ext == L".js" || ext == L".wsf")
        return L"wscript.exe " + quoted + tail;

    return quoted + tail;
}

} // namespace

const wchar_t* BehaviorEventTypeName(BehaviorEventType type) {
    switch (type) {
    case BehaviorEventType::ProcessStarted:       return L"process started";
    case BehaviorEventType::ProcessExited:        return L"process exited";
    case BehaviorEventType::FileCreated:          return L"file created";
    case BehaviorEventType::FileModified:         return L"file modified";
    case BehaviorEventType::FileDeleted:          return L"file deleted";
    case BehaviorEventType::FileRenamed:          return L"file renamed";
    case BehaviorEventType::RegistryValueSet:     return L"registry value added";
    case BehaviorEventType::RegistryValueChanged: return L"registry value changed";
    case BehaviorEventType::RegistryValueDeleted: return L"registry value deleted";
    case BehaviorEventType::RegistryKeyCreated:   return L"registry key created";
    case BehaviorEventType::RegistryKeyDeleted:   return L"registry key deleted";
    case BehaviorEventType::NetworkConnection:    return L"network connection";
    case BehaviorEventType::NetworkListen:        return L"listening socket";
    case BehaviorEventType::MonitorNote:          return L"monitor note";
    }
    return L"event";
}

std::vector<std::wstring> BehaviorMonitor::DefaultWatchedDirs() {
    std::vector<std::wstring> dirs = {
        ExpandEnv(L"TEMP"),
        ExpandEnv(L"APPDATA"),
        ExpandEnv(L"LOCALAPPDATA"),
        ExpandEnv(L"ProgramData"),
        ExpandEnv(L"PUBLIC"),
    };

    if (auto appdata = ExpandEnv(L"APPDATA"); !appdata.empty()) {
        dirs.push_back(appdata +
            L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    }
    if (auto windir = ExpandEnv(L"WINDIR"); !windir.empty()) {
        // Весь System32 не берём: он и без образцов переписывается
        // непрерывно, и полезные события утонули бы в этом потоке.
        // Берём места, куда обычные программы не пишут никогда.
        dirs.push_back(windir + L"\\System32\\Tasks");
        dirs.push_back(windir + L"\\System32\\drivers");
        dirs.push_back(windir + L"\\Temp");
    }

    return NormalizeRoots(std::move(dirs));
}

int BehaviorMonitor::ElapsedMs() const {
    using namespace std::chrono;
    return static_cast<int>(
        duration_cast<milliseconds>(steady_clock::now() - startedAt_).count());
}

void BehaviorMonitor::Emit(BehaviorEvent&& e) {
    e.atMs = ElapsedMs();

    BehaviorEvent copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!report_) return;
        report_->events.push_back(e);
        copy = report_->events.back();
    }
    // Колбэк интерфейса зовём без мьютекса: он рисует, ходит в очередь
    // Qt и вообще не обязан быть быстрым.
    if (onEvent_) onEvent_(std::move(copy));
}

bool BehaviorMonitor::IsWatchedPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    return live_.find(pid) != live_.end();
}

void BehaviorMonitor::OnProcessStarted(DWORD pid, bool isRoot) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (live_.find(pid) != live_.end()) return;   // уже учтён
    }

    // Дескриптор держим до самого конца: пока он открыт, номер процесса
    // не может быть переиспользован системой, и сетевые события не
    // приклеятся к чужому процессу с тем же PID.
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    ObservedProcess p;
    p.pid = pid;
    p.isRoot = isRoot;
    p.startedAtMs = ElapsedMs();

    if (h) {
        p.image = ProcessImagePath(h);
        ProcBasicInfo info{};
        if (QueryBasicInfo(h, info)) {
            p.parentPid = static_cast<DWORD>(info.InheritedFromUniqueProcessId);
            p.commandLine = ReadCommandLine(h, info);
        }
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (report_) report_->processes.push_back(p);
        live_[pid] = h;   // возможно nullptr: процесс умер раньше, чем открыли
    }

    BehaviorEvent e;
    e.type   = BehaviorEventType::ProcessStarted;
    e.pid    = pid;
    e.target = p.image.empty() ? L"<unknown image>" : p.image;
    e.detail = p.commandLine;
    Emit(std::move(e));
}

void BehaviorMonitor::OnProcessExited(DWORD pid) {
    HANDLE h = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = live_.find(pid);
        if (it == live_.end()) return;
        h = it->second;
        live_.erase(it);
    }

    DWORD code = 0;
    if (h) GetExitCodeProcess(h, &code);

    std::wstring image;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (report_) {
            for (auto& p : report_->processes) {
                if (p.pid != pid || p.exitedAtMs >= 0) continue;
                p.exitedAtMs = ElapsedMs();
                p.exitCode = code;
                image = p.image;
                if (p.isRoot) report_->rootExitCode = code;
                break;
            }
        }
    }
    if (h) CloseHandle(h);

    BehaviorEvent e;
    e.type   = BehaviorEventType::ProcessExited;
    e.pid    = pid;
    e.target = image.empty() ? L"<unknown image>" : image;
    e.detail = L"exit code " + std::to_wstring(code);
    Emit(std::move(e));
}

bool BehaviorMonitor::Run(const Options& opt, CancelToken& cancel,
                          BehaviorReport& report, BehaviorSink onEvent)
{
    report = BehaviorReport{};
    report.target    = opt.target;
    report.arguments = opt.arguments;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        report_ = &report;
        live_.clear();
    }
    onEvent_ = std::move(onEvent);
    startedAt_ = std::chrono::steady_clock::now();

    auto fail = [&](const std::wstring& reason) {
        report.launchFailed  = true;
        report.failureReason = reason;
        report.durationMs    = ElapsedMs();
        std::lock_guard<std::mutex> lock(mutex_);
        report_ = nullptr;
        return false;
    };

    std::error_code ec;
    if (!fs::exists(opt.target, ec))
        return fail(L"Target not found: " + opt.target);

    // --- job: одно дерево, ничего не разбегается ------------------------
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) return fail(L"CreateJobObject failed, error " +
                          std::to_wstring(GetLastError()));

    HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (!port) {
        CloseHandle(job);
        return fail(L"CreateIoCompletionPort failed");
    }

    JOBOBJECT_ASSOCIATE_COMPLETION_PORT assoc{};
    assoc.CompletionKey  = job;
    assoc.CompletionPort = port;
    SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation,
                            &assoc, sizeof(assoc));

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = kMaxProcesses;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                            &limits, sizeof(limits));

    // --- наблюдатели: поднимаем ДО запуска образца ----------------------
    auto sink = [this](BehaviorEvent&& e) { Emit(std::move(e)); };

    FileActivityWatcher     files;
    RegistryActivityWatcher registry;
    NetworkActivityWatcher  network;

    std::vector<std::wstring> roots;
    std::vector<std::wstring> watchedRoots;
    if (opt.watchFiles) {
        roots = opt.watchedDirs.empty() ? DefaultWatchedDirs() : opt.watchedDirs;
        // Папка образца: дропперы часто пишут рядом с собой.
        auto own = fs::path(opt.target).parent_path().wstring();
        if (!own.empty()) roots.push_back(own);
        roots = NormalizeRoots(std::move(roots));

        if (!files.Start(roots, sink)) {
            report.limitations.push_back(
                L"File system was not watched: no directory could be opened.");
        }
        // Список берём сразу: Stop() его очищает, а нужен он в самом конце.
        watchedRoots = files.WatchedRoots();
        for (const auto& r : roots) {
            if (std::find(watchedRoots.begin(), watchedRoots.end(), r)
                    == watchedRoots.end()) {
                report.limitations.push_back(
                    L"Directory could not be watched: " + r);
            }
        }
    }
    if (opt.watchRegistry) {
        if (!registry.Start(RegistryActivityWatcher::DefaultKeys(), sink)) {
            report.limitations.push_back(
                L"Registry was not watched: no key could be opened.");
        }
    }
    if (opt.watchNetwork) {
        if (!network.Start([this](DWORD pid) { return IsWatchedPid(pid); }, sink)) {
            report.limitations.push_back(
                L"Network was not watched: connection tables are unavailable.");
        }
    }

    // --- запуск ---------------------------------------------------------
    std::wstring cmdline = BuildCommandLine(opt.target, opt.arguments);
    std::wstring workDir = opt.workingDir.empty()
        ? fs::path(opt.target).parent_path().wstring()
        : opt.workingDir;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::vector<wchar_t> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back(L'\0');

    BOOL launched = CreateProcessW(
        nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
        // CREATE_NO_WINDOW: консольный образец не должен отбирать фокус
        // и мигать окном поверх интерфейса. На оконные программы флаг
        // не влияет — их окна всё равно появятся.
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        nullptr,
        workDir.empty() ? nullptr : workDir.c_str(),
        &si, &pi);

    if (!launched) {
        DWORD err = GetLastError();
        files.Stop();
        registry.Stop();
        network.Stop();
        CloseHandle(port);
        CloseHandle(job);
        return fail(L"CreateProcess failed, error " + std::to_wstring(err));
    }

    // Приписываем к job ещё до первой инструкции образца: иначе процесс,
    // успевший породить потомка, увёл бы его из-под наблюдения.
    if (!AssignProcessToJobObject(job, pi.hProcess)) {
        DWORD err = GetLastError();
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        files.Stop();
        registry.Stop();
        network.Stop();
        CloseHandle(port);
        CloseHandle(job);
        return fail(L"AssignProcessToJobObject failed, error " +
                    std::to_wstring(err));
    }

    OnProcessStarted(pi.dwProcessId, /*isRoot=*/true);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    Logger::Instance().Info("[Dyn] watching " + WideToUtf8(opt.target) +
                            ", pid " + std::to_string(pi.dwProcessId));

    // --- ожидание -------------------------------------------------------
    const int deadline = opt.timeoutMs;
    bool allExited = false;

    for (;;) {
        DWORD msg = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* ov = nullptr;

        BOOL ok = GetQueuedCompletionStatus(port, &msg, &key, &ov, kPumpSliceMs);
        if (ok) {
            DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(ov));
            switch (msg) {
            case JOB_OBJECT_MSG_NEW_PROCESS:
                OnProcessStarted(pid, /*isRoot=*/false);
                break;
            case JOB_OBJECT_MSG_EXIT_PROCESS:
            case JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS:
                OnProcessExited(pid);
                break;
            case JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO:
                allExited = true;
                break;
            case JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT: {
                BehaviorEvent e;
                e.type   = BehaviorEventType::MonitorNote;
                e.target = opt.target;
                e.detail = L"Process limit of " + std::to_wstring(kMaxProcesses) +
                           L" reached; further child processes were blocked";
                Emit(std::move(e));
                break;
            }
            default:
                break;
            }
        }

        if (allExited) break;

        if (cancel.IsCancelled()) {
            report.limitations.push_back(L"Observation was cancelled by the user.");
            break;
        }
        if (ElapsedMs() >= deadline) {
            report.timedOut = true;
            break;
        }
    }

    // --- завершение -----------------------------------------------------
    bool stillRunning;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stillRunning = !live_.empty();
    }

    if (stillRunning && opt.killTreeWhenDone) {
        TerminateJobObject(job, 1);
        report.killed = true;

        // Добираем сообщения о завершении, чтобы в отчёте не осталось
        // процессов, вечно висящих в статусе «работает».
        const int drainDeadline = ElapsedMs() + 2000;
        for (;;) {
            DWORD msg = 0; ULONG_PTR key = 0; OVERLAPPED* ov = nullptr;
            if (!GetQueuedCompletionStatus(port, &msg, &key, &ov, 100)) {
                if (ElapsedMs() >= drainDeadline) break;
                continue;
            }
            DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(ov));
            if (msg == JOB_OBJECT_MSG_EXIT_PROCESS ||
                msg == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS) {
                OnProcessExited(pid);
            } else if (msg == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) {
                break;
            }
            if (ElapsedMs() >= drainDeadline) break;
        }
    }

    // Уведомления о файлах и реестре приходят с задержкой: снимать
    // наблюдателей сразу — значит потерять последние действия образца.
    Sleep(kDrainMs);

    files.Stop();
    registry.Stop();
    network.Stop();

    CloseHandle(pi.hProcess);
    CloseHandle(port);
    CloseHandle(job);   // KILL_ON_JOB_CLOSE добьёт всё, что уцелело

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [pid, h] : live_) if (h) CloseHandle(h);
        live_.clear();
    }

    report.durationMs = ElapsedMs();

    std::stable_sort(report.events.begin(), report.events.end(),
                     [](const BehaviorEvent& a, const BehaviorEvent& b) {
                         return a.atMs < b.atMs;
                     });

    // Границы наблюдения — часть отчёта, а не сноска. Отчёт без них
    // читается как полная картина происходившего, а это не так.
    auto& lim = report.limitations;
    lim.push_back(L"No kernel driver: code injection, in-memory activity and "
                  L"direct system calls are not observed.");
    lim.push_back(L"File and registry changes are not attributed to a process: "
                  L"user-mode monitoring does not report the author of a change.");
    lim.push_back(L"Registry changes made and reverted between two notifications "
                  L"are invisible.");
    lim.push_back(L"Connection tables are polled, so connections shorter than the "
                  L"polling interval are missed; DNS lookups are not visible.");
    if (opt.watchFiles) {
        std::wstring watched = L"Only these directories were watched: ";
        for (size_t i = 0; i < watchedRoots.size(); ++i) {
            if (i) watched += L"; ";
            watched += watchedRoots[i];
        }
        lim.push_back(watched + L".");
    }
    if (report.timedOut) {
        lim.push_back(L"Time limit reached: the sample was still running and may "
                      L"do more than what is listed here.");
    }

    Logger::Instance().Info(
        "[Dyn] done in " + std::to_string(report.durationMs) + " ms, " +
        std::to_string(report.processes.size()) + " processes, " +
        std::to_string(report.events.size()) + " events");

    {
        std::lock_guard<std::mutex> lock(mutex_);
        report_ = nullptr;
    }
    onEvent_ = {};
    return true;
}
