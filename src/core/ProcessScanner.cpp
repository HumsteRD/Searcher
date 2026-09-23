#include "ProcessScanner.h"
#include "SignatureDB.h"
#include "Logger.h"
#include "SignatureVerifier.h"
#include "PublisherWhitelist.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <filesystem>
#include <unordered_map>
#include <algorithm>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

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
        [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

std::wstring GetProcessPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};

    wchar_t buf[MAX_PATH * 4] = {};
    DWORD sz = sizeof(buf) / sizeof(wchar_t);

    std::wstring path;
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
        path.assign(buf, sz);
    }
    CloseHandle(h);
    return path;
}

struct SystemProc {
    const wchar_t* name;
    const wchar_t* canonicalDir;
    bool           protectedProc; // защищённый (PPL) — путь часто не читается
};

const std::vector<SystemProc>& KnownSystemProcs() {
    static const std::vector<SystemProc> kList = {
        {L"svchost.exe",     L"system32", false},
        {L"csrss.exe",       L"system32", true },
        {L"lsass.exe",       L"system32", true },
        {L"services.exe",    L"system32", true },
        {L"winlogon.exe",    L"system32", true },
        {L"smss.exe",        L"system32", true },
        {L"wininit.exe",     L"system32", true },
        {L"spoolsv.exe",     L"system32", false},
        {L"conhost.exe",     L"system32", false},
        {L"dwm.exe",         L"system32", true },
        {L"taskhostw.exe",   L"system32", false},
        {L"taskhost.exe",    L"system32", false},
        {L"sihost.exe",      L"system32", false},
        {L"unsecapp.exe",    L"system32", false},
        {L"fontdrvhost.exe", L"system32", true },
        {L"audiodg.exe",     L"system32", true },
        {L"explorer.exe",    L"windows",  false},
    };
    return kList;
}

// Whitelist известных легитимных процессов Windows / популярного софта
// ПО ИМЕНИ — на случай если подпись не читается (защищённые процессы,
// процессы под другим пользователем и т.д.)
bool IsWhitelistedProcName(const std::wstring& nameLow) {
    static const std::vector<std::wstring> kNames = {
        // Windows системные
        L"searchprotocolhost.exe", L"searchfilterhost.exe",
        L"searchindexer.exe", L"runtimebroker.exe",
        L"backgroundtaskhost.exe", L"dllhost.exe",
        L"wmiprvse.exe", L"ctfmon.exe", L"taskmgr.exe",
        L"securityhealthservice.exe", L"securityhealthsystray.exe",
        L"applicationframehost.exe", L"shellexperiencehost.exe",
        L"startmenuexperiencehost.exe", L"textinputhost.exe",
        L"crossdeviceresume.exe", L"crossdevice.exe",
        L"phoneexperiencehost.exe", L"lockapp.exe",
        L"useroobebroker.exe", L"systemsettings.exe",
        L"smartscreen.exe", L"wudfhost.exe",

        // Update-сервисы известных вендоров
        L"microsoftedgeupdate.exe", L"googleupdate.exe",
        L"bravecrashhandler.exe", L"bravecrashhandler64.exe",
        L"gigabyteupdateservice.exe",
    };
    for (const auto& n : kNames) if (nameLow == n) return true;
    return false;
}

std::wstring CheckSystemMasquerade(const std::wstring& procName,
                                   const std::wstring& procPath)
{
    // Если путь пустой — НЕ судим о маскараде. Пустой путь = защищённый
    // процесс, который мы не смогли прочитать (это не подозрительно само по себе).
    if (procPath.empty()) return L"";

    auto nameLow = ToLower(procName);
    auto pathLow = ToLower(procPath);

    for (const auto& sys : KnownSystemProcs()) {
        if (nameLow == ToLower(sys.name)) {
            std::wstring canon = ToLower(sys.canonicalDir);
            if (pathLow.find(L"\\" + canon + L"\\") == std::wstring::npos) {
                return L"Process named '" + procName +
                       L"' should run from %WINDIR%\\" + sys.canonicalDir +
                       L", but runs from: " + procPath;
            }
            return L"";
        }
    }
    return L"";
}

std::wstring CheckSuspiciousParent(const std::wstring& childName,
                                   const std::wstring& parentName)
{
    auto childLow  = ToLower(childName);
    auto parentLow = ToLower(parentName);

    static const std::vector<std::wstring> dangerousChildren = {
        L"powershell.exe", L"pwsh.exe", L"cmd.exe",
        L"wscript.exe", L"cscript.exe", L"mshta.exe",
        L"rundll32.exe", L"regsvr32.exe", L"certutil.exe",
        L"bitsadmin.exe",
    };
    static const std::vector<std::wstring> dangerousParents = {
        L"winword.exe", L"excel.exe", L"powerpnt.exe",
        L"outlook.exe", L"onenote.exe", L"acrord32.exe",
        L"acrobat.exe",
    };

    bool c = false, p = false;
    for (const auto& x : dangerousChildren) if (childLow  == x) { c = true; break; }
    for (const auto& x : dangerousParents)  if (parentLow == x) { p = true; break; }

    if (c && p) {
        return L"Suspicious parent: " + parentName + L" spawned " +
               childName + L" (typical of macro malware or phishing).";
    }
    return L"";
}

bool IsTrustedSigned(const std::wstring& path) {
    if (path.empty()) return false;
    fs::path p(path);
    auto sig = SignatureVerifier::Verify(p);
    if (!sig.valid || sig.publisher.empty()) return false;
    return PublisherWhitelist::Get().IsTrusted(sig.publisher);
}

} // namespace

void ProcessScanner::Scan(IReportSink& sink, CancelToken& cancel) {
    Logger::Instance().Info("[Proc] enumerating processes...");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Logger::Instance().Error("[Proc] snapshot failed");
        return;
    }

    struct ProcInfo {
        DWORD pid = 0, parentPid = 0;
        std::wstring name, path;
    };
    std::unordered_map<DWORD, ProcInfo> procs;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    int counter = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (cancel.IsCancelled()) break;
            ProcInfo info;
            info.pid       = pe.th32ProcessID;
            info.parentPid = pe.th32ParentProcessID;
            info.name      = pe.szExeFile;
            info.path      = GetProcessPath(pe.th32ProcessID);
            procs[info.pid] = std::move(info);
            ++counter;
        } while (Process32NextW(snap, &pe) && !cancel.IsCancelled());
    }
    CloseHandle(snap);

    Logger::Instance().Info("[Proc] " + std::to_string(counter) + " processes found");

    int flagged = 0, skippedBySig = 0, skippedByName = 0;

    size_t procIdx = 0;
    const size_t procTotal = procs.size();
    for (const auto& [pid, p] : procs) {
        sink.Item(p.path.empty() ? p.name : p.path);
        if (procTotal) {
            sink.Progress("Processes",
                          static_cast<int>(100 * procIdx / procTotal));
        }
        ++procIdx;
        if (cancel.IsCancelled()) break;
        if (pid == 0 || pid == 4) continue;

        auto nameLow = ToLower(p.name);

        // Быстрый whitelist по имени — известные легитимные процессы
        if (IsWhitelistedProcName(nameLow)) {
            ++skippedByName;
            continue;
        }

        bool isFlagged = false;
        Severity sev = Severity::Medium;
        std::wstring why;

        if (auto reason = CheckSystemMasquerade(p.name, p.path); !reason.empty()) {
            isFlagged = true;
            sev = Severity::Critical;
            why = reason;
        }

        if (SignatureDB::Get().IsSuspiciousFileName(p.name)) {
            isFlagged = true;
            if (sev < Severity::High) sev = Severity::High;
            if (!why.empty()) why += L" ";
            why += L"Process name matches malware/miner heuristic.";
        }

        if (!p.path.empty() && SignatureDB::Get().IsSuspiciousPath(p.path)) {
            isFlagged = true;
            if (sev < Severity::Medium) sev = Severity::Medium;
            if (!why.empty()) why += L" ";
            why += L"Running from a dropper-typical location (Temp/AppData).";
        }

        // Бесфайловый: путь ЕСТЬ, но файла на диске нет.
        // Если путь пустой — НЕ флагаем (просто не смогли прочитать).
        if (!p.path.empty()) {
            std::error_code ec;
            if (!fs::exists(p.path, ec)) {
                isFlagged = true;
                sev = Severity::Critical;
                if (!why.empty()) why += L" ";
                why += L"Image file missing on disk (possible fileless malware).";
            }
        }

        auto parentIt = procs.find(p.parentPid);
        if (parentIt != procs.end()) {
            if (auto reason = CheckSuspiciousParent(p.name, parentIt->second.name);
                !reason.empty())
            {
                isFlagged = true;
                if (sev < Severity::High) sev = Severity::High;
                if (!why.empty()) why += L" ";
                why += reason;
            }
        }

        if (!isFlagged) continue;

        if (!p.path.empty() && IsTrustedSigned(p.path)) {
            ++skippedBySig;
            continue;
        }

        ++flagged;

        Threat t;
        t.kind        = ThreatKind::Process;
        t.category    = ThreatCategory::HiddenProcess;
        t.severity    = sev;
        t.name        = p.name + L" (PID " + std::to_wstring(p.pid) + L")";
        t.source      = p.path.empty() ? L"<protected / no path>" : p.path;
        t.description = why;
        t.pid         = p.pid;
        t.filePath    = p.path;
        t.suggestion  = L"Investigate. Consider terminating and quarantining.";

        sink.Report(t);
        Logger::Instance().Warn("[Proc] flagged PID " + std::to_string(p.pid) +
                                ": " + WideToUtf8(p.name));
    }

    Logger::Instance().Info(
        "[Proc] done. Total: " + std::to_string(counter) +
        ", flagged: " + std::to_string(flagged) +
        ", skipped by signature: " + std::to_string(skippedBySig) +
        ", skipped by name: " + std::to_string(skippedByName));
}
