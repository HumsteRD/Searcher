#include "ProcessScanner.h"
#include "CommandTarget.h"
#include "Detections.h"
#include "Logger.h"

#include "../engine/FileAnalyzer.h"
#include "../engine/TrustVerifier.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cwctype>
#include <unordered_map>
#include <vector>

using Detections::Reason;
using Detections::Utf8;

namespace {

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

struct Proc {
    DWORD        pid = 0;
    DWORD        parent = 0;
    std::wstring name;
    std::wstring path;
    std::wstring commandLine;
};

std::wstring ImagePath(HANDLE h) {
    wchar_t buf[MAX_PATH * 4] = {};
    DWORD size = static_cast<DWORD>(std::size(buf));
    return QueryFullProcessImageNameW(h, 0, buf, &size) ? std::wstring(buf, size) : std::wstring();
}

// Командная строка без чтения чужой памяти: класс 60 появился в Windows 8.1.
std::wstring CommandLineOf(HANDLE h) {
    using QueryFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static const QueryFn query = reinterpret_cast<QueryFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!query) return {};
    ULONG needed = 0;
    query(h, 60, nullptr, 0, &needed);
    if (needed == 0 || needed > 64 * 1024) return {};
    std::vector<BYTE> buf(needed);
    if (query(h, 60, buf.data(), needed, &needed) < 0) return {};
    const auto* us = reinterpret_cast<const UNICODE_STRING*>(buf.data());
    if (!us->Buffer || us->Length == 0) return {};
    return std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
}

// Имена системных процессов и каталог, откуда они обязаны запускаться.
const wchar_t* ExpectedDir(const std::wstring& nameLower) {
    static const std::pair<const wchar_t*, const wchar_t*> kSystem[] = {
        { L"svchost.exe", L"\\windows\\system32\\" }, { L"csrss.exe", L"\\windows\\system32\\" },
        { L"lsass.exe", L"\\windows\\system32\\" },   { L"services.exe", L"\\windows\\system32\\" },
        { L"winlogon.exe", L"\\windows\\system32\\" },{ L"smss.exe", L"\\windows\\system32\\" },
        { L"wininit.exe", L"\\windows\\system32\\" }, { L"spoolsv.exe", L"\\windows\\system32\\" },
        { L"taskhostw.exe", L"\\windows\\system32\\" },{ L"sihost.exe", L"\\windows\\system32\\" },
        { L"dwm.exe", L"\\windows\\system32\\" },     { L"conhost.exe", L"\\windows\\system32\\" },
        { L"ctfmon.exe", L"\\windows\\system32\\" },  { L"dllhost.exe", L"\\windows\\sys" },
        { L"rundll32.exe", L"\\windows\\sys" },       { L"explorer.exe", L"\\windows\\" },
        { L"runtimebroker.exe", L"\\windows\\system32\\" },
    };
    for (const auto& [n, dir] : kSystem)
        if (nameLower == n) return dir;
    return nullptr;
}

} // namespace

void ProcessScanner::Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) {
    std::vector<Proc> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Logger::Instance().Error("[Processes] snapshot failed");
        return;
    }
    PROCESSENTRY32W pe{ sizeof(pe) };
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (pe.th32ProcessID <= 4) continue;
        Proc p;
        p.pid = pe.th32ProcessID;
        p.parent = pe.th32ParentProcessID;
        p.name = pe.szExeFile;
        if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid)) {
            p.path = ImagePath(h);
            p.commandLine = CommandLineOf(h);
            CloseHandle(h);
        }
        procs.push_back(std::move(p));
    }
    CloseHandle(snap);
    Logger::Instance().Info("[Processes] " + std::to_string(procs.size()) + " processes");

    FileAnalyzer::Options opt;
    opt.reportPua = config.reportPua;

    // Один образ — одна проверка: у браузера бывает три десятка процессов.
    std::unordered_map<std::wstring, Verdict> verdicts;
    long long checked = 0;

    for (size_t i = 0; i < procs.size() && !cancel.IsCancelled(); ++i) {
        const Proc& p = procs[i];
        sink.Progress("Processes", static_cast<int>(100 * i / std::max<size_t>(procs.size(), 1)));
        sink.Item(p.path.empty() ? p.name : p.path);
        sink.Checked(++checked);

        Threat t;
        t.kind = ThreatKind::Process;
        t.name = p.name;
        t.source = p.path.empty() ? p.name : p.path;
        t.filePath = p.path;
        t.pid = p.pid;
        t.evidence = p.commandLine;
        bool flagged = false;

        if (!p.path.empty() && !config.IsExcludedPath(p.path)) {
            const std::wstring key = Lower(p.path);
            auto it = verdicts.find(key);
            if (it == verdicts.end()) it = verdicts.emplace(key, FileAnalyzer::Analyze(p.path, opt)).first;
            const Verdict& v = it->second;
            if (v.level != Verdict::Clean && !config.IsAllowedHash(v.sha256)) {
                Detections::FillFromVerdict(t, v);
                t.summary = Detections::SummaryOf(v);
                flagged = true;
            }
        }

        // Маскировка: системное имя, но не системный каталог. Подпись
        // Microsoft снимает подозрение — у части компонентов есть копии
        // в других местах (например, в WinSxS).
        const std::wstring nameLower = Lower(p.name);
        if (const wchar_t* dir = ExpectedDir(nameLower); dir && !p.path.empty()) {
            const std::wstring pathLower = Lower(p.path);
            if (pathLower.find(dir) == std::wstring::npos) {
                const TrustVerifier::Result trust = TrustVerifier::Check(p.path);
                const bool microsoft = trust.signedValid &&
                    Lower(trust.publisher).find(L"microsoft") == 0;
                if (!microsoft) {
                    t.reasons.push_back(Reason({ "masquerade", Utf8(p.name) }));
                    t.severity = Severity::Critical;
                    if (t.summary.empty()) t.summary = L"Impersonates a Windows system process";
                    flagged = true;
                }
            }
        }

        // Закодированная команда сама по себе у работающего процесса — не
        // улика: так запускают PowerShell и честные установщики, и средства
        // управления. Считается только вместе с другим приёмом.
        std::vector<std::string> abuse = CommandTarget::AbuseReasons(p.commandLine);
        if (abuse.size() == 1 && abuse.front() == "cmd.encoded") abuse.clear();
        for (const std::string& r : abuse) {
            t.reasons.push_back(r);
            if (static_cast<int>(t.severity) < static_cast<int>(Severity::High)) t.severity = Severity::High;
            if (t.summary.empty()) t.summary = L"Process abuses a system program";
            flagged = true;
        }

        if (!flagged) continue;
        t.reasons.insert(t.reasons.begin(), Reason({ "process", std::to_string(p.pid) }));
        sink.Report(t);
        Logger::Instance().Warn("[Processes] flagged: " + Utf8(t.source) + " (pid " +
                                std::to_string(p.pid) + ")");
    }
    Logger::Instance().Info("[Processes] done");
}
