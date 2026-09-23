#include "NetworkScanner.h"
#include "SignatureDB.h"
#include "Logger.h"
#include "SignatureVerifier.h"
#include "PublisherWhitelist.h"

#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Psapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
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
        [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

std::wstring GetProcessPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH * 4] = {};
    DWORD sz = sizeof(buf) / sizeof(wchar_t);
    std::wstring path;
    if (QueryFullProcessImageNameW(h, 0, buf, &sz)) path.assign(buf, sz);
    CloseHandle(h);
    return path;
}

std::string IpToString(DWORD addr) {
    struct in_addr a;
    a.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

// Подозрительные порты (часто используются малварью)
bool IsSuspiciousPort(int port) {
    static const std::vector<int> kPorts = {
        4444,  // Metasploit default
        4445,
        1337,  // "leet" — частый бэкдор
        6667,  // IRC — старые ботнеты
        6666,
        31337, // Back Orifice
        12345, // NetBus
        9001,  // Tor (иногда)
    };
    for (int p : kPorts) if (p == port) return true;
    return false;
}

bool IsTrustedSigned(const std::wstring& path) {
    if (path.empty()) return false;
    auto sig = SignatureVerifier::Verify(fs::path(path));
    if (!sig.valid || sig.publisher.empty()) return false;
    return PublisherWhitelist::Get().IsTrusted(sig.publisher);
}

} // namespace

void NetworkScanner::Scan(IReportSink& sink, CancelToken& cancel) {
    Logger::Instance().Info("[Net] enumerating TCP connections...");

    // Запрашиваем расширенную таблицу TCP с привязкой к PID
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) {
        Logger::Instance().Error("[Net] GetExtendedTcpTable size query failed");
        return;
    }

    std::vector<BYTE> buf(size);
    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());

    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        Logger::Instance().Error("[Net] GetExtendedTcpTable failed");
        return;
    }

    int total = (int)table->dwNumEntries;
    int flagged = 0, skippedBySig = 0;

    Logger::Instance().Info("[Net] " + std::to_string(total) + " TCP entries");

    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        if (table->dwNumEntries) {
            sink.Progress("Network connections",
                          static_cast<int>(100ull * i / table->dwNumEntries));
        }
        if (cancel.IsCancelled()) break;

        const auto& row = table->table[i];

        // Интересуют только установленные исходящие соединения
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

        DWORD pid = row.dwOwningPid;
        if (pid == 0 || pid == 4) continue;

        std::string remoteIp = IpToString(row.dwRemoteAddr);
        int remotePort = ntohs((u_short)row.dwRemotePort);

        // Пропускаем локальные адреса
        if (remoteIp.rfind("127.", 0) == 0 ||
            remoteIp.rfind("0.", 0) == 0 ||
            remoteIp == "0.0.0.0") continue;

        std::wstring procPath = GetProcessPath(pid);
        std::wstring procName = procPath.empty()
            ? L"<unknown>"
            : fs::path(procPath).filename().wstring();

        bool isFlagged = false;
        Severity sev = Severity::Medium;
        std::wstring why;

        // 1) Майнинг-пул по IP (наш список — доменные имена, но проверим IP тоже)
        if (SignatureDB::Get().IsKnownMiningPool(remoteIp)) {
            isFlagged = true;
            sev = Severity::Critical;
            why = L"Connection to a known cryptocurrency mining pool.";
        }

        // 2) Подозрительный порт
        if (IsSuspiciousPort(remotePort)) {
            isFlagged = true;
            if (sev < Severity::High) sev = Severity::High;
            if (!why.empty()) why += L" ";
            why += L"Connection on a port commonly used by backdoors/C2 (" +
                   std::to_wstring(remotePort) + L").";
        }

        // 3) Процесс из подозрительного места лезет в сеть
        if (!procPath.empty() &&
            SignatureDB::Get().IsSuspiciousPath(procPath)) {
            isFlagged = true;
            if (sev < Severity::High) sev = Severity::High;
            if (!why.empty()) why += L" ";
            why += L"Network activity from a process in a dropper-typical location.";
        }

        if (!isFlagged) continue;

        if (!procPath.empty() && IsTrustedSigned(procPath)) {
            ++skippedBySig;
            continue;
        }

        ++flagged;

        std::wstring remote = std::wstring(remoteIp.begin(), remoteIp.end()) +
                              L":" + std::to_wstring(remotePort);

        Threat t;
        t.kind        = ThreatKind::Process;
        t.category    = ThreatCategory::NetworkBeacon;
        t.severity    = sev;
        t.name        = procName + L" → " + remote;
        t.source      = procPath.empty() ? remote : procPath;
        t.description = why;
        t.pid         = pid;
        t.filePath    = procPath;
        t.suggestion  = L"Investigate the network connection and owning process.";

        sink.Report(t);
        Logger::Instance().Warn("[Net] flagged: " + WideToUtf8(procName) +
                                " -> " + remoteIp + ":" + std::to_string(remotePort));
    }

    Logger::Instance().Info(
        "[Net] done. Connections: " + std::to_string(total) +
        ", flagged: " + std::to_string(flagged) +
        ", skipped by signature: " + std::to_string(skippedBySig));
}
