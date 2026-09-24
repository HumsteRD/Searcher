#include "NetworkScanner.h"
#include "Detections.h"
#include "Logger.h"

#include "../engine/FileWalker.h"
#include "../engine/TrustVerifier.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>

#include <memory>
#include <mutex>
#include <thread>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

using Detections::Reason;
using Detections::Utf8;

namespace {

const char* kPools[] = {
    "pool.minexmr.com", "xmr.2miners.com", "xmrpool.eu", "pool.supportxmr.com",
    "gulf.moneroocean.stream", "rx.unmineable.com", "xmr-eu1.nanopool.org",
    "xmr-eu2.nanopool.org", "xmr-us-east1.nanopool.org", "pool.hashvault.pro",
    "xmr.pool.minergate.com", "monerohash.com", "eth.2miners.com", "etc.2miners.com",
    "rvn.2miners.com", "stratum.f2pool.com", "xmr.f2pool.com", "mine.c3pool.com",
    "auto.c3pool.org", "pool.xmr.pt",
};

std::string Ip4(DWORD addr) {
    in_addr a{};
    a.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

std::string Ip6(const UCHAR* addr) {
    in6_addr a{};
    memcpy(&a, addr, 16);
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    return buf;
}

// Адреса пулов на момент проверки. Разрешение имён идёт в отдельных
// потоках с ограничением по времени: недоступный DNS не должен вешать
// проверку. Опоздавшие потоки дорабатывают сами и пишут в общий объект,
// который живёт, пока жив последний из них.
std::set<std::string> ResolvePools() {
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    struct Shared {
        std::mutex            lock;
        std::set<std::string> ips;
        int                   pending = 0;
    };
    auto shared = std::make_shared<Shared>();
    shared->pending = static_cast<int>(std::size(kPools));

    for (const char* host : kPools) {
        std::thread([shared, host] {
            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            addrinfo* res = nullptr;
            std::vector<std::string> found;
            if (getaddrinfo(host, nullptr, &hints, &res) == 0) {
                for (addrinfo* p = res; p; p = p->ai_next) {
                    char buf[INET6_ADDRSTRLEN] = {};
                    if (p->ai_family == AF_INET)
                        inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr, buf, sizeof(buf));
                    else if (p->ai_family == AF_INET6)
                        inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr, buf, sizeof(buf));
                    if (buf[0]) found.push_back(buf);
                }
                freeaddrinfo(res);
            }
            std::lock_guard<std::mutex> lock(shared->lock);
            shared->ips.insert(found.begin(), found.end());
            --shared->pending;
        }).detach();
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(shared->lock);
            if (shared->pending == 0) break;
        }
        Sleep(50);
    }
    std::lock_guard<std::mutex> lock(shared->lock);
    return shared->ips;
}

struct Conn {
    DWORD pid = 0;
    std::string remote;
    int port = 0;
};

std::vector<Conn> Connections() {
    std::vector<Conn> out;
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    std::vector<BYTE> buf(size + 1024);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
        auto* t = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            if (r.dwState != MIB_TCP_STATE_ESTAB) continue;
            out.push_back({ r.dwOwningPid, Ip4(r.dwRemoteAddr), ntohs(static_cast<u_short>(r.dwRemotePort)) });
        }
    }
    size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    buf.assign(size + 1024, 0);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
        auto* t = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buf.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            if (r.dwState != MIB_TCP_STATE_ESTAB) continue;
            out.push_back({ r.dwOwningPid, Ip6(r.ucRemoteAddr), ntohs(static_cast<u_short>(r.dwRemotePort)) });
        }
    }
    return out;
}

std::wstring ProcessPath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH * 4] = {};
    DWORD size = static_cast<DWORD>(std::size(buf));
    std::wstring p = QueryFullProcessImageNameW(h, 0, buf, &size) ? std::wstring(buf, size) : L"";
    CloseHandle(h);
    return p;
}

bool IsC2Port(int port) {
    // Порты по умолчанию у распространённых средств удалённого управления.
    return port == 4444 || port == 1337 || port == 31337 || port == 6667 || port == 12345 ||
           port == 5552 || port == 1604 || port == 7707;
}

bool IsStratumPort(int port) {
    return port == 3333 || port == 14444 || port == 45700 || port == 10128 || port == 10343;
}

} // namespace

void NetworkScanner::Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) {
    sink.Progress("Network", 0);
    const std::set<std::string> pools = ResolvePools();
    const std::vector<Conn> conns = Connections();
    Logger::Instance().Info("[Network] " + std::to_string(conns.size()) + " connections, " +
                            std::to_string(pools.size()) + " pool addresses resolved");

    std::set<DWORD> reported;
    long long checked = 0;
    for (size_t i = 0; i < conns.size() && !cancel.IsCancelled(); ++i) {
        const Conn& c = conns[i];
        sink.Progress("Network", static_cast<int>(20 + 80 * i / std::max<size_t>(conns.size(), 1)));
        sink.Checked(++checked);
        if (c.pid <= 4 || reported.count(c.pid)) continue;

        const std::wstring path = ProcessPath(c.pid);
        if (!path.empty() && config.IsExcludedPath(path)) continue;
        const std::string endpoint = c.remote + ":" + std::to_string(c.port);

        std::string reason;
        Severity sev = Severity::Medium;
        if (pools.count(c.remote)) {
            reason = Reason({ "net.pool", endpoint });
            sev = Severity::Critical;
        } else if ((IsC2Port(c.port) || IsStratumPort(c.port)) && !path.empty() &&
                   FileWalker::IsRiskyLocation(path)) {
            const TrustVerifier::Result trust = TrustVerifier::Check(path);
            if (trust.signedValid) continue;
            reason = Reason({ IsStratumPort(c.port) ? "net.stratum-port" : "net.c2-port", endpoint });
            sev = Severity::Medium;
        } else {
            continue;
        }

        Threat t;
        t.kind = ThreatKind::Process;
        t.severity = sev;
        t.name = path.empty() ? L"PID " + std::to_wstring(c.pid) : path.substr(path.find_last_of(L'\\') + 1);
        t.source = path.empty() ? Detections::Wide(endpoint) : path;
        t.filePath = path;
        t.pid = c.pid;
        t.evidence = Detections::Wide(endpoint);
        t.summary = sev == Severity::Critical ? L"Connected to a cryptocurrency mining pool"
                                              : L"Unsigned program talks on a remote-control port";
        t.malwareClass = sev == Severity::Critical ? 6 /* Miner */ : 0;
        t.reasons.push_back(Reason({ "process", std::to_string(c.pid) }));
        t.reasons.push_back(reason);
        reported.insert(c.pid);
        sink.Report(t);
        Logger::Instance().Warn("[Network] flagged: " + Utf8(t.name) + " -> " + endpoint);
    }
    Logger::Instance().Info("[Network] done");
}
