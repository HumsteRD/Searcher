#include "NetworkActivityWatcher.h"
#include "Logger.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>

namespace {

std::wstring Ipv4ToString(DWORD addr) {
    in_addr a{};
    a.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    wchar_t wide[INET_ADDRSTRLEN] = {};
    MultiByteToWideChar(CP_ACP, 0, buf, -1, wide, INET_ADDRSTRLEN);
    return wide;
}

std::wstring Ipv6ToString(const UCHAR addr[16]) {
    in6_addr a{};
    memcpy(&a, addr, 16);
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    wchar_t wide[INET6_ADDRSTRLEN] = {};
    MultiByteToWideChar(CP_ACP, 0, buf, -1, wide, INET6_ADDRSTRLEN);
    return std::wstring(L"[") + wide + L"]";
}

// Порт в таблице лежит в сетевом порядке байт, причём в младшем слове.
USHORT PortOf(DWORD raw) {
    return ntohs(static_cast<USHORT>(raw & 0xFFFF));
}

const wchar_t* TcpStateName(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED:     return L"closed";
    case MIB_TCP_STATE_LISTEN:     return L"listening";
    case MIB_TCP_STATE_SYN_SENT:   return L"connecting";
    case MIB_TCP_STATE_SYN_RCVD:   return L"connecting";
    case MIB_TCP_STATE_ESTAB:      return L"established";
    case MIB_TCP_STATE_FIN_WAIT1:
    case MIB_TCP_STATE_FIN_WAIT2:
    case MIB_TCP_STATE_CLOSE_WAIT:
    case MIB_TCP_STATE_CLOSING:
    case MIB_TCP_STATE_LAST_ACK:
    case MIB_TCP_STATE_TIME_WAIT:  return L"closing";
    default:                       return L"unknown";
    }
}

std::vector<BYTE> QueryTable(ULONG family, ULONG tableClass, bool tcp) {
    ULONG size = 0;
    DWORD rc = tcp
        ? GetExtendedTcpTable(nullptr, &size, FALSE, family,
                              static_cast<TCP_TABLE_CLASS>(tableClass), 0)
        : GetExtendedUdpTable(nullptr, &size, FALSE, family,
                              static_cast<UDP_TABLE_CLASS>(tableClass), 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) return {};

    std::vector<BYTE> buf(size);
    rc = tcp
        ? GetExtendedTcpTable(buf.data(), &size, FALSE, family,
                              static_cast<TCP_TABLE_CLASS>(tableClass), 0)
        : GetExtendedUdpTable(buf.data(), &size, FALSE, family,
                              static_cast<UDP_TABLE_CLASS>(tableClass), 0);
    if (rc != NO_ERROR) return {};
    return buf;
}

} // namespace

NetworkActivityWatcher::~NetworkActivityWatcher() {
    Stop();
}

bool NetworkActivityWatcher::Start(PidFilter filter, BehaviorSink sink,
                                   int pollMs)
{
    if (stopEvent_) return false;
    filter_ = std::move(filter);
    sink_   = std::move(sink);

    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) return false;

    // Снимок до запуска образца: наблюдаемых процессов ещё нет, фильтр
    // никого не пропускает, поэтому событий не будет — зато таблица
    // прогрета и первый настоящий опрос не выдаст чужие соединения.
    PollOnce();

    thread_ = std::thread([this, pollMs] { Pump(pollMs); });
    return true;
}

void NetworkActivityWatcher::Stop() {
    if (!stopEvent_) return;
    stopping_ = true;
    SetEvent(stopEvent_);
    if (thread_.joinable()) thread_.join();
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
    stopping_ = false;
    seen_.clear();
}

void NetworkActivityWatcher::Pump(int pollMs) {
    for (;;) {
        if (WaitForSingleObject(stopEvent_, static_cast<DWORD>(pollMs))
                == WAIT_OBJECT_0)
            break;
        PollOnce();
    }
    // Последний опрос: соединение могло появиться между предпоследним
    // опросом и остановкой.
    PollOnce();
}

void NetworkActivityWatcher::EmitOnce(BehaviorEventType type, DWORD pid,
                                      const std::wstring& target,
                                      const std::wstring& detail)
{
    std::wstring key = std::to_wstring(static_cast<int>(type)) + L"/" +
                       std::to_wstring(pid) + L"/" + target;
    if (!seen_.insert(key).second) return;   // уже сообщали
    if (!sink_) return;

    BehaviorEvent e;
    e.type   = type;
    e.pid    = pid;
    e.target = target;
    e.detail = detail;
    sink_(std::move(e));
}

void NetworkActivityWatcher::PollOnce() {
    auto watched = [this](DWORD pid) {
        return pid != 0 && (!filter_ || filter_(pid));
    };

    // TCP v4
    if (auto buf = QueryTable(AF_INET, TCP_TABLE_OWNER_PID_ALL, true);
        !buf.empty())
    {
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (!watched(row.dwOwningPid)) continue;

            if (row.dwState == MIB_TCP_STATE_LISTEN) {
                EmitOnce(BehaviorEventType::NetworkListen, row.dwOwningPid,
                         Ipv4ToString(row.dwLocalAddr) + L":" +
                             std::to_wstring(PortOf(row.dwLocalPort)),
                         L"TCP");
            } else if (row.dwRemoteAddr != 0) {
                EmitOnce(BehaviorEventType::NetworkConnection, row.dwOwningPid,
                         Ipv4ToString(row.dwRemoteAddr) + L":" +
                             std::to_wstring(PortOf(row.dwRemotePort)),
                         std::wstring(L"TCP, ") + TcpStateName(row.dwState));
            }
        }
    }

    // TCP v6
    if (auto buf = QueryTable(AF_INET6, TCP_TABLE_OWNER_PID_ALL, true);
        !buf.empty())
    {
        auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (!watched(row.dwOwningPid)) continue;

            if (row.dwState == MIB_TCP_STATE_LISTEN) {
                EmitOnce(BehaviorEventType::NetworkListen, row.dwOwningPid,
                         Ipv6ToString(row.ucLocalAddr) + L":" +
                             std::to_wstring(PortOf(row.dwLocalPort)),
                         L"TCP/IPv6");
            } else {
                EmitOnce(BehaviorEventType::NetworkConnection, row.dwOwningPid,
                         Ipv6ToString(row.ucRemoteAddr) + L":" +
                             std::to_wstring(PortOf(row.dwRemotePort)),
                         std::wstring(L"TCP/IPv6, ") + TcpStateName(row.dwState));
            }
        }
    }

    // UDP v4: состояния у датаграмм нет, видно только открытую точку.
    if (auto buf = QueryTable(AF_INET, UDP_TABLE_OWNER_PID, false);
        !buf.empty())
    {
        auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (!watched(row.dwOwningPid)) continue;
            EmitOnce(BehaviorEventType::NetworkListen, row.dwOwningPid,
                     Ipv4ToString(row.dwLocalAddr) + L":" +
                         std::to_wstring(PortOf(row.dwLocalPort)),
                     L"UDP");
        }
    }
}
