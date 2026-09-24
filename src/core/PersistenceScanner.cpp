#include "PersistenceScanner.h"
#include "CommandTarget.h"
#include "Detections.h"
#include "Logger.h"

#include "../engine/FileAnalyzer.h"

#include <Windows.h>
#include <comdef.h>
#include <Wbemidl.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")

namespace fs = std::filesystem;
using Detections::Reason;
using Detections::Utf8;

namespace {

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::wstring ServiceDll(const std::wstring& service) {
    const std::wstring sub = L"SYSTEM\\CurrentControlSet\\Services\\" + service + L"\\Parameters";
    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, sub.c_str(), L"ServiceDll",
                     RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, buf, &size) != ERROR_SUCCESS)
        return {};
    return CommandTarget::NormalizeImagePath(buf);
}

bool IsLoopback(const std::string& ip) {
    return ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip == "::" || ip.rfind("127.", 0) == 0;
}

bool EndsWithDomain(const std::string& host, const char* domain) {
    const size_t n = std::strlen(domain);
    if (host.size() < n) return false;
    if (host.compare(host.size() - n, n, domain) != 0) return false;
    return host.size() == n || host[host.size() - n - 1] == '.';
}

// Домены защиты и обновлений: их блокировка отрезает машину от баз
// и заплаток. Телеметрию Microsoft здесь нет намеренно — её блокируют
// честные программы «приватности», и это не повод бить тревогу.
bool IsSecurityDomain(const std::string& host) {
    static const char* kDomains[] = {
        "kaspersky.com", "kaspersky.ru", "drweb.com", "drweb.ru", "eset.com", "avast.com",
        "avg.com", "avira.com", "malwarebytes.com", "bitdefender.com", "sophos.com",
        "mcafee.com", "norton.com", "symantec.com", "virustotal.com", "windowsupdate.com",
        "update.microsoft.com", "download.windowsupdate.com", "definitionupdates.microsoft.com",
        "wdcp.microsoft.com", "wd.microsoft.com", "go.microsoft.com", "esetnod32.ru",
    };
    for (const char* d : kDomains)
        if (EndsWithDomain(host, d)) return true;
    return false;
}

// Популярные сайты, подмена адреса которых — классический фишинг.
bool IsPopularSite(const std::string& host) {
    static const char* kSites[] = {
        "google.com", "youtube.com", "facebook.com", "vk.com", "ok.ru", "mail.ru", "yandex.ru",
        "sberbank.ru", "tinkoff.ru", "paypal.com", "steamcommunity.com", "steampowered.com",
        "discord.com", "telegram.org", "instagram.com", "twitter.com", "x.com", "github.com",
        "microsoft.com", "live.com", "apple.com", "gosuslugi.ru", "binance.com",
    };
    for (const char* d : kSites)
        if (EndsWithDomain(host, d)) return true;
    return false;
}

} // namespace

void PersistenceScanner::ScanServices(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD needed = 0, count = 0, resume = 0;
    const DWORD types = SERVICE_WIN32 | SERVICE_DRIVER;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, types, SERVICE_STATE_ALL, nullptr, 0,
                          &needed, &count, &resume, nullptr);
    std::vector<BYTE> buf(needed + 1024);
    resume = 0;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, types, SERVICE_STATE_ALL, buf.data(),
                               static_cast<DWORD>(buf.size()), &needed, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return;
    }
    auto* list = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    Logger::Instance().Info("[Services] " + std::to_string(count) + " services and drivers");

    FileAnalyzer::Options opt;
    opt.reportPua = config.reportPua;
    long long checked = 0;

    for (DWORD i = 0; i < count && !cancel.IsCancelled(); ++i) {
        sink.Progress("Services", static_cast<int>(90 * i / std::max<DWORD>(count, 1)));
        SC_HANDLE svc = OpenServiceW(scm, list[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!svc) continue;
        DWORD cfgNeeded = 0;
        QueryServiceConfigW(svc, nullptr, 0, &cfgNeeded);
        std::vector<BYTE> cfgBuf(cfgNeeded + 16);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
        const bool ok = QueryServiceConfigW(svc, cfg, static_cast<DWORD>(cfgBuf.size()), &cfgNeeded) &&
                        cfg->lpBinaryPathName;
        CloseServiceHandle(svc);
        if (!ok) continue;

        const std::wstring command = cfg->lpBinaryPathName;
        const std::wstring name = list[i].lpServiceName;
        sink.Item(name);
        sink.Checked(++checked);

        std::vector<std::wstring> targets;
        const CommandTarget::Parsed parsed = CommandTarget::Parse(command);
        if (!parsed.executable.empty()) targets.push_back(parsed.executable);
        const std::wstring dll = ServiceDll(name);
        if (!dll.empty()) targets.push_back(dll);

        Threat t;
        t.kind = ThreatKind::Service;
        t.name = list[i].lpDisplayName && *list[i].lpDisplayName ? list[i].lpDisplayName : name;
        t.source = L"Service :: " + name;
        t.serviceName = name;
        t.evidence = command;
        bool flagged = false;

        for (const std::wstring& target : targets) {
            if (config.IsExcludedPath(target)) continue;
            const Verdict v = FileAnalyzer::Analyze(target, opt);
            if (v.level == Verdict::Clean || config.IsAllowedHash(v.sha256)) continue;
            Detections::FillFromVerdict(t, v);
            t.summary = Detections::SummaryOf(v);
            t.filePath = target;
            flagged = true;
        }
        for (const std::string& r : CommandTarget::AbuseReasons(command)) {
            t.reasons.push_back(r);
            if (static_cast<int>(t.severity) < static_cast<int>(Severity::High)) t.severity = Severity::High;
            if (t.summary.empty()) t.summary = L"Service abuses a system program";
            flagged = true;
        }
        if (!flagged) continue;

        const bool driver = (list[i].ServiceStatusProcess.dwServiceType & SERVICE_DRIVER) != 0;
        t.reasons.insert(t.reasons.begin(), Reason({ driver ? "driver" : "service", Utf8(name) }));
        sink.Report(t);
        Logger::Instance().Warn("[Services] flagged: " + Utf8(name));
    }
    CloseServiceHandle(scm);
}

void PersistenceScanner::ScanWmi(IReportSink& sink, const ScanConfig& config) {
    const HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                                reinterpret_cast<void**>(&loc))) || !loc ||
        FAILED(loc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr, nullptr, 0,
                                  nullptr, nullptr, &svc)) || !svc)
    {
        if (loc) loc->Release();
        if (SUCCEEDED(co)) CoUninitialize();
        return;
    }
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    FileAnalyzer::Options opt;
    opt.reportPua = config.reportPua;

    // Потребители, которые выполняют код: команду или сценарий. На домашней
    // машине честного применения у них почти нет.
    for (const wchar_t* cls : { L"CommandLineEventConsumer", L"ActiveScriptEventConsumer" }) {
        IEnumWbemClassObject* en = nullptr;
        const std::wstring query = std::wstring(L"SELECT * FROM ") + cls;
        if (FAILED(svc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                                  WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en)) || !en)
            continue;

        IWbemClassObject* obj = nullptr;
        ULONG got = 0;
        while (en->Next(WBEM_INFINITE, 1, &obj, &got) == S_OK && got) {
            auto get = [&](const wchar_t* prop) {
                VARIANT v{};
                std::wstring s;
                if (SUCCEEDED(obj->Get(prop, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
                    s = v.bstrVal;
                VariantClear(&v);
                return s;
            };
            const std::wstring name = get(L"Name");
            const std::wstring relpath = get(L"__RELPATH");
            std::wstring payload = get(L"CommandLineTemplate");
            if (payload.empty()) payload = get(L"ExecutablePath");
            if (payload.empty()) payload = get(L"ScriptFileName");
            if (payload.empty()) payload = get(L"ScriptText").substr(0, 400);
            obj->Release();
            obj = nullptr;

            // Пример из старых версий Windows, безвреден.
            if (name == L"BVTConsumer") continue;

            Threat t;
            t.kind = ThreatKind::WmiConsumer;
            t.severity = Severity::High;
            t.name = name.empty() ? std::wstring(cls) : name;
            t.source = std::wstring(L"WMI ") + cls + L" :: " + t.name;
            t.wmiConsumerPath = relpath;
            t.evidence = payload;
            t.summary = L"Permanent WMI event subscription runs code";
            t.reasons.push_back(Reason({ "wmi", Utf8(cls) }));

            const CommandTarget::Parsed parsed = CommandTarget::Parse(payload);
            if (!parsed.executable.empty()) {
                const Verdict v = FileAnalyzer::Analyze(parsed.executable, opt);
                if (v.level != Verdict::Clean) {
                    Detections::FillFromVerdict(t, v);
                    t.filePath = parsed.executable;
                }
            }
            for (const std::string& r : CommandTarget::AbuseReasons(payload)) {
                t.reasons.push_back(r);
                t.severity = Severity::Critical;
            }
            sink.Report(t);
            Logger::Instance().Warn("[Services] WMI consumer: " + Utf8(t.name));
        }
        en->Release();
    }
    svc->Release();
    loc->Release();
    if (SUCCEEDED(co)) CoUninitialize();
}

void PersistenceScanner::ScanHosts(IReportSink& sink) {
    wchar_t sysDir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) return;
    const fs::path hosts = fs::path(sysDir) / L"drivers" / L"etc" / L"hosts";
    std::ifstream in(hosts);
    if (!in) return;

    std::string line;
    while (std::getline(in, line)) {
        const size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos || line[first] == '#') continue;
        std::istringstream ss(line.substr(first));
        std::string ip, host;
        ss >> ip;
        while (ss >> host) {
            if (host.empty() || host[0] == '#') break;
            std::transform(host.begin(), host.end(), host.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            const bool security = IsSecurityDomain(host);
            // Подмена адреса популярного сайта на чужой сервер — фишинг.
            // Блокировку (0.0.0.0, 127.0.0.1) популярных сайтов не трогаем:
            // родительский контроль и блокировщики делают ровно это.
            const bool hijack = !IsLoopback(ip) && IsPopularSite(host);
            if (!security && !hijack) continue;

            Threat t;
            t.kind = ThreatKind::HostsEntry;
            t.severity = hijack ? Severity::Critical : Severity::High;
            t.name = Detections::Wide(host);
            t.source = hosts.wstring();
            t.hostsLine = Detections::Wide(line);
            t.evidence = Detections::Wide(line);
            t.summary = hijack ? L"hosts redirects a popular site to another server"
                               : L"hosts blocks a security or update site";
            t.reasons.push_back(Reason({ hijack ? "hosts.hijack" : "hosts.security", host, ip }));
            sink.Report(t);
            Logger::Instance().Warn("[Services] hosts entry: " + host + " -> " + ip);
        }
    }
}

void PersistenceScanner::Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) {
    sink.Progress("Services", 0);
    ScanHosts(sink);
    if (cancel.IsCancelled()) return;
    ScanServices(sink, cancel, config);
    if (cancel.IsCancelled()) return;
    sink.Progress("Services", 95);
    ScanWmi(sink, config);
    Logger::Instance().Info("[Services] done");
}
