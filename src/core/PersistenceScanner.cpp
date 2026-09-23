#include "PersistenceScanner.h"
#include "Logger.h"
#include "Lang.h"
#include "SignatureVerifier.h"
#include "PublisherWhitelist.h"

#include <Windows.h>
#include <comdef.h>
#include <Wbemidl.h>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")

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

// Домены, перенаправление которых почти всегда означает попытку
// отрезать машину от антивирусов и обновлений.
bool IsSecurityDomain(const std::wstring& hostLower) {
    static const wchar_t* kMarkers[] = {
        L"microsoft.com", L"windowsupdate", L"defender", L"virustotal",
        L"kaspersky", L"drweb", L"avast", L"avira", L"eset", L"nod32",
        L"malwarebytes", L"bitdefender", L"sophos", L"mcafee", L"norton",
        L"symantec", L"antivirus", L"virus",
    };
    for (const wchar_t* m : kMarkers) {
        if (hostLower.find(m) != std::wstring::npos) return true;
    }
    return false;
}

// Служба, живущая во временной или пользовательской папке, — подозрительно.
//
// ProgramData из списка убран намеренно: там законно живут Microsoft Defender,
// драйверы NVIDIA и половина установленного софта. Одного расположения мало.
bool IsSuspiciousServicePath(const std::wstring& pathLower) {
    static const wchar_t* kBad[] = {
        L"\\appdata\\local\\temp\\", L"\\windows\\temp\\",
        L"\\users\\public\\", L"\\downloads\\", L"\\recycle",
    };
    for (const wchar_t* b : kBad) {
        if (pathLower.find(b) != std::wstring::npos) return true;
    }
    return false;
}

// Путь к образу службы бывает с кавычками и аргументами:
//   "C:\Program Files\X\svc.exe" -k netsvcs
// Для проверки подписи нужен именно файл.
std::wstring ExtractImagePath(const std::wstring& cmdline) {
    std::wstring s = cmdline;
    if (!s.empty() && s.front() == L'"') {
        const size_t close = s.find(L'"', 1);
        if (close != std::wstring::npos) return s.substr(1, close - 1);
    }
    const size_t exe = ToLower(s).find(L".exe");
    if (exe != std::wstring::npos) return s.substr(0, exe + 4);
    return s;
}

// Файл, подписанный доверенным издателем, угрозой не считаем.
// Это отсекает Microsoft, NVIDIA и сторонние антивирусы: их присутствие
// в системе нормально, а пометка их «угрозой» подрывает доверие
// ко всему инструменту — пользователь может удалить рабочую защиту.
bool IsTrustedBinary(const std::wstring& imagePath) {
    if (imagePath.empty()) return false;

    std::error_code ec;
    if (!fs::exists(imagePath, ec)) return false;

    const auto sig = SignatureVerifier::Verify(imagePath);
    if (!sig.valid || sig.publisher.empty()) return false;

    return PublisherWhitelist::Get().IsTrusted(sig.publisher);
}

} // namespace

// ─────────────────────────── hosts ───────────────────────────

void PersistenceScanner::ScanHosts(IReportSink& sink) {
    wchar_t sysDir[MAX_PATH]{};
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) return;

    const fs::path hosts =
        fs::path(sysDir) / L"drivers" / L"etc" / L"hosts";

    std::ifstream in(hosts);
    if (!in) return;

    std::string line;
    int lineNo = 0;

    while (std::getline(in, line)) {
        ++lineNo;

        // Комментарии и пустые строки не интересуют.
        const size_t firstChar = line.find_first_not_of(" \t");
        if (firstChar == std::string::npos || line[firstChar] == '#') continue;

        std::istringstream ss(line.substr(firstChar));
        std::string ip, host;
        ss >> ip >> host;
        if (host.empty()) continue;

        const std::wstring hostW = ToLower(
            std::wstring(host.begin(), host.end()));
        if (!IsSecurityDomain(hostW)) continue;

        Threat t;
        t.kind        = ThreatKind::File;
        t.category    = ThreatCategory::Other;
        t.severity    = Severity::Critical;
        t.name        = std::wstring(host.begin(), host.end());
        t.source      = hosts.wstring() + L" : " + std::to_wstring(lineNo);
        t.description = TR("The hosts file redirects a security or update "
                           "domain — this is how malware cuts the machine off "
                           "from antivirus updates.").toStdWString();
        t.suggestion  = TR("Open the hosts file and remove this line if you "
                           "did not add it yourself.").toStdWString();
        t.filePath    = hosts.wstring();

        sink.Report(t);
        Logger::Instance().Warn("[Persist] hosts entry: " + host);
    }
}

// ────────────────────────── службы ───────────────────────────

void PersistenceScanner::ScanServices(IReportSink& sink, CancelToken& cancel) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0,
                          &needed, &count, &resume, nullptr);

    std::vector<BYTE> buf(needed ? needed : 1);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(),
                               &needed, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return;
    }

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());

    for (DWORD i = 0; i < count; ++i) {
        if (cancel.IsCancelled()) break;

        SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName,
                                     SERVICE_QUERY_CONFIG);
        if (!svc) continue;

        DWORD cfgNeeded = 0;
        QueryServiceConfigW(svc, nullptr, 0, &cfgNeeded);

        std::vector<BYTE> cfgBuf(cfgNeeded ? cfgNeeded : 1);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());

        if (QueryServiceConfigW(svc, cfg, (DWORD)cfgBuf.size(), &cfgNeeded) &&
            cfg->lpBinaryPathName)
        {
            const std::wstring bin   = cfg->lpBinaryPathName;
            const std::wstring image = ExtractImagePath(bin);

            // Порядок важен: сначала дешёвая проверка пути, и только для
            // подозрительных путей — дорогая проверка подписи.
            if (IsSuspiciousServicePath(ToLower(bin)) && !IsTrustedBinary(image)) {
                Threat t;
                t.kind        = ThreatKind::File;
                t.category    = ThreatCategory::AutoStart;
                t.severity    = Severity::High;
                t.name        = services[i].lpDisplayName
                                ? services[i].lpDisplayName
                                : services[i].lpServiceName;
                t.source      = bin;
                t.description = TR("A Windows service runs from a user or "
                                   "temporary folder. Software installed "
                                   "normally does not live there.").toStdWString();
                t.suggestion  = TR("Check what installed this service before "
                                   "removing it.").toStdWString();
                t.filePath    = bin;

                sink.Report(t);
                Logger::Instance().Warn(
                    "[Persist] service: " + WideToUtf8(bin));
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

// ─────────────────────── подписки WMI ────────────────────────

void PersistenceScanner::ScanWmiSubscriptions(IReportSink& sink) {
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool needUninit = SUCCEEDED(hrInit);

    IWbemLocator* loc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, (void**)&loc)) || !loc) {
        if (needUninit) CoUninitialize();
        return;
    }

    IWbemServices* svc = nullptr;
    // Потребители событий живут в пространстве subscription, а не cimv2.
    if (FAILED(loc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr,
                                  nullptr, nullptr, 0, nullptr, nullptr, &svc))
        || !svc) {
        loc->Release();
        if (needUninit) CoUninitialize();
        return;
    }

    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      nullptr, EOAC_NONE);

    // CommandLineEventConsumer запускает произвольную команду по событию.
    // Легитимного применения у него на домашней машине практически нет.
    IEnumWbemClassObject* en = nullptr;
    if (SUCCEEDED(svc->ExecQuery(
            _bstr_t(L"WQL"),
            _bstr_t(L"SELECT * FROM CommandLineEventConsumer"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr, &en)) && en)
    {
        IWbemClassObject* obj = nullptr;
        ULONG got = 0;

        while (en->Next(WBEM_INFINITE, 1, &obj, &got) == S_OK && got) {
            VARIANT vName{}, vCmd{};
            obj->Get(L"Name", 0, &vName, nullptr, nullptr);
            obj->Get(L"CommandLineTemplate", 0, &vCmd, nullptr, nullptr);

            const std::wstring name =
                (vName.vt == VT_BSTR && vName.bstrVal) ? vName.bstrVal : L"(unnamed)";
            const std::wstring cmd =
                (vCmd.vt == VT_BSTR && vCmd.bstrVal) ? vCmd.bstrVal : L"";

            Threat t;
            t.kind        = ThreatKind::File;
            t.category    = ThreatCategory::AutoStart;
            t.severity    = Severity::Critical;
            t.name        = name;
            t.source      = L"WMI CommandLineEventConsumer :: " + cmd;
            t.description = TR("A WMI subscription runs a command when a system "
                               "event happens. It survives reboots and is not "
                               "visible in startup lists or Task Scheduler.")
                                .toStdWString();
            t.evidence    = cmd;
            t.suggestion  = TR("Unless you set this up yourself, treat it as "
                               "malicious persistence.").toStdWString();

            sink.Report(t);
            Logger::Instance().Warn("[Persist] WMI consumer: " + WideToUtf8(name));

            VariantClear(&vName);
            VariantClear(&vCmd);
            obj->Release();
            obj = nullptr;
        }
        en->Release();
    }

    svc->Release();
    loc->Release();
    if (needUninit) CoUninitialize();
}

// ──────────────────────────────────────────────────────────────

void PersistenceScanner::Scan(IReportSink& sink, CancelToken& cancel) {
    Logger::Instance().Info("[Persist] checking system persistence...");

    sink.Progress("System persistence", 0);
    ScanHosts(sink);
    if (cancel.IsCancelled()) return;

    sink.Progress("System persistence", 33);
    ScanServices(sink, cancel);
    if (cancel.IsCancelled()) return;

    sink.Progress("System persistence", 66);
    ScanWmiSubscriptions(sink);

    Logger::Instance().Info("[Persist] done.");
}
