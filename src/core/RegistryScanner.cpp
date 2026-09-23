#include "RegistryScanner.h"
#include "Logger.h"

#include <Windows.h>
#include <vector>
#include <string>
#include <array>
#include <cwctype>

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
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

struct RegLoc {
    HKEY        root;
    const wchar_t* sub;
    const wchar_t* label;
};

const std::array<RegLoc, 8> kAutorunKeys = {{
    { HKEY_LOCAL_MACHINE,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"HKLM\\...\\Run" },

    { HKEY_LOCAL_MACHINE,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      L"HKLM\\...\\RunOnce" },

    { HKEY_LOCAL_MACHINE,
      L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"HKLM(Wow64)\\...\\Run" },

    { HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      L"HKCU\\...\\Run" },

    { HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      L"HKCU\\...\\RunOnce" },

    { HKEY_LOCAL_MACHINE,
      L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      L"HKLM\\...\\Winlogon" },

    { HKEY_LOCAL_MACHINE,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
      L"HKLM Policies Run" },

    { HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
      L"HKCU Policies Run" },
}};

std::wstring EvaluateValue(const std::wstring& valueData) {
    std::wstring lower = ToLower(valueData);

    if (lower.find(L"\\appdata\\roaming\\") != std::wstring::npos &&
        (lower.find(L".exe") != std::wstring::npos ||
         lower.find(L".bat") != std::wstring::npos ||
         lower.find(L".vbs") != std::wstring::npos)) {
        return L"Autorun-zapis zapuskaet fail iz AppData\\Roaming - tipichnoe mesto dropperov.";
    }
    if (lower.find(L"\\temp\\") != std::wstring::npos) {
        return L"Autorun-zapis zapuskaet fail iz Temp - krayne podozritelno.";
    }
    if (lower.find(L"\\programdata\\") != std::wstring::npos &&
        lower.find(L".exe") != std::wstring::npos) {
        return L"Autorun-zapis zapuskaet .exe iz ProgramData - netipichno.";
    }

    if (lower.find(L"powershell") != std::wstring::npos &&
        (lower.find(L"-encodedcommand") != std::wstring::npos ||
         lower.find(L"-enc ")           != std::wstring::npos ||
         lower.find(L"-w hidden")       != std::wstring::npos ||
         lower.find(L"frombase64string")!= std::wstring::npos)) {
        return L"Autorun zapuskaet PowerShell s obfuscirovannoy/skrytoy komandoy.";
    }
    if (lower.find(L"mshta ")    != std::wstring::npos ||
        lower.find(L"wscript ")  != std::wstring::npos ||
        lower.find(L"cscript ")  != std::wstring::npos) {
        return L"Autorun ispolzuet mshta/wscript/cscript - chastaya tehnika besfaylovyh atak.";
    }
    if (lower.find(L"rundll32 ") != std::wstring::npos &&
        lower.find(L".dll,") == std::wstring::npos) {
        return L"Autorun ispolzuet rundll32 v nestandartnom vide.";
    }

    return {};
}

void EnumerateKey(const RegLoc& loc, IReportSink& sink, CancelToken& cancel) {
    HKEY hKey = nullptr;
    LONG rc = RegOpenKeyExW(loc.root, loc.sub, 0,
                            KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (rc != ERROR_SUCCESS) {
        return;
    }

    DWORD valueCount = 0, maxNameLen = 0, maxDataLen = 0;
    RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                     &valueCount, &maxNameLen, &maxDataLen, nullptr, nullptr);

    std::vector<wchar_t> nameBuf(maxNameLen + 2);
    std::vector<BYTE>    dataBuf(maxDataLen + 2);

    for (DWORD i = 0; i < valueCount; ++i) {
        if (cancel.IsCancelled()) break;

        DWORD nameLen = (DWORD)nameBuf.size();
        DWORD dataLen = (DWORD)dataBuf.size();
        DWORD type    = 0;

        if (RegEnumValueW(hKey, i, nameBuf.data(), &nameLen, nullptr,
                          &type, dataBuf.data(), &dataLen) != ERROR_SUCCESS)
            continue;

        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        std::wstring valueName(nameBuf.data(), nameLen);
        std::wstring valueData(reinterpret_cast<wchar_t*>(dataBuf.data()),
                               dataLen / sizeof(wchar_t));
        while (!valueData.empty() && valueData.back() == L'\0')
            valueData.pop_back();

        sink.Item(std::wstring(loc.label) + L" :: " + valueName);

        std::wstring why = EvaluateValue(valueData);
        if (!why.empty()) {
            Threat t;
            t.kind        = ThreatKind::RegistryValue;
            t.category    = ThreatCategory::AutoStart;
            t.severity    = Severity::High;
            t.name        = valueName;
            t.source      = std::wstring(loc.label) + L" :: " + valueName;
            t.description = why;
            t.evidence    = valueData;
            t.suggestion  = L"Esli vy ne uznaete etot soft - otpravte v karantin.";

            t.regRoot      = loc.root;
            t.regSubKey    = loc.sub;
            t.regValueName = valueName;

            sink.Report(t);
            Logger::Instance().Warn("[Registry] flagged: " +
                                    WideToUtf8(t.source));
        }
    }

    RegCloseKey(hKey);
}

} // namespace

void RegistryScanner::Scan(IReportSink& sink, CancelToken& cancel) {
    Logger::Instance().Info("[Registry] enumerating autorun keys...");

    int idx = 0;
    for (const auto& loc : kAutorunKeys) {
        if (cancel.IsCancelled()) return;

        sink.Progress("Registry: " + WideToUtf8(loc.label),
                      (100 * idx) / (int)kAutorunKeys.size());

        EnumerateKey(loc, sink, cancel);
        ++idx;
    }

    Logger::Instance().Info("[Registry] done.");
}