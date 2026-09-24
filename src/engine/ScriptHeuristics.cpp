#include "ScriptHeuristics.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <string>

namespace ScriptHeuristics {
namespace {

struct Rule {
    const char* needle;   // в нижнем регистре
    const char* code;
    int         weight;
};

// Веса — цена ошибки: 10 берут порог «подозрительно» в одиночку только
// в паре с чем-то ещё, 6 — одна из двух улик, 3 — только усиление.
const Rule kRules[] = {
    { "downloadstring",                  "script.download-exec", 6 },
    { "downloadfile",                    "script.download", 6 },
    { "invoke-webrequest",               "script.download", 3 },
    { "invoke-restmethod",               "script.download", 3 },
    { "start-bitstransfer",              "script.download", 3 },
    { "certutil -urlcache",              "script.lolbin-download", 6 },
    { "certutil -decode",                "script.lolbin-decode", 6 },
    { "bitsadmin /transfer",             "script.lolbin-download", 6 },
    { "invoke-expression",               "script.dynamic-code", 6 },
    { "iex(",                            "script.dynamic-code", 6 },
    { "iex (",                           "script.dynamic-code", 6 },
    { "-encodedcommand",                 "script.encoded", 10 },
    { " -enc ",                          "script.encoded", 10 },
    { "frombase64string",                "script.base64", 6 },
    { "-windowstyle hidden",             "script.hidden-window", 6 },
    { "-w hidden",                       "script.hidden-window", 6 },
    { "createobject(\"wscript.shell\")", "script.shell", 3 },
    { "set-mppreference",                "script.defender", 10 },
    { "disablerealtimemonitoring",       "script.defender", 10 },
    { "add-mppreference -exclusion",     "script.defender-exclusion", 10 },
    { "amsiinitfailed",                  "script.amsi-bypass", 12 },
    { "sc stop windefend",               "script.defender", 10 },
    { "netsh advfirewall set",           "script.firewall", 6 },
    { "currentversion\\run",             "script.autorun", 6 },
    { "schtasks /create",                "script.task", 6 },
    { "register-scheduledtask",          "script.task", 6 },
    { "new-service",                     "script.service", 6 },
    { "\\start menu\\programs\\startup", "script.startup", 6 },
    { "get-clipboard",                   "script.clipboard", 3 },
    { "\\login data",                    "script.browser-passwords", 10 },
    { "\\cookies",                       "script.browser-cookies", 6 },
    { "getasynckeystate",                "script.keylogger", 10 },
    { "remove-item $myinvocation",       "script.self-delete", 6 },
    { "del %0",                          "script.self-delete", 6 },
    { "clear-eventlog",                  "script.clear-logs", 10 },
    { "wevtutil cl",                     "script.clear-logs", 10 },
    { "vssadmin delete shadows",         "script.delete-backups", 12 },
    { "wmic shadowcopy delete",          "script.delete-backups", 12 },
    { "bcdedit /set {default} recoveryenabled no", "script.delete-backups", 10 },
    { "stratum+tcp",                     "script.miner", 12 },
    { "stratum+ssl",                     "script.miner", 12 },
};

double Entropy(const std::string& s) {
    int freq[256] = {};
    for (unsigned char c : s) ++freq[c];
    double e = 0.0;
    for (int n : freq) {
        if (!n) continue;
        const double p = static_cast<double>(n) / s.size();
        e -= p * std::log2(p);
    }
    return e;
}

// UTF-16 (PowerShell любит его) → байты ASCII; остальное как есть.
std::string ToText(const uint8_t* data, size_t size) {
    if (size >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        std::string out;
        out.reserve(size / 2);
        for (size_t i = 2; i + 1 < size; i += 2) {
            const uint16_t ch = static_cast<uint16_t>(data[i] | (data[i + 1] << 8));
            out += ch < 128 ? static_cast<char>(ch) : '?';
        }
        return out;
    }
    return std::string(reinterpret_cast<const char*>(data), size);
}

} // namespace

bool IsScriptExtension(const std::wstring& ext) {
    return ext == L".ps1" || ext == L".psm1" || ext == L".bat" || ext == L".cmd" ||
           ext == L".vbs" || ext == L".vbe" || ext == L".js" || ext == L".jse" ||
           ext == L".py" || ext == L".pyw" || ext == L".hta" || ext == L".wsf";
}

Result Analyze(const uint8_t* data, size_t size) {
    Result r;
    if (!data || size == 0) return r;
    // Больше 4 МБ — почти всегда данные или собранная библиотека, а не сценарий.
    std::string text = ToText(data, std::min<size_t>(size, 4u << 20));
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const Rule& rule : kRules) {
        if (text.find(rule.needle) == std::string::npos) continue;
        if (std::find(r.rules.begin(), r.rules.end(), rule.code) != r.rules.end()) continue;
        r.rules.push_back(rule.code);
        r.score += rule.weight;
    }

    // Запутанный текст — не улика сам по себе (так выглядит любой
    // минифицированный JavaScript), только усиление найденного.
    if (r.score > 0) {
        size_t pos = 0;
        while (pos < text.size()) {
            size_t end = text.find('\n', pos);
            if (end == std::string::npos) end = text.size();
            if (end - pos > 400 && Entropy(text.substr(pos, end - pos)) > 5.0) {
                r.rules.push_back("script.obfuscated");
                r.score += 3;
                break;
            }
            pos = end + 1;
        }
    }
    return r;
}

} // namespace ScriptHeuristics
