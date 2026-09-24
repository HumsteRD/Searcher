#include "ScriptHeuristics.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <string>

namespace ScriptHeuristics {
namespace {

enum Lang : unsigned {
    PowerShell = 1,   // .ps1, .psm1 и PowerShell, вызванный из другого сценария
    Batch      = 2,   // .bat, .cmd
    Wsh        = 4,   // .vbs, .vbe, .wsf, .hta, .jse и JS с признаками WSH
    Python     = 8,
    Any        = 15,
};

struct Rule {
    const char* needle;   // в нижнем регистре
    const char* code;
    int         weight;
    unsigned    langs;
};

// Веса — цена ошибки. Порог «подозрительно» — 10: одиночного признака
// с весом 6 мало, нужна связка (скачать + выполнить, спрятать + закрепиться).
const Rule kRules[] = {
    // Скачать и выполнить.
    { "downloadstring",                  "script.download-exec", 6, PowerShell },
    { "downloadfile",                    "script.download", 4, PowerShell },
    { "invoke-webrequest",               "script.download", 3, PowerShell },
    { "invoke-restmethod",               "script.download", 3, PowerShell },
    { "start-bitstransfer",              "script.download", 3, PowerShell },
    { "msxml2.xmlhttp",                  "script.download", 4, Wsh },
    { "winhttp.winhttprequest",          "script.download", 4, Wsh },
    { "adodb.stream",                    "script.drop-file", 4, Wsh },
    { "certutil -urlcache",              "script.lolbin-download", 8, Any },
    { "certutil -decode",                "script.lolbin-decode", 6, Any },
    { "bitsadmin /transfer",             "script.lolbin-download", 6, Any },
    { "invoke-expression",               "script.dynamic-code", 6, PowerShell },
    { "iex(",                            "script.dynamic-code", 6, PowerShell },
    { "iex (",                           "script.dynamic-code", 6, PowerShell },
    { "| iex",                           "script.dynamic-code", 6, PowerShell },
    // Спрятать.
    { "-encodedcommand",                 "script.encoded", 10, PowerShell },
    { " -enc ",                          "script.encoded", 10, PowerShell },
    { "frombase64string",                "script.base64", 4, PowerShell },
    { "-windowstyle hidden",             "script.hidden-window", 5, PowerShell },
    { "-w hidden",                       "script.hidden-window", 5, PowerShell },
    { "wscript.shell",                   "script.shell", 3, Wsh },
    { "shell.application",               "script.shell", 3, Wsh },
    // Отключить защиту.
    { "set-mppreference",                "script.defender", 10, PowerShell },
    { "disablerealtimemonitoring",       "script.defender", 10, Any },
    { "add-mppreference -exclusion",     "script.defender-exclusion", 12, PowerShell },
    { "amsiinitfailed",                  "script.amsi-bypass", 16, PowerShell },
    { "sc stop windefend",               "script.defender", 12, Batch | PowerShell },
    { "netsh advfirewall set",           "script.firewall", 4, Batch | PowerShell },
    // Закрепиться.
    { "currentversion\\run",             "script.autorun", 5, Any },
    { "schtasks /create",                "script.task", 5, Any },
    { "register-scheduledtask",          "script.task", 5, PowerShell },
    { "new-service",                     "script.service", 5, PowerShell },
    { "\\start menu\\programs\\startup", "script.startup", 5, Any },
    // Кража и слежка.
    { "get-clipboard",                   "script.clipboard", 3, PowerShell },
    { "\\login data",                    "script.browser-passwords", 10, Any },
    { "\\network\\cookies",              "script.browser-cookies", 8, Any },
    { "getasynckeystate",                "script.keylogger", 10, Any },
    { "pynput.keyboard",                 "script.keylogger", 8, Python },
    // Замести следы, разрушить.
    { "remove-item $myinvocation",       "script.self-delete", 5, PowerShell },
    { "del %0",                          "script.self-delete", 5, Batch },
    { "clear-eventlog",                  "script.clear-logs", 10, PowerShell },
    { "wevtutil cl",                     "script.clear-logs", 10, Batch | PowerShell },
    { "vssadmin delete shadows",         "script.delete-backups", 16, Any },
    { "wmic shadowcopy delete",          "script.delete-backups", 16, Any },
    { "bcdedit /set {default} recoveryenabled no", "script.delete-backups", 12, Any },
    { "stratum+tcp",                     "script.miner", 16, Any },
    { "stratum+ssl",                     "script.miner", 16, Any },
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

bool Contains(const std::string& text, const char* needle) {
    return text.find(needle) != std::string::npos;
}

} // namespace

bool IsScriptExtension(const std::wstring& ext) {
    return ext == L".ps1" || ext == L".psm1" || ext == L".bat" || ext == L".cmd" ||
           ext == L".vbs" || ext == L".vbe" || ext == L".js" || ext == L".jse" ||
           ext == L".py" || ext == L".pyw" || ext == L".hta" || ext == L".wsf";
}

Result Analyze(const uint8_t* data, size_t size, const std::wstring& ext, const std::wstring& path) {
    Result r;
    if (!data || size == 0) return r;

    // Библиотеки, а не сценарии: их не запускает Windows.
    if (path.find(L"\\node_modules\\") != std::wstring::npos ||
        path.find(L"\\site-packages\\") != std::wstring::npos ||
        path.find(L"\\bower_components\\") != std::wstring::npos)
        return r;

    // Больше 4 МБ — почти всегда данные или собранная библиотека.
    std::string text = ToText(data, std::min<size_t>(size, 4u << 20));
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    unsigned lang = 0;
    if (ext == L".ps1" || ext == L".psm1") lang = PowerShell;
    else if (ext == L".bat" || ext == L".cmd") lang = Batch;
    else if (ext == L".vbs" || ext == L".vbe" || ext == L".wsf" || ext == L".hta" || ext == L".jse") lang = Wsh;
    else if (ext == L".py" || ext == L".pyw") lang = Python;
    else if (ext == L".js") {
        // Обычный JavaScript (браузер, Node) Windows не запускает сама.
        if (!Contains(text, "wscript.") && !Contains(text, "activexobject")) return r;
        lang = Wsh;
    }
    if (!lang) return r;
    // PowerShell, вызванный из batch или VBS, проверяется по правилам PowerShell.
    if (lang != PowerShell && Contains(text, "powershell")) lang |= PowerShell;

    for (const Rule& rule : kRules) {
        if (!(rule.langs & lang)) continue;
        if (!Contains(text, rule.needle)) continue;
        if (std::find(r.rules.begin(), r.rules.end(), rule.code) != r.rules.end()) continue;
        r.rules.push_back(rule.code);
        r.score += rule.weight;
    }

    // Запутанный текст — не улика сам по себе (так выглядит любой
    // минифицированный код), только усиление уже найденного.
    if (r.score >= 6) {
        size_t pos = 0;
        while (pos < text.size()) {
            size_t end = text.find('\n', pos);
            if (end == std::string::npos) end = text.size();
            if (end - pos > 400 && Entropy(text.substr(pos, end - pos)) > 5.2) {
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
