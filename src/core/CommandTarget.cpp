#include "CommandTarget.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>

namespace CommandTarget {
namespace {

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::wstring Expand(const std::wstring& s) {
    if (s.find(L'%') == std::wstring::npos) return s;
    wchar_t buf[4096] = {};
    const DWORD n = ExpandEnvironmentStringsW(s.c_str(), buf, 4096);
    return (n > 0 && n <= 4096) ? std::wstring(buf) : s;
}

bool IsFile(const std::wstring& p) {
    if (p.empty()) return false;
    const DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring Trim(std::wstring s) {
    const auto notSpace = [](wchar_t c) { return !std::iswspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

// Найти программу по голому имени так же, как это сделает Windows.
std::wstring Resolve(const std::wstring& name) {
    if (name.empty()) return {};
    if (IsFile(name)) return name;
    wchar_t buf[MAX_PATH * 2] = {};
    if (SearchPathW(nullptr, name.c_str(), L".exe", static_cast<DWORD>(std::size(buf)), buf, nullptr))
        return buf;
    return {};
}

// Разбить аргументы, уважая кавычки.
std::vector<std::wstring> SplitArgs(const std::wstring& s) {
    std::vector<std::wstring> out;
    std::wstring cur;
    bool quoted = false;
    for (wchar_t c : s) {
        if (c == L'"') { quoted = !quoted; continue; }
        if (!quoted && std::iswspace(c)) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
            continue;
        }
        cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::wstring FileNameLower(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return Lower(slash == std::wstring::npos ? path : path.substr(slash + 1));
}

} // namespace

std::wstring NormalizeImagePath(const std::wstring& raw) {
    std::wstring p = Trim(Expand(raw));
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    const std::wstring low = Lower(p);

    if (low.rfind(L"\\??\\", 0) == 0) return p.substr(4);
    if (low.rfind(L"\\systemroot\\", 0) == 0) return std::wstring(winDir) + p.substr(11);
    if (low.rfind(L"system32\\", 0) == 0 || low.rfind(L"syswow64\\", 0) == 0)
        return std::wstring(winDir) + L"\\" + p;
    return p;
}

Parsed Parse(const std::wstring& commandLine) {
    Parsed r;
    const std::wstring cmd = Trim(NormalizeImagePath(commandLine));
    if (cmd.empty()) return r;

    if (cmd.front() == L'"') {
        const size_t end = cmd.find(L'"', 1);
        r.executable = cmd.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
        r.arguments  = end == std::wstring::npos ? L"" : Trim(cmd.substr(end + 1));
    } else {
        // Незакавыченный путь с пробелами: пробуем всё более длинные
        // префиксы, пока не найдётся существующий файл.
        size_t pos = 0;
        for (;;) {
            const size_t space = cmd.find(L' ', pos);
            const std::wstring head = cmd.substr(0, space);
            if (IsFile(head) || IsFile(head + L".exe")) {
                r.executable = IsFile(head) ? head : head + L".exe";
                r.arguments  = space == std::wstring::npos ? L"" : Trim(cmd.substr(space + 1));
                break;
            }
            if (space == std::wstring::npos) {
                // Ничего не нашлось: первый токен — имя программы.
                const size_t first = cmd.find(L' ');
                r.executable = cmd.substr(0, first);
                r.arguments  = first == std::wstring::npos ? L"" : Trim(cmd.substr(first + 1));
                break;
            }
            pos = space + 1;
        }
    }

    // Голое имя (rundll32.exe, powershell) — ищем, как ищет Windows.
    if (r.executable.find(L'\\') == std::wstring::npos) {
        const std::wstring found = Resolve(r.executable);
        if (!found.empty()) r.executable = found;
    }

    // Что выполнит интерпретатор или загрузчик DLL.
    const std::wstring exe = FileNameLower(r.executable);
    const std::vector<std::wstring> args = SplitArgs(r.arguments);
    static const wchar_t* kScriptHosts[] = {
        L"wscript.exe", L"cscript.exe", L"mshta.exe", L"python.exe", L"pythonw.exe",
        L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"node.exe", L"java.exe", L"javaw.exe",
    };
    const bool scriptHost = std::any_of(std::begin(kScriptHosts), std::end(kScriptHosts),
                                        [&](const wchar_t* h) { return exe == h; });

    for (const std::wstring& a : args) {
        std::wstring candidate = a;
        if (exe == L"rundll32.exe") {
            const size_t comma = candidate.find(L',');
            if (comma != std::wstring::npos) candidate = candidate.substr(0, comma);
        }
        if (exe == L"regsvr32.exe" && !candidate.empty() && candidate[0] == L'/') continue;
        if (!(scriptHost || exe == L"rundll32.exe" || exe == L"regsvr32.exe")) break;
        if (candidate.empty() || candidate[0] == L'-' || candidate[0] == L'/') continue;
        const std::wstring expanded = Expand(candidate);
        if (IsFile(expanded)) r.payloads.push_back(expanded);
    }
    return r;
}

std::vector<std::string> AbuseReasons(const std::wstring& commandLine) {
    std::vector<std::string> out;
    const std::wstring c = Lower(commandLine);
    auto has = [&](const wchar_t* s) { return c.find(s) != std::wstring::npos; };
    const bool powershell = has(L"powershell") || has(L"pwsh");

    if (powershell && (has(L" -enc") || has(L" -e ") || has(L"-encodedcommand") ||
                       has(L"frombase64string")))
        out.push_back("cmd.encoded");
    if (powershell && (has(L"downloadstring") || has(L"downloadfile") || has(L"net.webclient") ||
                       has(L"invoke-webrequest") || has(L"iwr ") || has(L"start-bitstransfer") ||
                       has(L"invoke-restmethod") || has(L"irm ")) &&
        (has(L"iex") || has(L"invoke-expression") || has(L"start-process") || has(L".exe")))
        out.push_back("cmd.download");
    if (has(L"mshta") && (has(L"http:") || has(L"https:") || has(L"javascript:") ||
                          has(L"vbscript:")))
        out.push_back("cmd.mshta");
    if (has(L"regsvr32") && has(L"/i:http"))
        out.push_back("cmd.regsvr32");
    if (has(L"rundll32") && (has(L"javascript:") || has(L"runhtmlapplication")))
        out.push_back("cmd.rundll32-script");
    if (has(L"certutil") && (has(L"-urlcache") || has(L"-decode")))
        out.push_back("cmd.certutil");
    if (has(L"bitsadmin") && has(L"/transfer"))
        out.push_back("cmd.bitsadmin");
    if ((has(L"wscript") || has(L"cscript")) && has(L"//b ") && has(L"//e:"))
        out.push_back("cmd.hidden-script");
    return out;
}

} // namespace CommandTarget
