#include "AutorunScanner.h"
#include "CommandTarget.h"
#include "Detections.h"
#include "Logger.h"

#include "../engine/FileAnalyzer.h"

#include <Windows.h>
#include <ShlObj.h>
#include <ShObjIdl.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;
using Detections::Reason;
using Detections::Utf8;

namespace {

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::wstring RootName(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER)  return L"HKCU";
    return L"HK";
}

struct Entry {
    std::wstring location;     // для показа: HKCU\...\Run
    std::wstring name;         // имя значения или файла
    std::wstring command;      // что запускается
    HKEY         root = nullptr;
    std::wstring subKey;
    std::wstring valueName;
    std::wstring startupFile;  // для папки автозагрузки — сам ярлык или файл
    bool         alwaysSuspicious = false;   // сам факт записи — улика
    std::string  extraReason;
};

std::vector<std::pair<std::wstring, std::wstring>> ReadValues(HKEY root, const std::wstring& sub,
                                                              REGSAM view)
{
    std::vector<std::pair<std::wstring, std::wstring>> out;
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, sub.c_str(), 0, KEY_READ | view, &key) != ERROR_SUCCESS) return out;

    DWORD count = 0, maxName = 0, maxData = 0;
    RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &count,
                     &maxName, &maxData, nullptr, nullptr);
    std::vector<wchar_t> name(maxName + 2);
    std::vector<BYTE>    data(maxData + 4);

    for (DWORD i = 0; i < count; ++i) {
        DWORD nl = static_cast<DWORD>(name.size()), dl = static_cast<DWORD>(data.size()), type = 0;
        if (RegEnumValueW(key, i, name.data(), &nl, nullptr, &type, data.data(), &dl) != ERROR_SUCCESS)
            continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        std::wstring value(reinterpret_cast<wchar_t*>(data.data()), dl / sizeof(wchar_t));
        while (!value.empty() && value.back() == L'\0') value.pop_back();
        out.emplace_back(std::wstring(name.data(), nl), value);
    }
    RegCloseKey(key);
    return out;
}

std::wstring ReadString(HKEY root, const std::wstring& sub, const wchar_t* value, REGSAM view) {
    wchar_t buf[2048] = {};
    DWORD size = sizeof(buf);
    if (RegGetValueW(root, sub.c_str(), value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | view,
                     nullptr, buf, &size) != ERROR_SUCCESS)
        return {};
    return buf;
}

DWORD ReadDword(HKEY root, const std::wstring& sub, const wchar_t* value, REGSAM view) {
    DWORD v = 0, size = sizeof(v);
    RegGetValueW(root, sub.c_str(), value, RRF_RT_REG_DWORD | view, nullptr, &v, &size);
    return v;
}

REGSAM ViewFlag(REGSAM view) {
    return view == KEY_WOW64_32KEY ? RRF_SUBKEY_WOW6432KEY : RRF_SUBKEY_WOW6464KEY;
}

void CollectRunKeys(std::vector<Entry>& out) {
    struct Loc { HKEY root; const wchar_t* sub; REGSAM view; };
    const Loc locs[] = {
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_32KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_32KEY },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_64KEY },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", KEY_WOW64_64KEY },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", KEY_WOW64_64KEY },
    };
    for (const Loc& l : locs) {
        for (auto& [name, data] : ReadValues(l.root, l.sub, l.view)) {
            Entry e;
            e.location  = RootName(l.root) + L"\\" + l.sub + (l.view == KEY_WOW64_32KEY ? L" (32-bit)" : L"");
            e.name      = name;
            e.command   = data;
            e.root      = l.root;
            e.subKey    = l.view == KEY_WOW64_32KEY
                ? std::wstring(l.sub).replace(0, 8, L"Software\\WOW6432Node") : l.sub;
            e.valueName = name;
            out.push_back(std::move(e));
        }
    }
}

// Winlogon: Shell и Userinit должны быть стандартными. Добавка через
// запятую — классический способ запускаться вместе с проводником.
void CollectWinlogon(std::vector<Entry>& out) {
    const std::wstring sub = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    for (HKEY root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
        const std::wstring shell = ReadString(root, sub, L"Shell", RRF_SUBKEY_WOW6464KEY);
        if (!shell.empty() && Lower(shell) != L"explorer.exe") {
            Entry e;
            e.location = RootName(root) + L"\\" + sub;
            e.name = L"Shell";
            e.command = shell;
            // Значение у пользователя удаляется — Windows вернётся к общему.
            // Удалять Shell в HKLM нельзя: без него не будет рабочего стола,
            // поэтому там действие только над запускаемым файлом.
            if (root == HKEY_CURRENT_USER) { e.root = root; e.subKey = sub; e.valueName = L"Shell"; }
            e.alwaysSuspicious = true;
            e.extraReason = "winlogon.shell";
            out.push_back(e);
        }
        if (root == HKEY_LOCAL_MACHINE) {
            const std::wstring userinit = ReadString(root, sub, L"Userinit", RRF_SUBKEY_WOW6464KEY);
            std::wstring low = Lower(userinit);
            while (!low.empty() && (low.back() == L',' || low.back() == L' ')) low.pop_back();
            // Системный каталог берём у Windows: она не обязана стоять на C:.
            wchar_t sysDir[MAX_PATH] = {};
            GetSystemDirectoryW(sysDir, MAX_PATH);
            const std::wstring standard = Lower(std::wstring(sysDir) + L"\\userinit.exe");
            if (!low.empty() && low != standard && low != L"userinit.exe") {
                Entry e;
                e.location = RootName(root) + L"\\" + sub;
                e.name = L"Userinit";
                e.command = userinit;
                e.alwaysSuspicious = true;
                e.extraReason = "winlogon.userinit";
                out.push_back(e);
            }
        }
    }
}

// Image File Execution Options: отладчик, назначенный программе,
// запускается вместо неё. Отладчик на экранной клавиатуре или залипании
// клавиш — известный способ получить командную строку на экране входа.
void CollectIfeo(std::vector<Entry>& out) {
    const std::wstring base =
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return;
    wchar_t name[256];
    for (DWORD i = 0;; ++i) {
        DWORD len = 256;
        if (RegEnumKeyExW(key, i, name, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        const std::wstring sub = base + L"\\" + name;
        const std::wstring debugger = ReadString(HKEY_LOCAL_MACHINE, sub, L"Debugger", RRF_SUBKEY_WOW6464KEY);
        if (debugger.empty()) continue;
        const std::wstring target = Lower(name);
        static const wchar_t* kAccessibility[] = {
            L"sethc.exe", L"utilman.exe", L"osk.exe", L"magnify.exe", L"narrator.exe",
            L"displayswitch.exe", L"atbroker.exe",
        };
        const bool critical = std::any_of(std::begin(kAccessibility), std::end(kAccessibility),
                                          [&](const wchar_t* a) { return target == a; });
        // Отладчики разработчика на своих программах — норма; тревожимся за
        // системные программы и за экран входа.
        const bool systemTarget = critical || target == L"taskmgr.exe" || target == L"explorer.exe" ||
                                  target == L"msmpeng.exe" || target == L"mbam.exe";
        if (!systemTarget) continue;
        Entry e;
        e.location = L"HKLM\\" + sub;
        e.name = name;
        e.command = debugger;
        e.root = HKEY_LOCAL_MACHINE; e.subKey = sub; e.valueName = L"Debugger";
        e.alwaysSuspicious = true;
        e.extraReason = critical ? "ifeo.accessibility" : "ifeo.debugger";
        out.push_back(e);
    }
    RegCloseKey(key);
}

void CollectAppInit(std::vector<Entry>& out) {
    const std::wstring sub = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    for (REGSAM view : { KEY_WOW64_64KEY, KEY_WOW64_32KEY }) {
        const std::wstring dlls = ReadString(HKEY_LOCAL_MACHINE, sub, L"AppInit_DLLs", ViewFlag(view));
        if (dlls.empty()) continue;
        if (!ReadDword(HKEY_LOCAL_MACHINE, sub, L"LoadAppInit_DLLs", ViewFlag(view))) continue;
        Entry e;
        e.location = L"HKLM\\" + sub + (view == KEY_WOW64_32KEY ? L" (32-bit)" : L"");
        e.name = L"AppInit_DLLs";
        e.command = dlls;
        e.alwaysSuspicious = true;
        e.extraReason = "appinit";
        out.push_back(e);
    }
}

std::wstring ResolveShortcut(const std::wstring& lnk, std::wstring* args) {
    IShellLinkW* link = nullptr;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                reinterpret_cast<void**>(&link))))
        return {};
    std::wstring target;
    IPersistFile* file = nullptr;
    if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&file)))) {
        if (SUCCEEDED(file->Load(lnk.c_str(), STGM_READ))) {
            wchar_t path[MAX_PATH * 2] = {};
            if (SUCCEEDED(link->GetPath(path, static_cast<int>(std::size(path)), nullptr, SLGP_RAWPATH)))
                target = path;
            wchar_t a[2048] = {};
            if (args && SUCCEEDED(link->GetArguments(a, 2048))) *args = a;
        }
        file->Release();
    }
    link->Release();
    return target;
}

void CollectStartupFolders(std::vector<Entry>& out) {
    for (REFKNOWNFOLDERID id : { FOLDERID_Startup, FOLDERID_CommonStartup }) {
        PWSTR raw = nullptr;
        if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &raw))) continue;
        const std::wstring dir = raw;
        CoTaskMemFree(raw);

        std::error_code ec;
        for (const auto& it : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
            if (!it.is_regular_file(ec)) continue;
            const std::wstring file = it.path().wstring();
            const std::wstring ext = Lower(it.path().extension().wstring());
            if (ext == L".ini") continue;   // desktop.ini
            Entry e;
            e.location = dir;
            e.name = it.path().filename().wstring();
            e.startupFile = file;
            if (ext == L".lnk") {
                std::wstring args;
                const std::wstring target = ResolveShortcut(file, &args);
                e.command = target.empty() ? L"" : L"\"" + target + L"\" " + args;
            } else {
                e.command = L"\"" + file + L"\"";
            }
            out.push_back(std::move(e));
        }
    }
}

} // namespace

void AutorunScanner::Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) {
    const HRESULT co = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    std::vector<Entry> entries;
    CollectRunKeys(entries);
    CollectWinlogon(entries);
    CollectIfeo(entries);
    CollectAppInit(entries);
    CollectStartupFolders(entries);
    Logger::Instance().Info("[Autoruns] " + std::to_string(entries.size()) + " entries");

    FileAnalyzer::Options opt;
    opt.reportPua = config.reportPua;
    long long checked = 0;

    for (size_t i = 0; i < entries.size() && !cancel.IsCancelled(); ++i) {
        const Entry& e = entries[i];
        sink.Progress("Autoruns", static_cast<int>(100 * i / std::max<size_t>(entries.size(), 1)));
        sink.Item(e.location + L" :: " + e.name);
        sink.Checked(++checked);

        Threat t;
        t.kind     = e.startupFile.empty() ? ThreatKind::RegistryValue : ThreatKind::File;
        t.name     = e.name;
        t.source   = e.location + L" :: " + e.name;
        t.evidence = e.command;
        t.regRoot  = e.root;
        t.regSubKey = e.subKey;
        t.regValueName = e.valueName;
        if (!e.startupFile.empty()) t.filePath = e.startupFile;
        // Без ключа реестра действовать можно только над файлом.
        if (t.kind == ThreatKind::RegistryValue && !e.root) t.kind = ThreatKind::File;

        bool flagged = false;

        // Что запускается и что оно выполнит.
        const CommandTarget::Parsed parsed = CommandTarget::Parse(e.command);
        std::vector<std::wstring> targets;
        if (!parsed.executable.empty()) targets.push_back(parsed.executable);
        targets.insert(targets.end(), parsed.payloads.begin(), parsed.payloads.end());

        for (const std::wstring& target : targets) {
            if (config.IsExcludedPath(target)) continue;
            const Verdict v = FileAnalyzer::Analyze(target, opt);
            if (v.level == Verdict::Clean || config.IsAllowedHash(v.sha256)) continue;
            Detections::FillFromVerdict(t, v);
            t.summary = Detections::SummaryOf(v);
            if (t.filePath.empty() || !e.startupFile.empty()) {
                // Для файла в папке автозагрузки в карантин идёт цель ярлыка.
                t.filePath = target;
            }
            flagged = true;
        }

        const std::vector<std::string> abuse = CommandTarget::AbuseReasons(e.command);
        if (!abuse.empty()) {
            for (const auto& r : abuse) t.reasons.push_back(r);
            if (static_cast<int>(t.severity) < static_cast<int>(Severity::High)) t.severity = Severity::High;
            if (t.summary.empty()) t.summary = L"Autorun abuses a system program";
            flagged = true;
        }

        if (e.alwaysSuspicious) {
            t.reasons.push_back(e.extraReason);
            const Severity s = e.extraReason == "ifeo.accessibility" ? Severity::Critical : Severity::High;
            if (static_cast<int>(t.severity) < static_cast<int>(s)) t.severity = s;
            if (t.summary.empty()) t.summary = L"Unusual autostart entry (" + Detections::Wide(e.extraReason) + L")";
            flagged = true;
        }

        if (!flagged) continue;
        t.reasons.insert(t.reasons.begin(), Reason({ "autorun", Utf8(e.location) }));
        if (!parsed.executable.empty()) t.reasons.push_back(Reason({ "runs", Utf8(parsed.executable) }));
        sink.Report(t);
        Logger::Instance().Warn("[Autoruns] flagged: " + Utf8(t.source));
    }

    if (SUCCEEDED(co)) CoUninitialize();
    Logger::Instance().Info("[Autoruns] done");
}
