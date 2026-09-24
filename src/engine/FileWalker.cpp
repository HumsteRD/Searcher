#include "FileWalker.h"
#include "FileAnalyzer.h"

#include <Windows.h>
#include <ShlObj.h>

#include <algorithm>
#include <cwctype>
#include <unordered_set>

namespace FileWalker {
namespace {

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::wstring Trim(std::wstring p) {
    std::replace(p.begin(), p.end(), L'/', L'\\');
    while (p.size() > 3 && (p.back() == L'\\')) p.pop_back();
    return p;
}

std::wstring Known(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, nullptr, &raw)) && raw) out = raw;
    if (raw) CoTaskMemFree(raw);
    return Trim(out);
}

std::wstring TempDir() {
    wchar_t buf[MAX_PATH + 1] = {};
    const DWORD n = GetTempPathW(MAX_PATH, buf);
    return n ? Trim(std::wstring(buf, n)) : std::wstring();
}

std::wstring WindowsDir() {
    wchar_t buf[MAX_PATH] = {};
    GetWindowsDirectoryW(buf, MAX_PATH);
    return Trim(buf);
}

bool StartsWithDir(const std::wstring& pathLower, const std::wstring& dirLower) {
    if (dirLower.empty() || pathLower.size() < dirLower.size()) return false;
    if (pathLower.compare(0, dirLower.size(), dirLower) != 0) return false;
    return pathLower.size() == dirLower.size() || pathLower[dirLower.size()] == L'\\' ||
           dirLower.back() == L'\\';
}

// Папки, где «смотреть байты» у файлов с непонятным расширением ещё
// оправдано: туда попадает скачанное. В AppData так делать нельзя —
// кэши браузеров это миллионы файлов без расширения.
std::vector<std::wstring> SniffZones() {
    static const std::vector<std::wstring> zones = [] {
        std::vector<std::wstring> z;
        for (const std::wstring& p : { Known(FOLDERID_Downloads), Known(FOLDERID_Desktop),
                                       TempDir(), Known(FOLDERID_Startup),
                                       Known(FOLDERID_CommonStartup), Known(FOLDERID_Public) })
            if (!p.empty()) z.push_back(Lower(p));
        return z;
    }();
    return zones;
}

bool InSniffZone(const std::wstring& lower) {
    for (const std::wstring& z : SniffZones())
        if (StartsWithDir(lower, z)) return true;
    return false;
}

const std::unordered_set<std::wstring>& SkippedFileNames() {
    static const std::unordered_set<std::wstring> k = {
        L"pagefile.sys", L"hiberfil.sys", L"swapfile.sys", L"dumpstack.log",
        L"dumpstack.log.tmp",
    };
    return k;
}

const std::unordered_set<std::wstring>& SkippedDirNames() {
    static const std::unordered_set<std::wstring> k = {
        L"system volume information", L"$windows.~bt", L"$windows.~ws",
    };
    return k;
}

} // namespace

std::vector<std::wstring> DefaultExcludes() {
    std::vector<std::wstring> out;
    const std::wstring win = Lower(WindowsDir());
    const std::wstring pd  = Lower(Known(FOLDERID_ProgramData));
    if (!win.empty()) {
        for (const wchar_t* sub : { L"\\winsxs", L"\\servicing", L"\\softwaredistribution\\datastore",
                                    L"\\csc", L"\\systemapps\\microsoft.windows.search_cw5n1h2txyewy" })
            out.push_back(win + sub);
    }
    if (!pd.empty()) {
        // Базы других антивирусов состоят из сигнатур — на них срабатывает
        // всё подряд. Свои данные (карантин, базы) тоже не проверяем.
        for (const wchar_t* sub : { L"\\microsoft\\windows defender", L"\\kaspersky lab",
                                    L"\\eset", L"\\avast software", L"\\avg", L"\\malwarebytes",
                                    L"\\bitdefender", L"\\norton", L"\\mcafee", L"\\symantec",
                                    L"\\doctor web", L"\\drweb", L"\\threatscanner",
                                    L"\\microsoft\\windows\\wer" })
            out.push_back(pd + sub);
    }
    wchar_t exe[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(std::size(exe)));
    std::wstring own = Lower(exe);
    const size_t slash = own.find_last_of(L'\\');
    if (slash != std::wstring::npos) out.push_back(own.substr(0, slash) + L"\\signatures");
    return out;
}

bool IsRiskyLocation(const std::wstring& path) {
    static const std::vector<std::wstring> zones = [] {
        std::vector<std::wstring> z;
        for (const std::wstring& p : { Known(FOLDERID_Downloads), Known(FOLDERID_Desktop), TempDir(),
                                       Known(FOLDERID_RoamingAppData), Known(FOLDERID_LocalAppData),
                                       Known(FOLDERID_Startup), Known(FOLDERID_CommonStartup),
                                       Known(FOLDERID_Public), WindowsDir() + L"\\Temp" })
            if (!p.empty()) z.push_back(Lower(p));
        const std::wstring pd = Lower(Known(FOLDERID_ProgramData));
        if (!pd.empty()) z.push_back(pd);
        return z;
    }();
    const std::wstring lower = Lower(Trim(path));
    for (const std::wstring& z : zones)
        if (StartsWithDir(lower, z)) return true;
    return false;
}

std::vector<Root> QuickRoots() {
    std::vector<Root> r;
    auto add = [&](const std::wstring& p, int depth, bool risky) {
        if (!p.empty() && GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES)
            r.push_back({ p, depth, risky });
    };
    // Порядок — по вероятности встретить вредонос.
    add(Known(FOLDERID_Downloads), 8, true);
    add(Known(FOLDERID_Desktop), 6, true);
    add(TempDir(), 6, true);
    add(Known(FOLDERID_Startup), 3, true);
    add(Known(FOLDERID_CommonStartup), 3, true);
    add(Known(FOLDERID_RoamingAppData), 5, true);
    add(Known(FOLDERID_LocalAppData), 4, true);
    add(Known(FOLDERID_Public), 5, true);
    add(Known(FOLDERID_ProgramData), 3, true);
    add(WindowsDir() + L"\\Temp", 5, true);
    add(Known(FOLDERID_Documents), 4, false);
    return r;
}

std::vector<Root> FullRoots() {
    std::vector<Root> r;
    // Сначала рискованные папки — угроза, если она есть, найдётся раньше.
    // Глубина у них полная: при обходе дисков эти папки уже не повторяются.
    for (Root q : QuickRoots()) { q.maxDepth = 64; r.push_back(q); }

    const DWORD mask = GetLogicalDrives();
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        if (!(mask & (1u << (letter - L'A')))) continue;
        const std::wstring root = std::wstring(1, letter) + L":\\";
        const UINT type = GetDriveTypeW(root.c_str());
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;
        r.push_back({ root, 64, false });
    }
    return r;
}

std::vector<Root> CustomRoots(const std::vector<std::wstring>& paths) {
    std::vector<Root> r;
    for (const std::wstring& p : paths) {
        if (!p.empty()) r.push_back({ Trim(p), 64, false });
    }
    return r;
}

void Walk(const std::vector<Root>& roots, const std::vector<std::wstring>& userExcludes,
          const std::atomic<bool>& cancel, Stats& stats,
          const std::function<void(Candidate&&)>& sink)
{
    std::vector<std::wstring> excludes = DefaultExcludes();
    for (const std::wstring& e : userExcludes) {
        if (!e.empty()) excludes.push_back(Lower(Trim(e)));
    }

    // Уже пройденные корни: папка, которую обходит отдельный корень
    // (Temp внутри LocalAppData), второй раз не обходится.
    std::vector<std::wstring> walked;

    for (size_t ri = 0; ri < roots.size() && !cancel.load(); ++ri) {
        const Root& root = roots[ri];
        const std::wstring rootLower = Lower(Trim(root.path));

        bool covered = false;
        for (const std::wstring& w : walked)
            if (StartsWithDir(rootLower, w)) covered = true;
        if (covered) continue;

        // Одиночный файл как корень — пользователь выбрал именно его.
        const DWORD attrs = GetFileAttributesW(root.path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) continue;
        if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            WIN32_FILE_ATTRIBUTE_DATA a{};
            GetFileAttributesExW(root.path.c_str(), GetFileExInfoStandard, &a);
            Candidate c;
            c.path = root.path;
            c.size = (static_cast<uint64_t>(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
            ++stats.files;
            ++stats.candidates;
            stats.candidateBytes += c.size;
            sink(std::move(c));
            continue;
        }

        // Корни, которые пойдут отдельно позже, внутри этого пропускаем.
        std::vector<std::wstring> later;
        for (size_t k = ri + 1; k < roots.size(); ++k) {
            const std::wstring l = Lower(Trim(roots[k].path));
            if (StartsWithDir(l, rootLower) && l != rootLower) later.push_back(l);
        }

        struct Dir { std::wstring path; int depth; };
        std::vector<Dir> stack{ { Trim(root.path), 0 } };
        const bool rootSniff = InSniffZone(rootLower);

        while (!stack.empty() && !cancel.load()) {
            Dir dir = std::move(stack.back());
            stack.pop_back();
            ++stats.directories;

            std::wstring pattern = dir.path;
            if (pattern.back() != L'\\') pattern += L'\\';
            const std::wstring prefix = pattern;
            pattern += L'*';
            const std::wstring longPattern =
                pattern.rfind(L"\\\\", 0) == 0 ? pattern : L"\\\\?\\" + pattern;

            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileExW(longPattern.c_str(), FindExInfoBasic, &fd,
                                        FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
            if (h == INVALID_HANDLE_VALUE) continue;

            const std::wstring dirLower = Lower(dir.path);
            const bool sniffHere = rootSniff || InSniffZone(dirLower);

            do {
                if (cancel.load()) break;
                const wchar_t* name = fd.cFileName;
                if (name[0] == L'.' && (name[1] == 0 || (name[1] == L'.' && name[2] == 0))) continue;

                const std::wstring full = prefix + name;
                const DWORD a = fd.dwFileAttributes;

                if (a & FILE_ATTRIBUTE_DIRECTORY) {
                    // Точки повторной обработки (ссылки и соединения) не
                    // обходим: они ведут в уже пройденное или по кругу.
                    if (a & FILE_ATTRIBUTE_REPARSE_POINT) continue;
                    if (dir.depth + 1 > root.maxDepth) continue;
                    const std::wstring lower = Lower(full);
                    if (SkippedDirNames().count(Lower(name))) continue;
                    bool skip = false;
                    for (const std::wstring& e : excludes)
                        if (StartsWithDir(lower, e)) { skip = true; break; }
                    for (const std::wstring& l : later)
                        if (lower == l) { skip = true; break; }
                    for (const std::wstring& w : walked)
                        if (lower == w) { skip = true; break; }
                    if (!skip) stack.push_back({ full, dir.depth + 1 });
                    continue;
                }

                ++stats.files;

                // Облачные заглушки OneDrive: чтение скачало бы файл из сети.
                if (a & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS |
                         FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_REPARSE_POINT))
                    continue;
                if (SkippedFileNames().count(Lower(name))) continue;

                const bool byName = FileAnalyzer::IsCandidateByName(name);
                bool sniff = false;
                if (!byName) {
                    if (!sniffHere) continue;
                    // Смотрим байты только у того, что без расширения или
                    // с расширением, которое ничего не говорит.
                    const wchar_t* dot = wcsrchr(name, L'.');
                    static const std::unordered_set<std::wstring> kVague = {
                        L".tmp", L".bin", L".dat", L".dmp", L".log", L".part",
                        L".crdownload", L".download", L".partial",
                    };
                    if (dot && !kVague.count(Lower(dot))) continue;
                    sniff = true;
                }

                Candidate c;
                c.path  = full;
                c.size  = (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
                c.sniff = sniff;
                ++stats.candidates;
                stats.candidateBytes += c.size;
                sink(std::move(c));
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        walked.push_back(rootLower);
    }
}

} // namespace FileWalker
