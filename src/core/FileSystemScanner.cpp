#include "FileSystemScanner.h"
#include "SignatureDB.h"
#include "Hasher.h"
#include "Logger.h"
#include "SignatureVerifier.h"
#include "PublisherWhitelist.h"
#include "AppSettings.h"

#include <Windows.h>
#include <filesystem>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_set>
#include <regex>

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

// Пути из диалога выбора приходят с прямыми слэшами, а обход каталога
// отдаёт обратные. Без приведения к одному виду сравнение путей
// не совпадает никогда.
std::wstring NormalizePath(const std::wstring& p) {
    std::wstring out = fs::path(p).make_preferred().wstring();
    std::transform(out.begin(), out.end(), out.begin(),
        [](wchar_t c) { return (wchar_t)towlower(c); });
    return out;
}

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

std::wstring GetExtLower(const fs::path& p) {
    auto ext = p.extension().wstring();
    return ToLower(std::move(ext));
}

bool IsExecutablePE(const std::wstring& extLower) {
    return extLower == L".exe" || extLower == L".dll" ||
           extLower == L".scr" || extLower == L".pif" || extLower == L".com";
}

bool IsScript(const std::wstring& extLower) {
    return extLower == L".bat" || extLower == L".cmd" ||
           extLower == L".vbs" || extLower == L".js"  ||
           extLower == L".ps1" || extLower == L".hta";
}

bool IsExecutable(const std::wstring& extLower) {
    return IsExecutablePE(extLower) || IsScript(extLower);
}

// === Path whitelist ===
// Файлы по этим путям заведомо легитимны — Microsoft, vcpkg, инсталляторы VS.
// Возвращает true, если путь надо пропустить без репорта.
bool IsPathWhitelisted(const std::wstring& fullPathLower) {
    // Каталоги установщика Visual Studio
    static const std::vector<std::wregex> patterns = {
        // VS installer внутри Temp
        std::wregex(LR"(.*\\appdata\\local\\temp\\[a-z0-9]+\.[a-z0-9]+\\.*microsoft\.visualstudio\..*)",
                    std::regex::icase),
        std::wregex(LR"(.*\\appdata\\local\\temp\\[a-z0-9]+\.[a-z0-9]+\\(setup|feedback|installcleanup|vs_|vswhere|dump).*)",
                    std::regex::icase),
        std::wregex(LR"(.*\\appdata\\local\\temp\\[a-z0-9]+\.[a-z0-9]+\\precheck.*)",
                    std::regex::icase),
        std::wregex(LR"(.*\\appdata\\local\\temp\\jyuotlrg\\.*)",
                    std::regex::icase),

        // VS Code installer
        std::wregex(LR"(.*\\appdata\\local\\temp\\vscode-.*)",
                    std::regex::icase),
        std::wregex(LR"(.*\\appdata\\local\\temp\\vs[\\\\]setup\\.*)",
                    std::regex::icase),

        // vcpkg installer
        std::wregex(LR"(.*\\appdata\\local\\temp\\vcpkg\\.*)",
                    std::regex::icase),

        // Microsoft Build / VS системные временные
        std::wregex(LR"(.*\\appdata\\local\\temp\\jyuotlrg\\microsoft\..*)",
                    std::regex::icase),

        // Package Cache (MSI установщики обычно)
        std::wregex(LR"(.*\\programdata\\package cache\\.*)",
                    std::regex::icase),

        // VS Setup в Programdata
        std::wregex(LR"(.*\\programdata\\microsoft\\visualstudio\\.*)",
                    std::regex::icase),

        // OneDrive
        std::wregex(LR"(.*\\appdata\\local\\microsoft\\onedrive\\.*)",
                    std::regex::icase),

        // Roblox
        std::wregex(LR"(.*\\appdata\\local\\roblox\\.*)",
                    std::regex::icase),

        // NSIS installer temp files (Un_A.exe, ~nsu.tmp)
        std::wregex(LR"(.*\\appdata\\local\\temp\\~ns.*\.tmp\\.*)",
                    std::regex::icase),
        std::wregex(LR"(.*\\appdata\\local\\temp\\nsm[a-f0-9]+\.tmp\\.*)",
                    std::regex::icase),
    };

    for (const auto& re : patterns) {
        if (std::regex_match(fullPathLower, re)) return true;
    }
    return false;
}

// Whitelist по цифровой подписи
bool IsWhitelistedBySignature(const fs::path& path, const std::wstring& extLower) {
    if (!IsExecutablePE(extLower)) return false;

    auto sig = SignatureVerifier::Verify(path);
    if (!sig.valid || sig.publisher.empty()) return false;

    return PublisherWhitelist::Get().IsTrusted(sig.publisher);
}

// Файлы крупнее не хэшируем — чтение целиком слишком дорого.
constexpr uintmax_t kMaxHashSize = 50ull * 1024 * 1024;

// === Глобальный (на скан) состояние ===
struct ScanState {
    std::unordered_set<std::wstring> visited; // dedup по абсолютному пути
    int  fileCounter        = 0;
    int  flaggedCounter     = 0;
    int  whitelistedBySig   = 0;
    int  whitelistedByPath  = 0;
    int  hashedCounter      = 0;
    bool deepScan           = false;

    // Проверка одного конкретного файла (перетащили в окно).
    // Хранится в нижнем регистре для сравнения путей.
    std::wstring onlyFile;
};

void ScanDir(const fs::path& dir,
             IReportSink& sink,
             CancelToken& cancel,
             int depth,
             int maxDepth,
             ScanState& st)
{
    if (cancel.IsCancelled() || depth > maxDepth) return;

    std::error_code ec;
    if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) return;

    for (auto it = fs::directory_iterator(
                       dir, fs::directory_options::skip_permission_denied, ec);
         !ec && it != fs::directory_iterator();
         it.increment(ec))
    {
        if (cancel.IsCancelled()) return;

        std::error_code ec2;
        const auto& entry = *it;

        if (entry.is_directory(ec2)) {
            ScanDir(entry.path(), sink, cancel, depth + 1, maxDepth, st);
            continue;
        }
        if (!entry.is_regular_file(ec2)) continue;

        const auto& path  = entry.path();
        const auto extLow = GetExtLower(path);

        const auto fname    = path.filename().wstring();
        const auto fpath    = path.wstring();
        const auto fpathLow = ToLower(fpath);

        if (!st.onlyFile.empty()) {
            // Явно указанный файл проверяем независимо от расширения:
            // пользователь попросил именно его.
            if (NormalizePath(fpath) != st.onlyFile) continue;
        } else if (!IsExecutable(extLow)) {
            continue;
        }

        // Dedup: один и тот же файл не флагаем дважды,
        // даже если попали в него через разные родительские пути
        if (!st.visited.insert(fpathLow).second) continue;

        ++st.fileCounter;
        sink.Item(fpath);

        // Сразу проверяем path whitelist
        if (IsPathWhitelisted(fpathLow)) {
            ++st.whitelistedByPath;
            continue;
        }

        bool flagged = false;
        Severity sev = Severity::Low;
        std::wstring why;

        if (SignatureDB::Get().IsSuspiciousFileName(fname)) {
            flagged = true;
            sev = Severity::High;
            why = L"Suspicious file name pattern (matches malware/miner heuristic).";
        }

        // Эвристика "exe в подозрительном месте" — но ТОЛЬКО для PE.
        // Скрипты сами по себе не флагуем за расположение —
        // слишком много легитимных .ps1/.bat в Temp.
        if (IsExecutablePE(extLow) &&
            SignatureDB::Get().IsSuspiciousPath(fpath))
        {
            flagged = true;
            if (sev < Severity::Medium) sev = Severity::Medium;
            if (!why.empty()) why += L" ";
            why += L"Executable located in a non-standard directory typical for droppers.";
        }

        std::string sha;
        bool hashed = false;

        // Deep scan: хэшируем каждый исполняемый файл, а не только тот,
        // что уже помечен эвристикой, — так ловим известные семплы
        // с безобидным именем в безобидном месте.
        if (st.deepScan && !flagged) {
            auto sz = entry.file_size(ec2);
            if (!ec2 && sz < kMaxHashSize) {
                if (auto h = Hasher::Sha256File(path)) {
                    sha = *h;
                    hashed = true;
                    ++st.hashedCounter;
                    if (SignatureDB::Get().IsKnownMaliciousHash(sha)) {
                        flagged = true;
                        sev = Severity::Critical;
                        why = L"SHA-256 matches a known malicious file.";
                    }
                }
            }
        }

        if (!flagged) continue;

        // Whitelist по подписи — только для PE
        if (IsWhitelistedBySignature(path, extLow)) {
            ++st.whitelistedBySig;
            continue;
        }

        // Хэш + сверка с базой malware
        if (!hashed) {
            auto sz = entry.file_size(ec2);
            if (!ec2 && sz < kMaxHashSize) {
                if (auto h = Hasher::Sha256File(path)) {
                    sha = *h;
                    ++st.hashedCounter;
                    if (SignatureDB::Get().IsKnownMaliciousHash(sha)) {
                        sev = Severity::Critical;
                        if (!why.empty()) why += L" ";
                        why += L"SHA-256 matches a known malicious file.";
                    }
                }
            }
        }

        ++st.flaggedCounter;

        Threat t;
        t.kind        = ThreatKind::File;
        t.category    = ThreatCategory::SuspiciousFile;
        t.severity    = sev;
        t.name        = fname;
        t.source      = fpath;
        t.description = why;
        t.evidence    = sha.empty() ? L"" : std::wstring(sha.begin(), sha.end());
        t.suggestion  = L"Inspect the file. If unknown — quarantine or delete.";
        t.filePath    = fpath;

        sink.Report(t);
        Logger::Instance().Warn("[FS] flagged: " + WideToUtf8(fpath));
    }
}

} // namespace

void FileSystemScanner::Scan(IReportSink& sink, CancelToken& cancel) {
    ScanState st;
    st.deepScan = AppSettings::Get().DeepScan();

    // В глубоком режиме заходим дальше по дереву и хэшируем всё исполняемое.
    int maxDepth = st.deepScan ? 6 : 3;
    if (AppSettings::Get().Mode() == AppSettings::ScanMode::Quick) maxDepth = 2;
    if (AppSettings::Get().Mode() == AppSettings::ScanMode::Custom) maxDepth = 6;

    Logger::Instance().Info(std::string("[FS] starting filesystem scan (") +
                            (st.deepScan ? "deep" : "normal") + " mode)...");

    // Область обхода зависит от режима проверки.
    const auto& hot = SignatureDB::Get().HotDirectories();
    std::vector<std::wstring> dirs;

    switch (AppSettings::Get().Mode()) {
    case AppSettings::ScanMode::Custom: {
        const std::wstring custom = AppSettings::Get().CustomPath();
        std::error_code ec;

        if (!custom.empty() && fs::is_regular_file(custom, ec)) {
            // Перетащили файл: обходим его папку без углубления
            // и отбираем ровно этот путь.
            st.onlyFile = NormalizePath(custom);
            dirs.push_back(fs::path(custom).parent_path().wstring());
        } else if (!custom.empty()) {
            dirs.push_back(custom);
        } else {
            dirs.assign(hot.begin(), hot.end());
        }
        break;
    }
    case AppSettings::ScanMode::Quick:
        // Быстрая: только первые каталоги списка — самые рискованные.
        dirs.assign(hot.begin(),
                    hot.begin() + std::min<size_t>(hot.size(), 3));
        break;
    case AppSettings::ScanMode::Full:
    default:
        dirs.assign(hot.begin(), hot.end());
        break;
    }

    // Поправку к глубине делаем после выбора режима: onlyFile
    // становится известен только там.
    if (!st.onlyFile.empty()) maxDepth = 0;   // только сам файл

    int totalDirs = (int)dirs.size();

    for (int i = 0; i < totalDirs; ++i) {
        if (cancel.IsCancelled()) break;

        const auto& dir = dirs[i];
        sink.Progress("FS: " + WideToUtf8(dir),
                      (100 * i) / std::max(totalDirs, 1));

        Logger::Instance().Info("[FS] scanning: " + WideToUtf8(dir));
        ScanDir(fs::path(dir), sink, cancel, 0, maxDepth, st);
    }

    Logger::Instance().Info(
        "[FS] done. Inspected: " + std::to_string(st.fileCounter) +
        ", hashed: " + std::to_string(st.hashedCounter) +
        ", flagged: " + std::to_string(st.flaggedCounter) +
        ", skipped by signature: " + std::to_string(st.whitelistedBySig) +
        ", skipped by path: " + std::to_string(st.whitelistedByPath));
}
