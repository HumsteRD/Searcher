#include "ScriptScanner.h"
#include "SignatureDB.h"
#include "AppSettings.h"
#include "Logger.h"
#include "Lang.h"

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <map>

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

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// См. комментарий в FileSystemScanner: разделители путей из диалога
// и из обхода каталога различаются.
std::wstring NormalizePath(const std::wstring& p) {
    std::wstring out = fs::path(p).make_preferred().wstring();
    std::transform(out.begin(), out.end(), out.begin(),
        [](wchar_t c) { return (wchar_t)towlower(c); });
    return out;
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

// Короткая выжимка строки для показа: длинные строки обфусцированных
// скриптов иначе занимают весь отчёт.
std::wstring Excerpt(const std::string& line) {
    std::string t = line;
    const size_t first = t.find_first_not_of(" \t");
    if (first != std::string::npos) t = t.substr(first);
    if (t.size() > 120) t = t.substr(0, 117) + "...";
    return Widen(t);
}

// Энтропия Шеннона: у осмысленного кода она заметно ниже, чем
// у base64-блоба или зашифрованной строки.
double Entropy(const std::string& s) {
    if (s.empty()) return 0.0;
    std::map<char, int> freq;
    for (char c : s) ++freq[c];

    double e = 0.0;
    for (const auto& [ch, n] : freq) {
        const double p = double(n) / s.size();
        e -= p * std::log2(p);
    }
    return e;
}

struct Rule {
    const char* needle;     // подстрока в нижнем регистре
    Severity    severity;
    const char* what;       // объяснение по-человечески
};

// Правила намеренно описывают НАМЕРЕНИЕ, а не синтаксис: пользователю
// нужно понять, что скрипт делает, а не какой командой.
const Rule kRules[] = {
    // Загрузка и немедленный запуск чужого кода
    { "downloadstring",      Severity::High,     "Downloads code from the internet" },
    { "downloadfile",        Severity::High,     "Downloads a file from the internet" },
    { "invoke-webrequest",   Severity::Medium,   "Downloads something from the internet" },
    { "invoke-restmethod",   Severity::Medium,   "Downloads something from the internet" },
    { "start-bitstransfer",  Severity::Medium,   "Downloads a file in the background" },
    { "certutil -urlcache",  Severity::High,     "Downloads a file using a system tool (a common trick to look legitimate)" },
    { "certutil -decode",    Severity::High,     "Decodes hidden data using a system tool" },
    { "bitsadmin /transfer", Severity::High,     "Downloads a file using a system tool" },

    { "invoke-expression",   Severity::High,     "Runs code built at runtime — the code is not visible in the file" },
    { "iex(",                Severity::High,     "Runs code built at runtime — the code is not visible in the file" },
    { "iex ",                Severity::High,     "Runs code built at runtime — the code is not visible in the file" },

    // Скрытое выполнение
    { "-encodedcommand",     Severity::Critical, "Runs a command hidden inside encoded text" },
    { " -enc ",              Severity::Critical, "Runs a command hidden inside encoded text" },
    { "frombase64string",    Severity::High,     "Decodes hidden text into code or data" },
    { "-windowstyle hidden", Severity::High,     "Runs without showing any window" },
    { "-w hidden",           Severity::High,     "Runs without showing any window" },
    { "createobject(\"wscript.shell\")", Severity::Medium, "Runs external programs" },

    // Отключение защиты
    { "set-mppreference",    Severity::Critical, "Changes Windows Defender settings" },
    { "disablerealtimemonitoring", Severity::Critical, "Turns off Windows Defender real-time protection" },
    { "add-mppreference -exclusionpath", Severity::Critical, "Hides a folder from Windows Defender" },
    { "amsiinitfailed",      Severity::Critical, "Disables the Windows anti-malware interface" },
    { "sc stop windefend",   Severity::Critical, "Stops Windows Defender" },
    { "netsh advfirewall set", Severity::High,   "Changes firewall rules" },

    // Закрепление в системе
    { "currentversion\\run", Severity::High,     "Adds itself to Windows startup" },
    { "schtasks /create",    Severity::High,     "Creates a scheduled task so it runs again later" },
    { "register-scheduledtask", Severity::High,  "Creates a scheduled task so it runs again later" },
    { "new-service",         Severity::High,     "Installs a Windows service" },
    { "startup\\",           Severity::Medium,   "Places a file in the startup folder" },

    // Кража и слежка
    { "get-clipboard",       Severity::Medium,   "Reads the clipboard" },
    { "clipboard",           Severity::Low,      "Touches the clipboard — check why" },
    { "\\login data",        Severity::Critical, "Reads saved browser passwords" },
    { "\\cookies",           Severity::High,     "Reads browser cookies" },
    { "getasynckeystate",    Severity::Critical, "Records keystrokes" },

    // Заметание следов
    { "remove-item $myinvocation", Severity::High, "Deletes itself after running" },
    { "del %0",              Severity::High,     "Deletes itself after running" },
    { "clear-eventlog",      Severity::Critical, "Erases Windows event logs" },
    { "vssadmin delete shadows", Severity::Critical, "Deletes system restore points — typical for ransomware" },
};

Severity Worst(Severity a, Severity b) { return a > b ? a : b; }

} // namespace

bool ScriptScanner::IsScriptFile(const std::wstring& ext) {
    return ext == L".ps1" || ext == L".bat" || ext == L".cmd" ||
           ext == L".vbs" || ext == L".js"  || ext == L".py"  ||
           ext == L".psm1" || ext == L".hta" || ext == L".wsf";
}

std::vector<ScriptScanner::Hit> ScriptScanner::Analyze(const std::wstring& path) {
    std::vector<Hit> hits;

    std::ifstream in(fs::path(path), std::ios::binary);
    if (!in) return hits;

    std::string line;
    int lineNo = 0;

    while (std::getline(in, line) && lineNo < 20000) {
        ++lineNo;
        if (line.empty()) continue;

        const std::string low = ToLower(line);

        for (const Rule& r : kRules) {
            if (low.find(r.needle) == std::string::npos) continue;
            hits.push_back({ r.severity, lineNo,
                             TR(r.what).toStdWString(), Excerpt(line) });
        }

        // Энтропия НЕ является уликой сама по себе: минифицированный
        // JavaScript — это ровно длинная строка с высокой энтропией.
        // Раньше это правило одно давало сотни ложных срабатываний на
        // временных файлах. Теперь оно лишь усиливает уже найденное
        // поведение — см. отбор по сумме весов в Scan().
        if (line.size() > 200 && Entropy(line) > 4.8) {
            hits.push_back({ Severity::Info, lineNo,
                             TR("A long scrambled line — the real content is hidden")
                                 .toStdWString(),
                             Excerpt(line) });
        }

        // Адреса майнинг-пулов из базы сигнатур.
        for (const auto& token : { "stratum+tcp", "stratum+ssl", "nicehash",
                                   "minexmr", "supportxmr", "pool.hashvault" }) {
            if (low.find(token) != std::string::npos) {
                hits.push_back({ Severity::Critical, lineNo,
                                 L"Connects to a cryptocurrency mining pool",
                                 Excerpt(line) });
                break;
            }
        }
    }

    return hits;
}

void ScriptScanner::Scan(IReportSink& sink, CancelToken& cancel) {
    Logger::Instance().Info("[Scripts] starting script analysis...");

    // Область берём ту же, что и файловый модуль.
    const auto& hot = SignatureDB::Get().HotDirectories();
    std::vector<std::wstring> dirs;

    const std::wstring custom = AppSettings::Get().CustomPath();
    std::error_code ec;

    if (AppSettings::Get().Mode() == AppSettings::ScanMode::Custom &&
        !custom.empty())
    {
        dirs.push_back(fs::is_regular_file(custom, ec)
                       ? fs::path(custom).parent_path().wstring()
                       : custom);
    } else if (AppSettings::Get().Mode() == AppSettings::ScanMode::Quick) {
        dirs.assign(hot.begin(), hot.begin() + std::min<size_t>(hot.size(), 3));
    } else {
        dirs.assign(hot.begin(), hot.end());
    }

    const bool single = !custom.empty() && fs::is_regular_file(custom, ec);
    const std::wstring onlyFile = single ? NormalizePath(custom)
                                        : std::wstring();

    int inspected = 0, flagged = 0;
    const int totalDirs = (int)dirs.size();

    for (int i = 0; i < totalDirs; ++i) {
        if (cancel.IsCancelled()) break;
        sink.Progress("Scripts", (100 * i) / std::max(totalDirs, 1));

        std::error_code ec2;
        for (auto it = fs::recursive_directory_iterator(
                 dirs[i], fs::directory_options::skip_permission_denied, ec2);
             !ec2 && it != fs::recursive_directory_iterator(); it.increment(ec2))
        {
            if (cancel.IsCancelled()) break;
            if (it.depth() > 3) { it.disable_recursion_pending(); continue; }

            std::error_code ec3;
            if (!it->is_regular_file(ec3)) continue;

            const auto p = it->path();
            std::wstring ext = p.extension().wstring();
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](wchar_t c) { return (wchar_t)towlower(c); });

            if (!onlyFile.empty()) {
                if (NormalizePath(p.wstring()) != onlyFile) continue;
            } else if (!IsScriptFile(ext)) {
                continue;
            }

            // Огромные файлы не разбираем: это почти всегда данные,
            // а не скрипт, и построчный проход по ним дорог.
            const auto size = it->file_size(ec3);
            if (!ec3 && size > 4ull * 1024 * 1024) continue;

            ++inspected;
            sink.Item(p.wstring());

            auto hits = Analyze(p.wstring());
            if (hits.empty()) continue;

            // Вес по уровню. Info (энтропия) намеренно весит ноль:
            // запутанный код без единого опасного действия — это просто
            // запутанный код, а не угроза.
            auto weightOf = [](Severity s) {
                switch (s) {
                    case Severity::Critical: return 10;
                    case Severity::High:     return 6;
                    case Severity::Medium:   return 3;
                    case Severity::Low:      return 1;
                    default:                 return 0;
                }
            };

            int score = 0;
            bool scrambled = false;
            for (const auto& h : hits) {
                score += weightOf(h.severity);
                if (h.severity == Severity::Info) scrambled = true;
            }

            // Обфускация добавляет вес только поверх реального поведения.
            if (score > 0 && scrambled) score += 2;

            // Порог: одна High, либо две Medium, либо Critical.
            // Одиночная Medium сама по себе не повод тревожить человека.
            constexpr int kThreshold = 6;
            if (score < kThreshold) continue;

            // Сводим находки в одну угрозу на файл: десяток строк из одного
            // скрипта в таблице — это шум, а не информация.
            Severity worst = Severity::Low;
            std::wstring why;
            int shown = 0;

            int significant = 0;
            for (const auto& h : hits) {
                if (h.severity == Severity::Info) continue;   // шум не показываем
                ++significant;
                worst = Worst(worst, h.severity);

                if (shown < 5) {
                    if (!why.empty()) why += L"\n";
                    why += TR("line").toStdWString() + L" " +
                           std::to_wstring(h.line) + L": " + h.what;
                    ++shown;
                }
            }
            if (significant > shown) {
                why += L"\n+" + std::to_wstring(significant - shown) + L" " +
                       TR("more").toStdWString();
            }

            Threat t;
            t.kind        = ThreatKind::File;
            t.category    = ThreatCategory::SuspiciousFile;
            t.severity    = worst;
            t.name        = p.filename().wstring();
            t.source      = p.wstring();
            t.description = why;
            t.suggestion  = TR("Open the script and look at the lines above "
                               "before running it.").toStdWString();
            t.filePath    = p.wstring();

            sink.Report(t);
            ++flagged;
            Logger::Instance().Warn("[Scripts] flagged: " + WideToUtf8(p.wstring()));
        }
    }

    Logger::Instance().Info("[Scripts] done. Inspected: " +
                            std::to_string(inspected) +
                            ", flagged: " + std::to_string(flagged));
}
