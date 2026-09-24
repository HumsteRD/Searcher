#include "FileAnalyzer.h"
#include "Classify.h"
#include "HashDatabase.h"
#include "TrustVerifier.h"
#include "Unpack.h"
#include "ScriptHeuristics.h"
#include "YaraEngine.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cwctype>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#pragma comment(lib, "bcrypt.lib")

namespace FileAnalyzer {
namespace {

// Файлы до этого размера читаются целиком в память; крупнее — YARA
// отображает их сама, а хэш считается потоком.
constexpr size_t kInMemoryLimit = 64u << 20;

// SHA-256 тестового файла EICAR (68 байт, стандарт проверки антивирусов).
// Хранится хэш, а не сама строка: иначе чужой антивирус поймал бы
// на ней наш собственный исполняемый файл.
constexpr const char* kEicarSha256[] = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
};

std::wstring LowerW(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::wstring ExtOf(const std::wstring& name) {
    const size_t dot = name.find_last_of(L'.');
    const size_t slash = name.find_last_of(L"\\/");
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash)) return {};
    return LowerW(name.substr(dot));
}

std::wstring FileNameOf(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::string ToHex(const uint8_t* d, size_t n) {
    static const char hex[] = "0123456789abcdef";
    std::string s(n * 2, '0');
    for (size_t i = 0; i < n; ++i) { s[2 * i] = hex[d[i] >> 4]; s[2 * i + 1] = hex[d[i] & 0xF]; }
    return s;
}

std::string Narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n,
                        nullptr, nullptr);
    return out;
}

// ─── SHA-256 ───

BCRYPT_ALG_HANDLE ShaProvider() {
    static BCRYPT_ALG_HANDLE alg = [] {
        BCRYPT_ALG_HANDLE h = nullptr;
        BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        return h;
    }();
    return alg;
}

bool Sha256(const uint8_t* data, size_t size, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = ShaProvider();
    if (!alg) return false;
    return BCryptHash(alg, nullptr, 0, const_cast<PUCHAR>(data), static_cast<ULONG>(size),
                      out, 32) == 0;
}

bool Sha256Stream(HANDLE file, uint64_t limit, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = ShaProvider();
    if (!alg) return false;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) != 0) return false;

    LARGE_INTEGER zero{};
    SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
    std::vector<uint8_t> buf(1u << 20);
    uint64_t done = 0;
    bool ok = true;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(file, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) { ok = false; break; }
        if (got == 0) break;
        if (BCryptHashData(h, buf.data(), got, 0) != 0) { ok = false; break; }
        done += got;
        if (done > limit) { ok = false; break; }
    }
    if (ok) ok = BCryptFinishHash(h, out, 32, 0) == 0;
    BCryptDestroyHash(h);
    return ok;
}

// ─── Улики по одному буферу ───

struct Evidence {
    std::vector<Finding> hash;      // совпадения с базой
    std::vector<Finding> yara;      // с оценкой силы в score
    std::vector<Classify::Strength> strength;
    bool eicar = false;
    ScriptHeuristics::Result script;   // только для сценариев
};

MalwareClass ClassFromScript(const std::vector<std::string>& rules) {
    auto has = [&](const char* r) { return std::find(rules.begin(), rules.end(), r) != rules.end(); };
    if (has("script.miner")) return MalwareClass::Miner;
    if (has("script.keylogger")) return MalwareClass::Keylogger;
    if (has("script.browser-passwords") || has("script.browser-cookies")) return MalwareClass::Stealer;
    if (has("script.delete-backups")) return MalwareClass::Ransomware;
    if (has("script.download-exec") || has("script.lolbin-download")) return MalwareClass::Loader;
    return MalwareClass::Suspicious;
}

void CollectFromHash(const std::string& sha, const std::string& inner, Evidence& ev) {
    for (const char* e : kEicarSha256) {
        if (sha == e) { ev.eicar = true; return; }
    }
    const HashDatabase::Match m = HashDatabase::Get().Lookup(sha);
    if (m.found) {
        Finding f;
        f.source = "hash";
        f.name   = m.family;
        f.detail = sha;
        f.score  = 100;
        f.inner  = inner;
        ev.hash.push_back(std::move(f));
    }
}

void CollectFromYara(const std::vector<YaraEngine::Hit>& hits, const std::string& inner,
                     Evidence& ev)
{
    for (const auto& h : hits) {
        Finding f;
        f.source = "yara";
        f.name   = h.rule;
        f.detail = h.description;
        f.score  = h.score;
        f.inner  = inner;
        ev.yara.push_back(std::move(f));
        ev.strength.push_back(Classify::RuleStrength(h.rule, h.score));
    }
}

bool LooksExecutableOrScript(const Unpack::Item& item) {
    if (item.data.size() >= 2 && item.data[0] == 'M' && item.data[1] == 'Z') return true;
    std::wstring name(item.name.begin(), item.name.end());
    return IsCandidateByName(FileNameOf(name));
}

void ScanBuffer(const uint8_t* data, size_t size, const std::string& inner, int depth,
                const Options& opt, Evidence& ev, std::string* container, size_t& budget)
{
    uint8_t digest[32];
    if (Sha256(data, size, digest)) CollectFromHash(ToHex(digest, 32), inner, ev);

    if (opt.useYara) CollectFromYara(YaraEngine::Get().Scan(data, size), inner, ev);

    if (!opt.unpack || depth >= 2 || budget == 0) return;

    Unpack::Limits lim;
    lim.maxTotalSize = std::min(lim.maxTotalSize, budget);
    const Unpack::Result sub = Unpack::Extract(data, size, lim);
    if (sub.container.empty()) return;
    if (container && container->empty()) *container = sub.container;

    for (const Unpack::Item& item : sub.items) {
        if (budget < item.data.size()) break;
        budget -= item.data.size();
        // Из ZIP проверяем то, что может выполниться; из PyInstaller —
        // всё: там только код программы.
        if (sub.container == "zip" && !LooksExecutableOrScript(item) &&
            !(item.data.size() >= 2 && item.data[0] == 'P' && item.data[1] == 'K'))
            continue;
        const std::string name = inner.empty() ? item.name : inner + " > " + item.name;
        ScanBuffer(item.data.data(), item.data.size(), name, depth + 1, opt, ev, nullptr, budget);
    }
}

// ─── Решение ───

int SeverityFor(Classify::Strength s) {
    switch (s) {
    case Classify::Strength::Strong: return 4;
    case Classify::Strength::Normal: return 3;
    case Classify::Strength::Weak:   return 3;
    default:                         return 1;
    }
}

void Decide(Evidence& ev, const std::wstring& path, const Options& opt, Verdict& v) {
    const bool anything = ev.eicar || !ev.hash.empty() || !ev.yara.empty() ||
                          ev.script.score >= ScriptHeuristics::kSuspicious;
    std::string deceptiveWhy;
    const bool deceptive = IsDeceptiveName(FileNameOf(path), &deceptiveWhy);
    if (!anything && !deceptive) return;

    // Подпись проверяем только когда есть что проверять: это самая
    // дорогая операция, а на чистых файлах она не нужна.
    const TrustVerifier::Result trust = TrustVerifier::Check(path);
    v.signedValid   = trust.signedValid;
    v.trustedVendor = trust.trustedVendor;
    v.signer        = trust.publisher;

    if (ev.eicar) {
        Finding f; f.source = "test"; f.name = "EICAR"; f.score = 100;
        v.findings.push_back(f);
        v.level = Verdict::Malicious;
        v.severity = 2;
        v.cls = MalwareClass::TestFile;
        v.family = "EICAR";
        return;
    }

    // База хэшей: совпадение без названия семейства на подписанном файле
    // не принимаем — в выгрузку изредка попадают легитимные программы.
    for (Finding& f : ev.hash) {
        if (f.name.empty() && trust.signedValid) { v.dismissed.push_back(f); continue; }
        v.findings.push_back(f);
    }

    // YARA: у подписанного файла остаются только правила с оценкой от 90,
    // у файла крупного вендора — ни одного.
    int strong = 0, normal = 0, weak = 0, indicators = 0;
    const Finding* best = nullptr;
    Classify::Strength bestStrength = Classify::Strength::Indicator;
    bool hackTool = false;

    for (size_t i = 0; i < ev.yara.size(); ++i) {
        const Finding& f = ev.yara[i];
        const Classify::Strength s = ev.strength[i];
        bool keep = true;
        if (trust.trustedVendor) keep = false;
        else if (trust.signedValid) keep = f.score >= 90 && s >= Classify::Strength::Normal;
        if (!keep) { v.dismissed.push_back(f); continue; }

        switch (s) {
        case Classify::Strength::Strong: ++strong; break;
        case Classify::Strength::Normal: ++normal; break;
        case Classify::Strength::Weak:   ++weak; break;
        default:
            ++indicators;
            if (Classify::FromName(f.name) == MalwareClass::HackTool) hackTool = true;
            break;
        }
        if (!best || s > bestStrength || (s == bestStrength && f.score > best->score)) {
            best = &f;
            bestStrength = s;
        }
    }

    const bool hashHit = !v.findings.empty();
    const bool yaraMalicious = strong + normal > 0 || weak >= 2 || (weak >= 1 && indicators >= 1);

    if (hashHit || yaraMalicious) {
        v.level = Verdict::Malicious;
        // Семейство и тип: база хэшей точнее, её название приоритетнее.
        std::string familySource;
        if (hashHit && !v.findings.front().name.empty()) {
            v.family = v.findings.front().name;
            familySource = v.family;
            v.severity = 4;
        } else if (hashHit) {
            v.severity = 3;
        }
        if (best) {
            if (v.family.empty()) v.family = Classify::FamilyFromRule(best->name);
            if (familySource.empty()) familySource = best->name;
            v.severity = std::max(v.severity, SeverityFor(bestStrength));
        }
        v.cls = Classify::FromName(familySource);
        if (v.cls == MalwareClass::Suspicious) v.cls = MalwareClass::Generic;

        for (size_t i = 0; i < ev.yara.size(); ++i) {
            const Finding& f = ev.yara[i];
            const bool dismissedAlready = std::any_of(v.dismissed.begin(), v.dismissed.end(),
                [&](const Finding& d) { return d.name == f.name && d.inner == f.inner; });
            if (!dismissedAlready) v.findings.push_back(f);
        }
        // Подписанный, но не крупным вендором файл с сильным совпадением —
        // всё ещё находка, но на ступень мягче.
        if (trust.signedValid && !hashHit) v.severity = std::max(2, v.severity - 1);
        return;
    }

    // Отдельные индикаторы в находку не превращаются — только в журнал.
    for (size_t i = 0; i < ev.yara.size(); ++i) {
        const Finding& f = ev.yara[i];
        const bool dismissedAlready = std::any_of(v.dismissed.begin(), v.dismissed.end(),
            [&](const Finding& d) { return d.name == f.name && d.inner == f.inner; });
        if (!dismissedAlready) v.dismissed.push_back(f);
    }

    // Сценарий без сигнатур, но с набором опасных намерений.
    if (ev.script.score >= ScriptHeuristics::kSuspicious && !trust.signedValid) {
        std::string codes;
        for (const std::string& r : ev.script.rules) codes += (codes.empty() ? "" : ",") + r;
        Finding f; f.source = "heur"; f.name = "script"; f.detail = codes; f.score = ev.script.score;
        v.findings.push_back(f);
        const bool malicious = ev.script.score >= ScriptHeuristics::kMalicious;
        v.level = malicious ? Verdict::Malicious : Verdict::Suspicious;
        v.severity = malicious ? 3 : 2;
        v.cls = ClassFromScript(ev.script.rules);
        return;
    }

    if (deceptive && !trust.signedValid) {
        Finding f; f.source = "heur"; f.name = "deceptive-name"; f.detail = deceptiveWhy; f.score = 60;
        v.findings.push_back(f);
        v.level = Verdict::Suspicious;
        v.severity = 2;
        v.cls = MalwareClass::Deceptive;
        return;
    }

    if (hackTool && opt.reportPua && !trust.signedValid) {
        for (auto it = v.dismissed.begin(); it != v.dismissed.end();) {
            if (Classify::FromName(it->name) == MalwareClass::HackTool) {
                v.findings.push_back(*it);
                it = v.dismissed.erase(it);
            } else {
                ++it;
            }
        }
        v.level = Verdict::Suspicious;
        v.severity = 1;
        v.cls = MalwareClass::HackTool;
    }
}

// ─── Кэш вердиктов в пределах одной проверки ───

struct CacheKey {
    std::wstring path;
    uint64_t     size;
    uint64_t     written;
    bool operator==(const CacheKey& o) const {
        return size == o.size && written == o.written && path == o.path;
    }
};
struct CacheHash {
    size_t operator()(const CacheKey& k) const {
        return std::hash<std::wstring>()(k.path) ^ (k.size * 1099511628211ull) ^ k.written;
    }
};

std::mutex g_cacheLock;
std::unordered_map<CacheKey, Verdict, CacheHash> g_cache;

} // namespace

void ResetCache() {
    std::lock_guard<std::mutex> lock(g_cacheLock);
    g_cache.clear();
}

bool IsCandidateByName(const std::wstring& fileName) {
    static const std::unordered_set<std::wstring> kExt = {
        L".exe", L".dll", L".sys", L".scr", L".com", L".pif", L".cpl", L".ocx", L".drv",
        L".efi", L".msi", L".msp", L".mst", L".jar", L".js", L".jse", L".vbs", L".vbe",
        L".wsf", L".wsh", L".hta", L".ps1", L".psm1", L".psd1", L".bat", L".cmd", L".lnk",
        L".py", L".pyw", L".pyc", L".zip", L".docm", L".xlsm", L".pptm", L".doc", L".xls",
        L".ppt", L".rtf", L".one", L".chm", L".reg", L".url", L".xll", L".appx",
        L".msix", L".scf", L".inf",
    };
    return kExt.count(ExtOf(fileName)) > 0;
}

bool IsCandidateByMagic(const uint8_t* h, size_t n) {
    if (n >= 2 && h[0] == 'M' && h[1] == 'Z') return true;                       // PE
    if (n >= 4 && h[0] == 'P' && h[1] == 'K' && h[2] == 3 && h[3] == 4) return true;  // ZIP
    if (n >= 4 && h[0] == 0xD0 && h[1] == 0xCF && h[2] == 0x11 && h[3] == 0xE0) return true; // OLE
    if (n >= 4 && h[0] == 0x4C && h[1] == 0 && h[2] == 0 && h[3] == 0) return true; // LNK
    return false;
}

bool IsDeceptiveName(const std::wstring& fileName, std::string* why) {
    static const std::unordered_set<std::wstring> kExec = {
        L".exe", L".scr", L".com", L".pif", L".bat", L".cmd", L".vbs", L".js", L".hta",
        L".lnk", L".cpl", L".jse", L".vbe", L".wsf", L".ps1",
    };
    static const std::unordered_set<std::wstring> kDoc = {
        L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".txt",
        L".jpg", L".jpeg", L".png", L".gif", L".mp3", L".mp4", L".avi", L".rtf", L".zip",
        L".rar", L".odt", L".csv", L".html",
    };

    // Символ смены направления текста: «invoice[U+202E]fdp.exe» показывается
    // проводником как «invoiceexe.pdf».
    if (fileName.find(static_cast<wchar_t>(0x202E)) != std::wstring::npos) {
        if (why) *why = "rtlo";
        return true;
    }

    const std::wstring ext = ExtOf(fileName);
    if (!kExec.count(ext)) return false;

    const std::wstring stem = fileName.substr(0, fileName.size() - ext.size());
    // Вереница пробелов перед настоящим расширением прячет его за краем колонки.
    if (stem.size() >= 8 && stem.find(L"      ") != std::wstring::npos &&
        stem.find_last_not_of(L' ') + 6 < stem.size())
    {
        if (why) *why = "padding";
        return true;
    }

    std::wstring inner = ExtOf(stem);
    while (!inner.empty() && inner.back() == L' ') inner.pop_back();
    if (kDoc.count(inner)) {
        if (why) *why = "double-extension:" + Narrow(inner + ext);
        return true;
    }
    return false;
}

Verdict Analyze(const std::wstring& path, const Options& opt) {
    Verdict v;

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        v.skipped = true;
        v.skipReason = "unreadable";
        return v;
    }

    BY_HANDLE_FILE_INFORMATION info{};
    GetFileInformationByHandle(file, &info);
    const uint64_t size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    const uint64_t written = (static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
                             info.ftLastWriteTime.dwLowDateTime;
    v.size = size;

    const CacheKey key{ LowerW(path), size, written };
    {
        std::lock_guard<std::mutex> lock(g_cacheLock);
        auto it = g_cache.find(key);
        if (it != g_cache.end()) { CloseHandle(file); return it->second; }
    }

    Evidence ev;
    if (size == 0) {
        v.skipped = true;
        v.skipReason = "empty";
    } else if (size <= kInMemoryLimit) {
        // Буфер на поток переиспользуется: при обходе диска выделять
        // и освобождать по мегабайту на каждый файл — лишняя работа.
        thread_local std::vector<uint8_t> buffer;
        buffer.resize(static_cast<size_t>(size));
        DWORD got = 0;
        size_t total = 0;
        bool ok = true;
        while (total < size) {
            const DWORD want = static_cast<DWORD>(std::min<uint64_t>(size - total, 16u << 20));
            if (!ReadFile(file, buffer.data() + total, want, &got, nullptr)) { ok = false; break; }
            if (got == 0) break;
            total += got;
        }
        if (!ok || total == 0) {
            v.skipped = true;
            v.skipReason = "unreadable";
        } else {
            uint8_t digest[32];
            if (Sha256(buffer.data(), total, digest)) v.sha256 = ToHex(digest, 32);
            if (!v.sha256.empty()) CollectFromHash(v.sha256, {}, ev);
            if (opt.useYara) CollectFromYara(YaraEngine::Get().Scan(buffer.data(), total), {}, ev);
            if (ScriptHeuristics::IsScriptExtension(ExtOf(path)))
                ev.script = ScriptHeuristics::Analyze(buffer.data(), total, ExtOf(path), LowerW(path));

            if (opt.unpack) {
                size_t budget = 160u << 20;
                Unpack::Limits lim;
                const Unpack::Result sub = Unpack::Extract(buffer.data(), total, lim);
                v.container = sub.container;
                for (const Unpack::Item& item : sub.items) {
                    if (budget < item.data.size()) break;
                    budget -= item.data.size();
                    if (sub.container == "zip" && !LooksExecutableOrScript(item) &&
                        !(item.data.size() >= 2 && item.data[0] == 'P' && item.data[1] == 'K'))
                        continue;
                    ScanBuffer(item.data.data(), item.data.size(), item.name, 1, opt, ev,
                               nullptr, budget);
                }
            }
        }
        // Большой буфер не держим после крупного файла.
        if (buffer.capacity() > (16u << 20)) { buffer.clear(); buffer.shrink_to_fit(); }
    } else {
        uint8_t digest[32];
        if (size <= opt.maxHashSize && Sha256Stream(file, opt.maxHashSize, digest)) {
            v.sha256 = ToHex(digest, 32);
            CollectFromHash(v.sha256, {}, ev);
        }
        // Сигнатуры — по первым 64 МБ. Код программы в начале файла, а
        // сотни мегабайт после него — ресурсы игр или «раздувание» нулями,
        // которым вредоносы уходят от проверок с пределом по размеру.
        if (opt.useYara) {
            std::vector<uint8_t> head(kInMemoryLimit);
            LARGE_INTEGER zero{};
            SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
            size_t total = 0;
            DWORD got = 0;
            while (total < head.size() &&
                   ReadFile(file, head.data() + total,
                            static_cast<DWORD>(std::min<size_t>(head.size() - total, 16u << 20)), &got, nullptr) &&
                   got > 0)
                total += got;
            if (total > 0) CollectFromYara(YaraEngine::Get().Scan(head.data(), total), {}, ev);
        }
    }
    CloseHandle(file);

    if (!v.skipped) Decide(ev, path, opt, v);

    std::lock_guard<std::mutex> lock(g_cacheLock);
    if (g_cache.size() > 50000) g_cache.clear();
    g_cache[key] = v;
    return v;
}

} // namespace FileAnalyzer
