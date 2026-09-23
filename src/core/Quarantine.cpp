#include "Quarantine.h"
#include "Logger.h"

#include <Windows.h>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <ctime>

namespace fs = std::filesystem;

namespace {

constexpr char kXorKey = (char)0xA7;

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                                nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(),
                        out.data(), n);
    return out;
}

std::string NowIso() {
    auto t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return os.str();
}

std::string GenId() {
    static std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream os;
    os << std::hex << dist(rng);
    return os.str();
}

// Простейший JSON-эскейп для строк
std::string JsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;       break;
        }
    }
    return out;
}

// Очень простой парсер значения по ключу из плоского JSON
std::string JsonGet(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t k = json.find(pat);
    if (k == std::string::npos) return {};
    size_t colon = json.find(':', k + pat.size());
    if (colon == std::string::npos) return {};

    size_t i = colon + 1;
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;

    if (i < json.size() && json[i] == '"') {
        // строка
        ++i;
        std::string out;
        while (i < json.size() && json[i] != '"') {
            if (json[i] == '\\' && i + 1 < json.size()) {
                ++i;
                switch (json[i]) {
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    default:  out += json[i]; break;
                }
            } else {
                out += json[i];
            }
            ++i;
        }
        return out;
    } else {
        // число
        std::string out;
        while (i < json.size() && json[i] != ',' && json[i] != '}' &&
               json[i] != '\n' && json[i] != ' ') {
            out += json[i++];
        }
        return out;
    }
}

} // namespace

Quarantine& Quarantine::Instance() {
    static Quarantine q;
    return q;
}

Quarantine::Quarantine() {
    wchar_t programData[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        dir_ = fs::path(L"C:\\ProgramData") / L"ThreatScanner" / L"Quarantine";
    } else {
        dir_ = fs::path(programData) / L"ThreatScanner" / L"Quarantine";
    }
    EnsureDir();
}

void Quarantine::EnsureDir() {
    std::error_code ec;
    fs::create_directories(dir_, ec);
    if (ec) {
        Logger::Instance().Error("[Quarantine] cannot create dir: " +
                                 WideToUtf8(dir_.wstring()));
    }
}

fs::path Quarantine::MetaPath(const std::string& id) const {
    return dir_ / (id + ".json");
}

fs::path Quarantine::BlobPath(const std::string& id) const {
    return dir_ / (id + ".q");
}

void Quarantine::XorTransform(std::vector<char>& data) {
    for (auto& b : data) b ^= kXorKey;
}

std::optional<std::string> Quarantine::QuarantineFile(
    const std::wstring& filePath,
    const std::wstring& threatName,
    const std::wstring& severity)
{
    std::error_code ec;
    if (!fs::exists(filePath, ec)) {
        Logger::Instance().Error("[Quarantine] file not found: " +
                                 WideToUtf8(filePath));
        return std::nullopt;
    }

    // Читаем файл
    std::ifstream in(filePath, std::ios::binary);
    if (!in) {
        Logger::Instance().Error("[Quarantine] cannot open: " +
                                 WideToUtf8(filePath));
        return std::nullopt;
    }
    std::vector<char> data((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
    in.close();

    uint64_t origSize = data.size();

    // Обфусцируем
    XorTransform(data);

    // Пишем blob
    std::string id = GenId();
    std::ofstream out(BlobPath(id), std::ios::binary);
    if (!out) {
        Logger::Instance().Error("[Quarantine] cannot write blob");
        return std::nullopt;
    }
    out.write(data.data(), (std::streamsize)data.size());
    out.close();

    // Пишем метаданные
    fs::path orig(filePath);
    std::ostringstream js;
    js << "{\n"
       << "  \"id\": \""          << JsonEscape(id) << "\",\n"
       << "  \"originalPath\": \""<< JsonEscape(WideToUtf8(filePath)) << "\",\n"
       << "  \"originalName\": \""<< JsonEscape(WideToUtf8(orig.filename().wstring())) << "\",\n"
       << "  \"threatName\": \""  << JsonEscape(WideToUtf8(threatName)) << "\",\n"
       << "  \"severity\": \""    << JsonEscape(WideToUtf8(severity)) << "\",\n"
       << "  \"quarantinedAt\": \""<< JsonEscape(NowIso()) << "\",\n"
       << "  \"size\": "          << origSize << "\n"
       << "}\n";

    std::ofstream meta(MetaPath(id), std::ios::binary);
    meta << js.str();
    meta.close();

    // Удаляем оригинал
    fs::remove(filePath, ec);
    if (ec) {
        Logger::Instance().Warn("[Quarantine] quarantined but couldn't remove original: " +
                                WideToUtf8(filePath));
    }

    Logger::Instance().Info("[Quarantine] quarantined: " +
                            WideToUtf8(filePath) + " (id=" + id + ")");
    return id;
}

bool Quarantine::Restore(const std::string& id) {
    std::error_code ec;

    // Читаем метаданные
    std::ifstream meta(MetaPath(id), std::ios::binary);
    if (!meta) return false;
    std::string json((std::istreambuf_iterator<char>(meta)),
                      std::istreambuf_iterator<char>());
    meta.close();

    std::wstring origPath = Utf8ToWide(JsonGet(json, "originalPath"));
    if (origPath.empty()) return false;

    // Читаем blob, расшифровываем
    std::ifstream blob(BlobPath(id), std::ios::binary);
    if (!blob) return false;
    std::vector<char> data((std::istreambuf_iterator<char>(blob)),
                            std::istreambuf_iterator<char>());
    blob.close();
    XorTransform(data);

    // Восстанавливаем родительскую папку при необходимости
    fs::path dest(origPath);
    fs::create_directories(dest.parent_path(), ec);

    std::ofstream out(dest, std::ios::binary);
    if (!out) {
        Logger::Instance().Error("[Quarantine] restore: cannot write " +
                                 WideToUtf8(origPath));
        return false;
    }
    out.write(data.data(), (std::streamsize)data.size());
    out.close();

    // Чистим карантин
    fs::remove(BlobPath(id), ec);
    fs::remove(MetaPath(id), ec);

    Logger::Instance().Info("[Quarantine] restored id=" + id + " to " +
                            WideToUtf8(origPath));
    return true;
}

bool Quarantine::DeletePermanently(const std::string& id) {
    std::error_code ec;
    bool ok1 = fs::remove(BlobPath(id), ec);
    bool ok2 = fs::remove(MetaPath(id), ec);
    Logger::Instance().Info("[Quarantine] deleted id=" + id);
    return ok1 || ok2;
}

std::vector<QuarantineItem> Quarantine::List() const {
    std::vector<QuarantineItem> items;
    std::error_code ec;

    if (!fs::exists(dir_, ec)) return items;

    for (auto it = fs::directory_iterator(dir_, ec);
         !ec && it != fs::directory_iterator(); it.increment(ec))
    {
        const auto& p = it->path();
        if (p.extension() != L".json") continue;

        std::ifstream meta(p, std::ios::binary);
        if (!meta) continue;
        std::string json((std::istreambuf_iterator<char>(meta)),
                          std::istreambuf_iterator<char>());
        meta.close();

        QuarantineItem qi;
        qi.id           = JsonGet(json, "id");
        qi.originalPath = Utf8ToWide(JsonGet(json, "originalPath"));
        qi.originalName = Utf8ToWide(JsonGet(json, "originalName"));
        qi.threatName   = Utf8ToWide(JsonGet(json, "threatName"));
        qi.severity     = Utf8ToWide(JsonGet(json, "severity"));
        qi.quarantinedAt= JsonGet(json, "quarantinedAt");
        try { qi.size = std::stoull(JsonGet(json, "size")); } catch (...) {}

        if (!qi.id.empty()) items.push_back(std::move(qi));
    }

    return items;
}
