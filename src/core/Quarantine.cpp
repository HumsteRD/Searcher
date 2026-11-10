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

// Файл переносится кусками: читать сотни мегабайт в память целиком
// незачем, а на больших файлах это ещё и было очень медленно.
constexpr size_t kChunk = 1u << 20;

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

// Идентификатор записи — только то, что выдаёт GenId: шестнадцатеричные
// цифры. Он приходит по каналу от интерфейса и подставляется в путь;
// «..\..\что-нибудь» дало бы прочитать и записать файл вне хранилища
// с правами администратора.
bool IsValidId(const std::string& id) {
    if (id.empty() || id.size() > 32) return false;
    for (char c : id) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return true;
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

std::string ReadWhole(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Скопировать src в dst, переворачивая каждый байт ключом. Возвращает
// число записанных байт или -1: частично записанный файл считается
// неудачей — по нему потом решается, можно ли удалять оригинал.
long long CopyTransformed(const fs::path& src, const fs::path& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return -1;
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out) return -1;

    std::vector<char> buf(kChunk);
    long long total = 0;
    for (;;) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        for (std::streamsize i = 0; i < got; ++i) buf[static_cast<size_t>(i)] ^= kXorKey;
        out.write(buf.data(), got);
        if (!out) return -1;
        total += got;
    }
    if (in.bad()) return -1;
    out.flush();
    out.close();
    return out.fail() ? -1 : total;
}

// Куда восстанавливать, если на прежнем месте уже лежит другой файл:
// «имя (restored).exe», «имя (restored 2).exe»… Затирать чужой файл
// содержимым из карантина нельзя.
fs::path FreeName(const fs::path& wanted) {
    std::error_code ec;
    if (!fs::exists(wanted, ec)) return wanted;
    const fs::path dir = wanted.parent_path();
    const std::wstring stem = wanted.stem().wstring();
    const std::wstring ext = wanted.extension().wstring();
    for (int i = 1; i < 1000; ++i) {
        const std::wstring suffix = i == 1 ? L" (restored)" : L" (restored " + std::to_wstring(i) + L")";
        const fs::path candidate = dir / (stem + suffix + ext);
        if (!fs::exists(candidate, ec)) return candidate;
    }
    return {};
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

std::optional<std::string> Quarantine::QuarantineFile(
    const std::wstring& filePath,
    const std::wstring& threatName,
    const std::wstring& severity)
{
    lastPendingReboot_ = false;
    std::error_code ec;
    if (!fs::is_regular_file(filePath, ec)) {
        Logger::Instance().Error("[Quarantine] file not found: " +
                                 WideToUtf8(filePath));
        return std::nullopt;
    }
    EnsureDir();

    const uint64_t origSize = fs::file_size(filePath, ec);
    if (ec) {
        Logger::Instance().Error("[Quarantine] cannot open: " + WideToUtf8(filePath));
        return std::nullopt;
    }

    const std::string id = GenId();
    auto undo = [&] {
        std::error_code e;
        fs::remove(BlobPath(id), e);
        fs::remove(MetaPath(id), e);
    };

    // Копия должна быть полной ДО удаления оригинала: при нехватке места
    // на диске прежний код удалял файл, оставив в хранилище обрезок.
    const long long written = CopyTransformed(filePath, BlobPath(id));
    if (written < 0 || static_cast<uint64_t>(written) != origSize) {
        undo();
        Logger::Instance().Error("[Quarantine] cannot copy the file into the store: " +
                                 WideToUtf8(filePath));
        return std::nullopt;
    }

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

    {
        std::ofstream meta(MetaPath(id), std::ios::binary | std::ios::trunc);
        meta << js.str();
        meta.flush();
        if (!meta) {
            undo();
            Logger::Instance().Error("[Quarantine] cannot write the record for: " +
                                     WideToUtf8(filePath));
            return std::nullopt;
        }
    }

    // Удаляем оригинал
    // Копия в хранилище без удаления оригинала — не карантин: файл
    // остался на месте и может работать. Занятый файл (запущенная
    // программа) удаляется при следующей загрузке, иначе — отказ.
    SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);   // «только чтение» мешает удалению
    fs::remove(filePath, ec);
    if (ec) {
        if (MoveFileExW(filePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            lastPendingReboot_ = true;
            Logger::Instance().Warn("[Quarantine] original is in use, removal scheduled for reboot: " +
                                    WideToUtf8(filePath));
        } else {
            undo();
            Logger::Instance().Error("[Quarantine] cannot remove the original, quarantine undone: " +
                                     WideToUtf8(filePath));
            return std::nullopt;
        }
    }

    Logger::Instance().Info("[Quarantine] quarantined: " +
                            WideToUtf8(filePath) + " (id=" + id + ")");
    return id;
}

bool Quarantine::Restore(const std::string& id) {
    lastRestoredPath_.clear();
    if (!IsValidId(id)) return false;
    std::error_code ec;

    // Читаем метаданные
    const std::string json = ReadWhole(MetaPath(id));
    if (json.empty()) return false;

    const std::wstring origPath = Utf8ToWide(JsonGet(json, "originalPath"));
    if (origPath.empty()) return false;
    if (!fs::exists(BlobPath(id), ec)) return false;

    // Восстанавливаем родительскую папку при необходимости
    fs::path dest(origPath);
    fs::create_directories(dest.parent_path(), ec);
    dest = FreeName(dest);
    if (dest.empty()) return false;

    // Сначала во временный файл рядом, потом переименование: оборванная
    // запись не должна оставить на месте половину программы, а запись
    // в хранилище удаляется только после удачи.
    const fs::path tmp = fs::path(dest).concat(L".tsrestore");
    const uint64_t blobSize = fs::file_size(BlobPath(id), ec);
    const long long written = CopyTransformed(BlobPath(id), tmp);   // XOR обратим тем же ключом
    if (written < 0 || static_cast<uint64_t>(written) != blobSize) {
        fs::remove(tmp, ec);
        Logger::Instance().Error("[Quarantine] restore: cannot write " + WideToUtf8(dest.wstring()));
        return false;
    }
    fs::rename(tmp, dest, ec);
    if (ec) {
        fs::remove(tmp, ec);
        Logger::Instance().Error("[Quarantine] restore: cannot write " + WideToUtf8(dest.wstring()));
        return false;
    }

    // Чистим карантин
    fs::remove(BlobPath(id), ec);
    fs::remove(MetaPath(id), ec);

    lastRestoredPath_ = dest.wstring();
    Logger::Instance().Info("[Quarantine] restored id=" + id + " to " +
                            WideToUtf8(dest.wstring()));
    return true;
}

bool Quarantine::DeletePermanently(const std::string& id) {
    if (!IsValidId(id)) return false;
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

        const std::string json = ReadWhole(p);
        if (json.empty()) continue;

        QuarantineItem qi;
        qi.id           = JsonGet(json, "id");
        qi.originalPath = Utf8ToWide(JsonGet(json, "originalPath"));
        qi.originalName = Utf8ToWide(JsonGet(json, "originalName"));
        qi.threatName   = Utf8ToWide(JsonGet(json, "threatName"));
        qi.severity     = Utf8ToWide(JsonGet(json, "severity"));
        qi.quarantinedAt= JsonGet(json, "quarantinedAt");
        try { qi.size = std::stoull(JsonGet(json, "size")); } catch (...) {}

        // Запись, у которой имя файла не совпадает с идентификатором
        // внутри, создана не нами — действия над ней всё равно отклонятся.
        if (IsValidId(qi.id) && p.stem().string() == qi.id) items.push_back(std::move(qi));
    }

    return items;
}

size_t Quarantine::Count() const {
    size_t n = 0;
    std::error_code ec;
    for (auto it = fs::directory_iterator(dir_, ec);
         !ec && it != fs::directory_iterator(); it.increment(ec))
    {
        if (it->path().extension() == L".json") ++n;
    }
    return n;
}
