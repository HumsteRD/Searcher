#include "HashDatabase.h"
#include "SignatureStore.h"
#include "../core/Logger.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <unordered_map>

namespace fs = std::filesystem;

namespace {

constexpr char kMagic[8] = { 'T', 'S', 'H', 'D', 'B', 0, 0, 1 };

int HexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool KeyFromHexImpl(const std::string& hex, uint64_t& key) {
    if (hex.size() < 16) return false;
    key = 0;
    for (int i = 0; i < 16; ++i) {
        const int v = HexValue(hex[i]);
        if (v < 0) return false;
        key = (key << 4) | static_cast<uint64_t>(v);
    }
    return true;
}

template <typename T>
bool ReadPod(std::ifstream& in, T& value) {
    return static_cast<bool>(in.read(reinterpret_cast<char*>(&value), sizeof(T)));
}

} // namespace

HashDatabase& HashDatabase::Get() {
    static HashDatabase db;
    return db;
}

HashDatabase::HashDatabase() {
    Reload();
}

bool HashDatabase::LoadFile(const fs::path& file, Table& out) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;

    char magic[8] = {};
    if (!in.read(magic, 8) || std::memcmp(magic, kMagic, 8) != 0) return false;

    uint32_t stamp = 0, count = 0, families = 0;
    if (!ReadPod(in, stamp) || !ReadPod(in, count) || !ReadPod(in, families))
        return false;

    // Защита от испорченного файла: больше десяти миллионов записей
    // выгрузка не содержит, а резервировать память по мусору нельзя.
    if (count > 10'000'000 || families > 65535) return false;

    out.stamp = stamp;
    out.names.resize(families);
    for (uint32_t i = 0; i < families; ++i) {
        uint8_t len = 0;
        if (!ReadPod(in, len)) return false;
        out.names[i].resize(len);
        if (len && !in.read(out.names[i].data(), len)) return false;
    }

    out.keys.resize(count);
    out.family.resize(count);
    if (count) {
        if (!in.read(reinterpret_cast<char*>(out.keys.data()), count * sizeof(uint64_t)))
            return false;
        if (!in.read(reinterpret_cast<char*>(out.family.data()), count * sizeof(uint16_t)))
            return false;
    }

    // Порядок проверяем, а не принимаем на веру: двоичный поиск по
    // неотсортированному массиву молча пропускал бы совпадения.
    if (!std::is_sorted(out.keys.begin(), out.keys.end())) {
        std::vector<size_t> order(count);
        for (size_t i = 0; i < count; ++i) order[i] = i;
        std::sort(order.begin(), order.end(),
                  [&](size_t a, size_t b) { return out.keys[a] < out.keys[b]; });
        std::vector<uint64_t> k(count);
        std::vector<uint16_t> f(count);
        for (size_t i = 0; i < count; ++i) { k[i] = out.keys[order[i]]; f[i] = out.family[order[i]]; }
        out.keys.swap(k);
        out.family.swap(f);
    }
    return true;
}

bool HashDatabase::ReadHeader(const fs::path& file, uint32_t* stamp, uint32_t* count) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;

    char magic[8] = {};
    if (!in.read(magic, 8) || std::memcmp(magic, kMagic, 8) != 0) return false;

    uint32_t s = 0, n = 0, families = 0;
    if (!ReadPod(in, s) || !ReadPod(in, n) || !ReadPod(in, families)) return false;
    if (n > 10'000'000 || families > 65535) return false;

    // Таблица имён — переменной длины; проходим её, чтобы узнать, где
    // начинаются ключи, и сверить длину файла: обрезанная при скачивании
    // база отсеивается здесь, без чтения десяти мегабайт.
    uint64_t offset = 8 + 12;
    for (uint32_t i = 0; i < families; ++i) {
        uint8_t len = 0;
        if (!ReadPod(in, len)) return false;
        if (len && !in.seekg(len, std::ios::cur)) return false;
        offset += 1 + len;
    }
    std::error_code ec;
    const uint64_t size = fs::file_size(file, ec);
    if (ec || size != offset + static_cast<uint64_t>(n) * (sizeof(uint64_t) + sizeof(uint16_t)))
        return false;

    if (stamp) *stamp = s;
    if (count) *count = n;
    return true;
}

bool HashDatabase::Validate(const fs::path& file, uint32_t* stamp, uint32_t* count) {
    Table t;
    if (!LoadFile(file, t)) return false;
    if (stamp) *stamp = t.stamp;
    if (count) *count = static_cast<uint32_t>(t.keys.size());
    return true;
}

void HashDatabase::Reload() {
    // Те же файлы, что уже в памяти, заново не читаем: Reload зовётся в
    // начале каждой проверки, а базы меняются раз в сутки. Раньше первая
    // проверка читала десять мегабайт дважды подряд.
    const std::vector<fs::path> files = SignatureStore::HashDatabaseFiles();
    std::wstring fingerprint;
    {
        std::error_code ec;
        for (const fs::path& file : files) {
            fingerprint += file.wstring() + L"|" + std::to_wstring(fs::file_size(file, ec)) + L"|" +
                           std::to_wstring(fs::last_write_time(file, ec).time_since_epoch().count()) + L";";
        }
        std::shared_lock lock(mutex_);
        if (!tables_.empty() && fingerprint == fingerprint_) return;
    }

    std::vector<Table> loaded;
    for (const fs::path& file : files) {
        Table t;
        if (LoadFile(file, t)) {
            Logger::Instance().Info("[HashDB] " + file.filename().string() + ": " +
                                    std::to_string(t.keys.size()) + " hashes, stamp " +
                                    std::to_string(t.stamp));
            loaded.push_back(std::move(t));
        } else {
            Logger::Instance().Warn("[HashDB] unreadable database skipped: " +
                                    file.filename().string());
        }
    }
    std::unique_lock lock(mutex_);
    tables_.swap(loaded);
    fingerprint_ = std::move(fingerprint);
}

HashDatabase::Match HashDatabase::Lookup(const std::string& sha256Hex) const {
    uint64_t key = 0;
    if (!KeyFromHexImpl(sha256Hex, key)) return {};

    std::shared_lock lock(mutex_);
    for (const Table& t : tables_) {
        auto it = std::lower_bound(t.keys.begin(), t.keys.end(), key);
        if (it == t.keys.end() || *it != key) continue;
        Match m;
        m.found = true;
        const size_t idx = static_cast<size_t>(it - t.keys.begin());
        const uint16_t fam = t.family[idx];
        if (fam > 0 && fam < t.names.size()) m.family = t.names[fam];
        if (m.family == "n/a") m.family.clear();
        return m;
    }
    return {};
}

HashDatabase::Match HashDatabase::Lookup(const uint8_t digest[32]) const {
    static const char hex[] = "0123456789abcdef";
    std::string s(16, '0');
    for (int i = 0; i < 8; ++i) {
        s[2 * i]     = hex[digest[i] >> 4];
        s[2 * i + 1] = hex[digest[i] & 0xF];
    }
    return Lookup(s);
}

size_t HashDatabase::Count() const {
    std::shared_lock lock(mutex_);
    size_t n = 0;
    for (const Table& t : tables_) n += t.keys.size();
    return n;
}

uint32_t HashDatabase::NewestStamp() const {
    std::shared_lock lock(mutex_);
    uint32_t s = 0;
    for (const Table& t : tables_) s = std::max(s, t.stamp);
    return s;
}

bool HashDatabase::KeyFromHex(const std::string& hex, uint64_t& key) {
    return KeyFromHexImpl(hex, key);
}

bool HashDatabase::ReadEntries(const fs::path& file, std::vector<Entry>& out) {
    Table t;
    if (!LoadFile(file, t)) return false;
    out.reserve(out.size() + t.keys.size());
    for (size_t i = 0; i < t.keys.size(); ++i) {
        const uint16_t f = t.family[i];
        out.emplace_back(t.keys[i], f < t.names.size() ? t.names[f] : std::string());
    }
    return true;
}

bool HashDatabase::WriteFile(const fs::path& file, uint32_t stamp, std::vector<Entry> entries) {
    std::sort(entries.begin(), entries.end(),
              [](const Entry& a, const Entry& b) { return a.first < b.first; });
    // Повторы ключа: оставляем запись с известным семейством.
    std::vector<Entry> unique;
    unique.reserve(entries.size());
    for (auto& e : entries) {
        if (!unique.empty() && unique.back().first == e.first) {
            if ((unique.back().second.empty() || unique.back().second == "n/a") && !e.second.empty())
                unique.back().second = e.second;
            continue;
        }
        unique.push_back(std::move(e));
    }

    std::vector<std::string> names{ "n/a" };
    std::vector<uint16_t> family(unique.size(), 0);
    std::unordered_map<std::string, uint16_t> index{ { "n/a", 0 } };
    for (size_t i = 0; i < unique.size(); ++i) {
        const std::string& n = unique[i].second.empty() ? names[0] : unique[i].second;
        auto it = index.find(n);
        if (it == index.end()) {
            if (names.size() >= 65535) continue;
            it = index.emplace(n, static_cast<uint16_t>(names.size())).first;
            names.push_back(n.substr(0, 255));
        }
        family[i] = it->second;
    }

    const fs::path tmp = fs::path(file).concat(L".tmp");
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(kMagic, 8);
        const uint32_t count = static_cast<uint32_t>(unique.size());
        const uint32_t fams = static_cast<uint32_t>(names.size());
        out.write(reinterpret_cast<const char*>(&stamp), 4);
        out.write(reinterpret_cast<const char*>(&count), 4);
        out.write(reinterpret_cast<const char*>(&fams), 4);
        for (const std::string& n : names) {
            const uint8_t len = static_cast<uint8_t>(std::min<size_t>(n.size(), 255));
            out.write(reinterpret_cast<const char*>(&len), 1);
            out.write(n.data(), len);
        }
        for (const Entry& e : unique) out.write(reinterpret_cast<const char*>(&e.first), 8);
        out.write(reinterpret_cast<const char*>(family.data()), family.size() * sizeof(uint16_t));
        if (!out) return false;
    }
    std::error_code ec;
    fs::rename(tmp, file, ec);
    if (ec) {
        fs::remove(file, ec);
        fs::rename(tmp, file, ec);
    }
    return !ec;
}
