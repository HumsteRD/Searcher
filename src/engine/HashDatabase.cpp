#include "HashDatabase.h"
#include "SignatureStore.h"
#include "../core/Logger.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace fs = std::filesystem;

namespace {

constexpr char kMagic[8] = { 'T', 'S', 'H', 'D', 'B', 0, 0, 1 };

int HexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool KeyFromHex(const std::string& hex, uint64_t& key) {
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

bool HashDatabase::Validate(const fs::path& file, uint32_t* stamp, uint32_t* count) {
    Table t;
    if (!LoadFile(file, t)) return false;
    if (stamp) *stamp = t.stamp;
    if (count) *count = static_cast<uint32_t>(t.keys.size());
    return true;
}

void HashDatabase::Reload() {
    std::vector<Table> loaded;
    for (const fs::path& file : SignatureStore::HashDatabaseFiles()) {
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
    std::lock_guard<std::mutex> lock(mutex_);
    tables_.swap(loaded);
}

HashDatabase::Match HashDatabase::Lookup(const std::string& sha256Hex) const {
    uint64_t key = 0;
    if (!KeyFromHex(sha256Hex, key)) return {};

    std::lock_guard<std::mutex> lock(mutex_);
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
    std::lock_guard<std::mutex> lock(mutex_);
    size_t n = 0;
    for (const Table& t : tables_) n += t.keys.size();
    return n;
}

uint32_t HashDatabase::NewestStamp() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t s = 0;
    for (const Table& t : tables_) s = std::max(s, t.stamp);
    return s;
}
