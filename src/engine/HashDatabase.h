#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <filesystem>

// База хэшей известных вредоносных файлов.
//
// Источник — выгрузка MalwareBazaar (abuse.ch, CC0), собранная скриптом
// tools/sigdb/build_sigdb.py. Хранятся первые 8 байт SHA-256: вероятность
// случайного совпадения чистого файла с миллионом записей ~1e-13, а база
// в четыре раза меньше полной.
//
// Файлов может быть несколько: базовый из установки и обновления поверх
// него. Поиск идёт по всем, семейство берётся из первого совпадения.
class HashDatabase {
public:
    static HashDatabase& Get();

    struct Match {
        bool        found = false;
        std::string family;   // пусто, если семейство не определено
    };

    // sha256 — 64 hex-символа в любом регистре.
    Match Lookup(const std::string& sha256Hex) const;
    Match Lookup(const uint8_t digest[32]) const;

    // Перечитать все файлы баз из каталогов сигнатур.
    void Reload();

    size_t   Count() const;
    uint32_t NewestStamp() const;   // yyyymmdd самой свежей базы, 0 — баз нет

    // Загрузить один файл. false — файл не читается или не того формата.
    static bool Validate(const std::filesystem::path& file, uint32_t* stamp = nullptr,
                         uint32_t* count = nullptr);

    // Записи файла базы: ключ (первые 8 байт SHA-256) и семейство.
    using Entry = std::pair<uint64_t, std::string>;
    static bool ReadEntries(const std::filesystem::path& file, std::vector<Entry>& out);
    // Записать базу. Порядок записей не важен — файл сортируется.
    static bool WriteFile(const std::filesystem::path& file, uint32_t stamp,
                          std::vector<Entry> entries);
    static bool KeyFromHex(const std::string& hex, uint64_t& key);

private:
    HashDatabase();

    struct Table {
        uint32_t                  stamp = 0;
        std::vector<uint64_t>     keys;      // по возрастанию
        std::vector<uint16_t>     family;    // индекс в names
        std::vector<std::string>  names;
    };

    static bool LoadFile(const std::filesystem::path& file, Table& out);

    mutable std::mutex   mutex_;
    std::vector<Table>   tables_;
};
