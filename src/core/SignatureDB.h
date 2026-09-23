#pragma once

#include <string>
#include <vector>
#include <regex>
#include <unordered_set>

// База подозрительных паттернов и хэшей.
// Используется файловым сканером и потом сетевым.
class SignatureDB {
public:
    // Не const: база пополняется из внешнего файла и может быть перечитана
    // без пересборки приложения.
    static SignatureDB& Get();

    // Перечитать внешний файл сигнатур поверх встроенных.
    void Reload();

    // Путь к пользовательскому файлу сигнатур (может не существовать).
    static std::wstring ExternalPath();

    // Сколько записей пришло из внешнего файла — для показа в настройках.
    int ExternalHashCount() const    { return extHashes_; }
    int ExternalPatternCount() const { return extPatterns_; }
    int ExternalPoolCount() const    { return extPools_; }

    // === Файловые сигнатуры ===
    bool IsSuspiciousFileName(const std::wstring& name) const;
    bool IsSuspiciousPath(const std::wstring& path) const;
    bool IsKnownMaliciousHash(const std::string& sha256_lower) const;

    // === Сетевые (на будущее, для NetworkScanner) ===
    bool IsKnownMiningPool(const std::string& hostOrIp) const;

    // Список горячих директорий для обхода файловым сканером
    const std::vector<std::wstring>& HotDirectories() const { return hotDirs_; }

private:
    SignatureDB();
    void LoadBuiltin();
    void LoadExternal();

    int extHashes_ = 0;
    int extPatterns_ = 0;
    int extPools_ = 0;

    std::vector<std::wregex>        fileNameRegex_;
    std::vector<std::wregex>        pathRegex_;
    std::unordered_set<std::string> knownHashes_;
    std::unordered_set<std::string> miningPools_;
    std::vector<std::wstring>       hotDirs_;
};
