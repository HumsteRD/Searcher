#pragma once

#include <filesystem>
#include <optional>
#include <string>

class Hasher {
public:
    // Возвращает hex-строку SHA-256 (lowercase) либо nullopt при ошибке.
    static std::optional<std::string> Sha256File(const std::filesystem::path& path);
};
