#pragma once

#include <filesystem>
#include <optional>
#include <string>

// Проверка цифровой подписи Windows-файла (Authenticode).
// Использует WinVerifyTrust + извлечение subject name из сертификата.
struct SignatureInfo {
    bool         valid = false;   // подпись существует и валидна
    std::wstring publisher;        // CN= subject (например, "Microsoft Corporation")
};

class SignatureVerifier {
public:
    // Проверяет подпись файла. Возвращает SignatureInfo.
    // Если файл не подписан или подпись битая — valid=false, publisher="".
    static SignatureInfo Verify(const std::filesystem::path& path);
};
