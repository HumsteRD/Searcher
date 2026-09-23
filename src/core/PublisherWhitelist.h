#pragma once

#include <string>
#include <vector>

// Whitelist издателей, которым мы доверяем.
class PublisherWhitelist {
public:
    static const PublisherWhitelist& Get();

    // Сравнение case-insensitive, по подстроке.
    bool IsTrusted(const std::wstring& publisher) const;

private:
    PublisherWhitelist();
    std::vector<std::wstring> publishers_;
};
