#include "PublisherWhitelist.h"
#include <algorithm>
#include <cwctype>

const PublisherWhitelist& PublisherWhitelist::Get() {
    static PublisherWhitelist db;
    return db;
}

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c) { return (wchar_t)std::towlower(c); });
    return s;
}

PublisherWhitelist::PublisherWhitelist() {
    // Доверенные компании. Случай не важен (toLower при сравнении).
    // Подстрочное сравнение — поэтому "Microsoft" покроет "Microsoft Corporation",
    // "Microsoft Windows", "Microsoft Visual Studio" и т.д.
    publishers_ = {
        // === Microsoft ===
        L"microsoft",
        L"windows",

        // === Крупные tech-компании ===
        L"google",
        L"apple",
        L"amazon",
        L"meta platforms",
        L"facebook",
        L"twitter",
        L"netflix",

        // === Браузеры / коммуникации ===
        L"mozilla",
        L"opera",
        L"brave software",
        L"telegram",
        L"discord",
        L"slack",
        L"zoom",
        L"skype",
        L"viber",

        // === Игровые ===
        L"valve",
        L"epic games",
        L"electronic arts",
        L"blizzard",
        L"activision",
        L"ubisoft",
        L"rockstar games",
        L"riot games",
        L"roblox",
        L"lesta",
        L"wargaming",
        L"nvidia",
        L"intel",
        L"amd",

        // === Музыка / медиа ===
        L"spotify",
        L"adobe",
        L"autodesk",

        // === Дев-тулы ===
        L"jetbrains",
        L"github",
        L"docker",
        L"python software foundation",
        L"oracle",
        L"hashicorp",

        // === Антивирусы и системные ===
        L"kaspersky",
        L"avast",
        L"avg",
        L"bitdefender",
        L"eset",
        L"mcafee",
        L"symantec",
        L"norton",

        // === Hardware ===
        L"gigabyte",
        L"asus",
        L"msi",
        L"hp inc",
        L"hewlett-packard",
        L"dell",
        L"lenovo",
        L"realtek",

        // === Прочие популярные ===
        L"vmware",
        L"oracle america",
        L"adobe inc",
        L"adobe systems",
    };
}

bool PublisherWhitelist::IsTrusted(const std::wstring& publisher) const {
    if (publisher.empty()) return false;

    std::wstring needle = ToLower(publisher);
    for (const auto& trusted : publishers_) {
        if (needle.find(trusted) != std::wstring::npos) return true;
    }
    return false;
}
