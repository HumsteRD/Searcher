#include "SignatureStore.h"
#include "HashDatabase.h"

#include <Windows.h>
#include <ShlObj.h>

#include <fstream>
#include <regex>
#include <string>

namespace fs = std::filesystem;

namespace SignatureStore {

fs::path InstallDir() {
    wchar_t buf[MAX_PATH * 2] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0) return {};
    return fs::path(std::wstring(buf, n)).parent_path() / L"signatures";
}

fs::path UpdateDir() {
    PWSTR programData = nullptr;
    fs::path dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &programData))) {
        dir = fs::path(programData) / L"ThreatScanner" / L"signatures";
    }
    if (programData) CoTaskMemFree(programData);
    if (!dir.empty()) {
        std::error_code ec;
        fs::create_directories(dir, ec);
    }
    return dir;
}

std::vector<fs::path> HashDatabaseFiles() {
    std::vector<fs::path> out;
    std::error_code ec;

    // Полная база: из установки или скачанная, какая новее.
    const fs::path installed = InstallDir() / L"base.tsdb";
    const fs::path updated   = UpdateDir() / L"base.tsdb";
    uint32_t si = 0, su = 0;
    const bool hasInstalled = fs::exists(installed, ec) && HashDatabase::Validate(installed, &si);
    const bool hasUpdated   = fs::exists(updated, ec) && HashDatabase::Validate(updated, &su);
    if (hasUpdated && (!hasInstalled || su >= si)) out.push_back(updated);
    else if (hasInstalled) out.push_back(installed);

    // Свежие записи за последние дни — отдельным файлом поверх полной.
    const fs::path recent = UpdateDir() / L"recent.tsdb";
    if (fs::exists(recent, ec)) out.push_back(recent);
    return out;
}

uint32_t RulesStamp(const fs::path& file) {
    // Пакеты YARA-Forge начинаются с комментария, где записана дата
    // сборки: " * Creation Date: 2026-09-20". Её и берём как метку.
    std::ifstream in(file);
    std::string line;
    static const std::regex stampRe(R"(Creation Date:\s*(\d{4})-(\d{2})-(\d{2}))",
                                    std::regex::icase);
    for (int i = 0; i < 40 && std::getline(in, line); ++i) {
        std::smatch m;
        if (std::regex_search(line, m, stampRe)) {
            return static_cast<uint32_t>(std::stoul(m[1].str() + m[2].str() + m[3].str()));
        }
    }
    return 0;
}

fs::path RulesFile(const std::string& set) {
    const std::wstring name = set == "extended" ? L"rules-extended.yar" : L"rules-core.yar";
    std::error_code ec;
    const fs::path installed = InstallDir() / name;
    const fs::path updated   = UpdateDir() / name;
    const bool hi = fs::exists(installed, ec);
    const bool hu = fs::exists(updated, ec);
    if (hi && hu) return RulesStamp(updated) >= RulesStamp(installed) ? updated : installed;
    if (hu) return updated;
    if (hi) return installed;
    return {};
}

Summary Describe() {
    Summary s;
    s.hashCount = HashDatabase::Get().Count();
    s.hashStamp = HashDatabase::Get().NewestStamp();
    const fs::path core = RulesFile("core");
    if (!core.empty()) s.rulesStamp = RulesStamp(core);
    return s;
}

} // namespace SignatureStore
