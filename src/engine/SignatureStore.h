#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// Где лежат базы сигнатур.
//
// Два места: каталог установки (`<папка программы>\signatures`) — то, что
// приехало с установщиком, и каталог обновлений
// (`%ProgramData%\ThreatScanner\signatures`) — то, что скачано позже.
// Из двух копий одного файла берётся более свежая по метке времени.
namespace SignatureStore {

std::filesystem::path InstallDir();
std::filesystem::path UpdateDir();      // создаётся при первом обращении

// Файлы баз хэшей в порядке поиска.
std::vector<std::filesystem::path> HashDatabaseFiles();

// Файл правил YARA: "core" или "extended". Пусто, если нет ни одной копии.
std::filesystem::path RulesFile(const std::string& set);

// Метка набора правил (yyyymmdd) из заголовка файла, 0 — нет метки.
uint32_t RulesStamp(const std::filesystem::path& file);

// Сводка для интерфейса.
struct Summary {
    uint64_t hashCount = 0;
    uint32_t hashStamp = 0;
    uint32_t rulesStamp = 0;
    int      coreRules = 0;
    int      extendedRules = 0;
};
Summary Describe();

} // namespace SignatureStore
