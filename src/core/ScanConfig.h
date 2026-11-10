#pragma once

#include <mutex>
#include <string>
#include <vector>

// Что и как проверять. Приезжает в помощник вместе с командой
// start_scan и действует ровно одну проверку; служба строит её сама
// из своей конфигурации.
struct ScanConfig {
    enum class Mode { Quick = 0, Full = 1, Custom = 2 };

    // Порядок — часть протокола: интерфейс передаёт флаги модулей массивом.
    enum Module { Files = 0, Processes, Autoruns, Tasks, Services, Network, ModuleCount };

    Mode mode = Mode::Quick;
    std::vector<std::wstring> paths;           // для Custom: папки и файлы
    bool modules[ModuleCount] = { true, true, true, true, true, true };

    bool extendedRules = false;   // расширенный набор YARA-Forge
    bool reportPua = false;       // показывать хакерские инструменты и PUA
    bool unpackArchives = true;
    int  threads = 0;             // потоков на проверку файлов, 0 — по числу ядер

    std::vector<std::wstring> excludedPaths;   // пользовательские исключения
    std::vector<std::string>  allowedHashes;   // SHA-256, которым пользователь доверяет

    bool ModuleOn(Module m) const { return m >= 0 && m < ModuleCount && modules[m]; }

    bool IsAllowedHash(const std::string& sha) const;
    bool IsExcludedPath(const std::wstring& path) const;

    // Одна конфигурация на проверку: модули читают её из рабочего потока,
    // поэтому ставится она до старта и не меняется до конца.
    static void SetCurrent(const ScanConfig& config);
    static ScanConfig Current();
};
