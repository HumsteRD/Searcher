#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Тип угрозы — то, что пользователь видит первым: «похититель данных»
// понятнее, чем имя правила. Порядок значений — часть протокола
// между помощником и интерфейсом, новые добавлять только в конец.
enum class MalwareClass : int {
    Generic = 0,
    Stealer,
    Keylogger,
    Rat,
    Backdoor,
    Ransomware,
    Miner,
    Loader,
    Banker,
    Worm,
    Exploit,
    HackTool,
    Pua,
    Webshell,
    Rootkit,
    Botnet,
    TestFile,
    Deceptive,     // файл выдаёт себя за документ (двойное расширение и т.п.)
    Suspicious,
};

// Одна улика.
struct Finding {
    std::string source;   // "hash", "yara", "heur", "test"
    std::string name;     // имя правила, семейства или код эвристики
    std::string detail;   // описание правила (по-английски) или аргумент
    int         score = 0;
    std::string inner;    // имя внутри контейнера, если улика оттуда
};

struct Verdict {
    enum Level { Clean = 0, Suspicious = 1, Malicious = 2 };

    Level        level = Clean;
    int          severity = 0;          // как ::Severity: 0 Info .. 4 Critical
    MalwareClass cls = MalwareClass::Generic;
    std::string  family;                // «RedLineStealer», если известно
    std::vector<Finding> findings;      // только то, что вошло в вердикт
    std::vector<Finding> dismissed;     // отброшенное — для журнала

    std::string  sha256;
    std::wstring signer;
    bool         signedValid = false;
    bool         trustedVendor = false;
    std::string  container;             // "zip", "pyinstaller"
    uint64_t     size = 0;
    std::string  origin;                // адрес, с которого файл скачан (только у находок)

    bool         skipped = false;       // файл не проверялся
    std::string  skipReason;            // "unreadable", "empty", "error"
};
