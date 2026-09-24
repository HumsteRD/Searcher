#pragma once

#include <cstdint>
#include <shared_mutex>
#include <string>
#include <vector>

struct YR_RULES;

// Сигнатурный поиск по содержимому — стандартный движок YARA и набор
// правил YARA-Forge (курируемая сборка публичных правил; пакет core —
// только правила с низкой долей ложных срабатываний).
//
// Правила всегда компилируются из исходного текста. Загружать уже
// скомпилированные правила из общей папки нельзя: формат .yarc считается
// доверенным, и подложенный файл выполнил бы код в процессе с правами
// администратора.
class YaraEngine {
public:
    static YaraEngine& Get();

    struct Hit {
        std::string rule;          // идентификатор правила
        std::string description;   // meta.description, по-английски
        std::string author;
        int         score = 0;     // meta.score, 0..100
        int         quality = 0;   // meta.quality
    };

    // Скомпилировать правила, если ещё не скомпилированы или набор
    // изменился. Дорого (1–2 с), поэтому зовётся в начале проверки.
    bool Prepare(bool includeExtended, std::string* error = nullptr);

    bool Ready() const;
    int  RuleCount() const;

    // Потокобезопасно: одни и те же правила сканируют несколько потоков.
    // Если правила не готовы — пустой результат.
    std::vector<Hit> Scan(const uint8_t* data, size_t size, int timeoutSec = 15) const;

    // Для больших файлов: YARA сама отображает файл в память и сама
    // переживает его обрезку посреди чтения.
    std::vector<Hit> ScanHandle(void* fileHandle, int timeoutSec = 30) const;

    ~YaraEngine();

private:
    YaraEngine();

    mutable std::shared_mutex lock_;
    YR_RULES*    rules_ = nullptr;
    int          ruleCount_ = 0;
    std::string  fingerprint_;      // пути, размеры и даты исходников
    bool         initialized_ = false;
};
