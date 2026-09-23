#pragma once

#include "BehaviorReport.h"

#include <string>
#include <vector>
#include <map>
#include <thread>
#include <atomic>
#include <Windows.h>

// Изменения в местах реестра, где закрепляются в системе.
//
// RegNotifyChangeKeyValue говорит только «под этим ключом что-то
// поменялось» — ни что именно, ни кто. Поэтому наблюдатель снимает
// слепок ключа заранее и после каждого сигнала сравнивает его с новым:
// разница и есть событие. Отсюда два следствия, о которых честно
// сказано в отчёте: автор изменения неизвестен (pid = 0), а изменение,
// сделанное и откаченное между двумя сигналами, останется невидимым.
class RegistryActivityWatcher {
public:
    struct WatchedKey {
        HKEY         root = nullptr;
        std::wstring subKey;
        std::wstring label;     // как показывать в отчёте
        bool         recursive = false;
        int          maxDepth = 1;   // глубина слепка при recursive
    };

    ~RegistryActivityWatcher();

    // Набор по умолчанию: автозапуск, Winlogon, службы, IFEO, окружение.
    static std::vector<WatchedKey> DefaultKeys();

    bool Start(const std::vector<WatchedKey>& keys, BehaviorSink sink);
    void Stop();

    // Ключи, которые реально удалось открыть на наблюдение.
    const std::vector<std::wstring>& WatchedLabels() const { return watched_; }

private:
    // «полный\путь\ключа|имя значения» → представление значения.
    using Snapshot = std::map<std::wstring, std::wstring>;

    struct Entry {
        WatchedKey  key;
        HKEY        handle = nullptr;
        HANDLE      event = nullptr;
        Snapshot    snapshot;
    };

    void Pump();
    bool Arm(Entry& entry);
    void DiffAndEmit(Entry& entry);
    void Emit(BehaviorEventType type, const std::wstring& target,
              const std::wstring& detail = {});

    std::vector<Entry> entries_;
    std::vector<std::wstring> watched_;
    HANDLE            stopEvent_ = nullptr;
    std::thread       thread_;
    std::atomic<bool> stopping_{ false };
    BehaviorSink      sink_;
};
