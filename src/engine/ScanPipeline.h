#pragma once

#include "FileAnalyzer.h"
#include "FileWalker.h"
#include "Verdict.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// Проверка множества файлов: один поток обходит диски, несколько
// потоков проверяют найденное. Обход и проверка идут одновременно —
// первые находки появляются сразу, а не после подсчёта всего диска.
class ScanPipeline {
public:
    struct Progress {
        uint64_t filesSeen = 0;        // всего файлов при обходе
        uint64_t candidates = 0;       // отобрано на проверку
        uint64_t checked = 0;          // проверено
        uint64_t failed = 0;           // не удалось разобрать (сбой на файле)
        uint64_t bytesTotal = 0;       // объём отобранного
        uint64_t bytesDone = 0;
        bool     walkFinished = false; // обход закончен, объём известен
        int      percent = 0;          // честный процент, пока обход идёт — 0
        std::wstring current;          // что проверяется сейчас
    };

    struct Config {
        std::vector<FileWalker::Root> roots;
        std::vector<std::wstring>     excludes;
        FileAnalyzer::Options         analyzer;
        int                           threads = 0;   // 0 — по числу ядер
        // Пока здесь true, новые файлы не берутся в работу (пауза).
        const std::atomic<bool>*      pause = nullptr;
    };

    using VerdictSink = std::function<void(const std::wstring& path, const Verdict& v)>;

    // Блокирующий запуск. onVerdict зовётся из рабочих потоков, только для
    // находок (Suspicious и Malicious). cancel проверяется постоянно.
    static void Run(const Config& config, const std::atomic<bool>& cancel,
                    const VerdictSink& onVerdict,
                    const std::function<void(const Progress&)>& onProgress);
};
