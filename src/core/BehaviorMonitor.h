#pragma once

#include "BehaviorReport.h"
#include "IScanModule.h"   // CancelToken

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <chrono>
#include <Windows.h>

// Наблюдение за поведением запущенной программы.
//
// ВАЖНО: изоляции здесь нет. Этот класс запускает файл там, где его
// позвали. Запускать им подозрительный образец в сеансе пользователя —
// значит заразить машину. Изоляцию даёт отдельный слой (Windows Sandbox),
// а наблюдатель одинаково работает и внутри песочницы, и на хосте, где
// его проверяют на заведомо безвредной мишени.
//
// Что видно без драйвера ядра: дерево процессов, изменения файлов и
// реестра, сетевые соединения процессов. Что не видно — перечислено в
// report.limitations и обязано доехать до интерфейса.
class BehaviorMonitor {
public:
    struct Options {
        std::wstring target;        // .exe, .bat/.cmd, .ps1, .vbs/.js
        std::wstring arguments;
        std::wstring workingDir;    // пусто — папка самого образца

        int  timeoutMs = 30000;
        bool killTreeWhenDone = true;   // снять всё дерево по окончании
        bool watchFiles = true;
        bool watchRegistry = true;
        bool watchNetwork = true;

        // Пусто — DefaultWatchedDirs(). Папка образца добавляется всегда.
        std::vector<std::wstring> watchedDirs;
    };

    static std::vector<std::wstring> DefaultWatchedDirs();

    // Блокирует вызывающий поток до конца наблюдения.
    // onEvent — живая лента для интерфейса; зовётся из потоков
    // наблюдателей, обработчик обязан быть потокобезопасным.
    // false — образец не удалось запустить (подробности в report).
    bool Run(const Options& options, CancelToken& cancel,
             BehaviorReport& report, BehaviorSink onEvent = {});

private:
    void   Emit(BehaviorEvent&& e);
    int    ElapsedMs() const;
    void   OnProcessStarted(DWORD pid, bool isRoot);
    void   OnProcessExited(DWORD pid);
    bool   IsWatchedPid(DWORD pid);

    std::chrono::steady_clock::time_point startedAt_;

    std::mutex                  mutex_;      // защищает report_ и live_
    BehaviorReport*             report_ = nullptr;
    BehaviorSink                onEvent_;
    std::map<DWORD, HANDLE>     live_;       // pid → дескриптор процесса
};
