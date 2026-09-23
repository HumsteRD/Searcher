#pragma once

#include <string>
#include <vector>
#include <functional>
#include <Windows.h>

// Динамический анализ: что образец делал, пока за ним наблюдали.
// Статические модули отвечают на вопрос «что это», этот — «что оно творит».

enum class BehaviorEventType {
    ProcessStarted,
    ProcessExited,

    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,

    RegistryValueSet,       // значения не было
    RegistryValueChanged,   // было, стало другим
    RegistryValueDeleted,
    RegistryKeyCreated,
    RegistryKeyDeleted,

    NetworkConnection,      // исходящее соединение
    NetworkListen,          // процесс открыл порт на приём

    // Сообщение самого наблюдателя, а не образца: потеря событий,
    // недоступный источник, таймаут. В отчёте показывать отдельно —
    // это признание границ наблюдения, а не поведение файла.
    MonitorNote,
};

struct BehaviorEvent {
    BehaviorEventType type = BehaviorEventType::MonitorNote;

    // Миллисекунды от начала наблюдения. Абсолютное время не нужно:
    // важен порядок и то, через сколько после запуска это случилось.
    int          atMs = 0;

    // 0 — источник неизвестен. Для файлов и реестра это норма, а не
    // недоработка: в пользовательском режиме автор изменения не виден.
    DWORD        pid = 0;

    std::wstring target;   // путь, «куст\ключ\значение», «адрес:порт»
    std::wstring detail;   // командная строка, «старое → новое», состояние
};

struct ObservedProcess {
    DWORD        pid = 0;
    DWORD        parentPid = 0;
    std::wstring image;
    std::wstring commandLine;   // пусто, если прочитать не удалось
    int          startedAtMs = 0;
    int          exitedAtMs = -1;   // -1 — на момент отчёта ещё работал
    DWORD        exitCode = 0;
    bool         isRoot = false;    // сам образец, а не его потомок
};

struct BehaviorReport {
    std::wstring target;
    std::wstring arguments;

    int   durationMs = 0;
    bool  timedOut = false;      // истёк лимит, процесс работал дальше
    bool  killed = false;        // дерево процессов принудительно снято
    bool  launchFailed = false;
    std::wstring failureReason;

    DWORD rootExitCode = 0;

    std::vector<ObservedProcess> processes;
    std::vector<BehaviorEvent>   events;

    // Что это наблюдение принципиально не видит. Заполняется всегда,
    // даже когда всё прошло гладко: отчёт без списка ограничений
    // читается как полный, а он не полный.
    std::vector<std::wstring>    limitations;
};

// Наблюдатели заполняют type/pid/target/detail; метку времени ставит
// BehaviorMonitor — только он знает момент старта.
using BehaviorSink = std::function<void(BehaviorEvent&&)>;

const wchar_t* BehaviorEventTypeName(BehaviorEventType type);
