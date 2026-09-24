#pragma once

#include <Windows.h>

#include <chrono>
#include <string>
#include <vector>

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

// Что именно найдено — от этого зависит, какие действия к находке применимы.
// Значения — часть протокола помощника, новые только в конец.
enum class ThreatKind {
    File,            // файл на диске
    RegistryValue,   // запись автозапуска в реестре
    ScheduledTask,   // задача планировщика
    Process,         // запущенный процесс
    Service,         // служба Windows
    WmiConsumer,     // постоянная подписка WMI
    HostsEntry,      // строка файла hosts
};

enum class ThreatStatus {
    Pending,
    Ignored,
    Quarantined,
    Deleted,
    Restored,
    Failed,
    Disabled,        // запись автозапуска или служба отключены, файл в карантине
};

// Находка.
//
// Причины хранятся кодами (reasons), а не готовыми фразами: текст строит
// интерфейс на выбранном языке. Формат кода — "код" или "код\tаргумент\t...".
// Англоязычное описание (summary) нужно только журналу и экспорту.
struct Threat {
    Severity      severity = Severity::Info;
    ThreatKind    kind = ThreatKind::File;
    ThreatStatus  status = ThreatStatus::Pending;

    int           malwareClass = 0;   // MalwareClass из engine/Verdict.h
    std::string   family;             // «RedLineStealer», если известно

    std::wstring  name;               // короткое имя для списка
    std::wstring  source;             // полное расположение: путь, ключ, задача
    std::vector<std::string> reasons;
    std::wstring  summary;            // одна строка по-английски для журнала
    std::wstring  evidence;           // командная строка, содержимое записи

    std::string   sha256;
    std::wstring  signer;             // издатель подписи, если есть

    std::wstring  actionMessage;      // код результата действия

    std::chrono::system_clock::time_point detected = std::chrono::system_clock::now();

    // Цель действия. Для записи автозапуска, задачи и службы filePath —
    // запускаемый файл: его кладём в карантин вместе с удалением записи.
    std::wstring  filePath;
    DWORD         pid = 0;
    HKEY          regRoot = nullptr;
    std::wstring  regSubKey;
    std::wstring  regValueName;
    std::wstring  taskFullPath;
    std::wstring  serviceName;
    std::wstring  wmiConsumerPath;    // путь объекта WMI (__RELPATH)
    std::wstring  hostsLine;
};

class IReportSink {
public:
    virtual ~IReportSink() = default;
    virtual void Report(const Threat& threat) = 0;

    // percent — прогресс ВНУТРИ текущего модуля, 0..100; -1 — пока неизвестен.
    virtual void Progress(const std::string& stage, int percent) = 0;

    // Текущий проверяемый объект.
    virtual void Item(const std::wstring& /*path*/) {}

    // Сколько объектов проверено модулем с начала его работы. Модули,
    // которые проверяют параллельно, сообщают итог сами, а не по одному.
    virtual void Checked(long long /*count*/) {}
};
