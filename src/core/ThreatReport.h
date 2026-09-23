#pragma once

#include <string>
#include <chrono>
#include <Windows.h>

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

enum class ThreatCategory {
    AutoStart,
    ScheduledTask,
    SuspiciousFile,
    HiddenProcess,
    MemoryAnomaly,
    NetworkBeacon,
    KnownMiner,
    KnownStealer,
    Other
};

enum class ThreatKind {
    File,
    RegistryValue,
    ScheduledTask,
    Process
};

enum class ThreatStatus {
    Pending,
    Ignored,
    Quarantined,
    Deleted,
    Restored,
    Failed
};

struct Threat {
    Severity        severity = Severity::Info;
    ThreatCategory  category = ThreatCategory::Other;
    ThreatKind      kind = ThreatKind::File;
    ThreatStatus    status = ThreatStatus::Pending;

    std::string     id;
    std::wstring    name;
    std::wstring    source;
    std::wstring    description;
    std::wstring    evidence;
    std::wstring    suggestion;
    std::wstring    actionMessage;

    std::chrono::system_clock::time_point detected
        = std::chrono::system_clock::now();

    std::wstring    filePath;
    DWORD           pid = 0;

    HKEY            regRoot = nullptr;
    std::wstring    regSubKey;
    std::wstring    regValueName;

    std::wstring    taskFullPath;
};

class IReportSink {
public:
    virtual ~IReportSink() = default;
    virtual void Report(const Threat& threat) = 0;

    // percent — прогресс ВНУТРИ текущего модуля, 0..100.
    // Scanner сам пересчитывает его в общий прогресс сканирования.
    virtual void Progress(const std::string& stage, int percent) = 0;

    // Текущий проверяемый объект. Модули зовут это на каждый файл, процесс,
    // ключ реестра — отсюда берётся счётчик проверенного и строка под
    // прогресс-баром, чтобы было видно, что работа идёт.
    virtual void Item(const std::wstring& /*path*/) {}
};