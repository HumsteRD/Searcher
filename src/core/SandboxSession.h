#pragma once

#include "BehaviorReport.h"
#include "IScanModule.h"   // CancelToken

#include <string>
#include <functional>

// Один сеанс изолированного анализа: подготовить раскладку, запустить
// Windows Sandbox, дождаться отчёта, разобрать его и убрать за собой.
//
// Заголовок намеренно без Qt — его включают страницы и ядро; QJsonDocument
// и QStandardPaths остались в .cpp, как это уже сделано в AppSettings.
class SandboxSession {
public:
    struct Options {
        std::wstring samplePath;
        std::wstring sampleArguments;

        int  observeTimeoutMs = 30000;    // сколько наблюдать внутри
        int  waitForReportMs  = 300000;   // сколько ждать отчёт снаружи
        bool networking = false;
        int  memoryMb = 4096;
        bool closeWhenDone = true;

        // Не удалять рабочую папку после сеанса. Только для разбора
        // полётов: там лежит копия образца.
        bool keepWorkFolder = false;
    };

    enum class Result {
        Completed,
        Unavailable,        // Windows Sandbox на этой системе нет
        StagingFailed,      // не удалось подготовить раскладку
        LaunchFailed,       // не удалось запустить песочницу
        TimedOut,           // отчёт так и не появился
        ReportUnreadable,   // файл есть, но прочитать его нельзя
        Cancelled,
    };

    struct Outcome {
        Result         result = Result::Unavailable;
        std::wstring   message;      // что именно произошло
        std::wstring   howToFix;     // пусто, если исправить нельзя
        std::wstring   workFolder;
        std::wstring   wsbPath;
        BehaviorReport report;
    };

    // Стадия сеанса для интерфейса: подготовка, ожидание, разбор.
    using ProgressSink = std::function<void(const std::wstring& stage)>;

    // Блокирует вызывающий поток до конца сеанса — звать из рабочего
    // потока, не из потока интерфейса.
    Outcome Run(const Options& options, CancelToken& cancel,
                ProgressSink onProgress = {});

    // Разбор отчёта агента. Вынесено наружу, чтобы можно было открыть
    // отчёт, сохранённый в прошлый раз.
    static bool ReadReportJson(const std::wstring& path, BehaviorReport& out,
                               std::wstring* error = nullptr);
};
