#pragma once

#include <string>

// Конфигурация сеанса Windows Sandbox (.wsb).
//
// Внутри песочницы у нас три отображённые папки и ни одной лишней:
//   C:\sample  — образец, только на чтение;
//   C:\agent   — наблюдатель, только на чтение;
//   C:\report  — единственная папка с записью, через неё отчёт
//                возвращается на хост.
// Всё остальное — сеть, буфер обмена, микрофон, камера, принтеры —
// выключено по умолчанию. Каждый включённый канал это ещё один путь
// наружу для того, что мы собираемся запустить.
class WsbGenerator {
public:
    struct Options {
        std::wstring samplePath;      // файл образца НА ХОСТЕ
        std::wstring sampleArguments; // с чем его запускать внутри
        std::wstring sampleDir;       // папка, которая отобразится в C:\sample
        std::wstring agentDir;      // папка с наблюдателем на хосте
        std::wstring reportDir;     // папка на хосте, куда ляжет отчёт

        std::wstring agentExeName = L"ThreatAgent.exe";
        std::wstring reportName   = L"report.json";

        // Сеть выключена по умолчанию. Включать её осмысленно (образец
        // без сети часто просто ничего не делает), но это осознанный
        // риск, и решение принимает пользователь, а не эта функция.
        bool networking = false;

        int  memoryMb  = 4096;
        int  timeoutMs = 30000;

        // Гасить песочницу, как только отчёт записан. Иначе окно с
        // работающим образцом остаётся висеть до тех пор, пока
        // пользователь не догадается его закрыть.
        bool closeWhenDone = true;

        // Усиленный режим клиента песочницы. На домашней редакции
        // проверить нельзя — Windows Sandbox тут отсутствует.
        bool protectedClient = true;
    };

    struct Result {
        bool         ok = false;
        std::wstring wsbPath;       // куда записан файл конфигурации
        std::wstring reportPath;    // где на хосте ждать отчёт
        std::wstring error;
    };

    // Собрать XML без записи на диск — этим же пользуются проверки.
    static std::wstring BuildXml(const Options& options);

    // Проверить пути и записать .wsb. Папки должны существовать:
    // песочница молча не стартует, если отображать нечего.
    static Result Write(const Options& options, const std::wstring& wsbPath);
};
