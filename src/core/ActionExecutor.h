#pragma once

#include <string>

// Результат действия. message — код для интерфейса (см. ThreatActions),
// а не готовая фраза: текст строится на выбранном языке.
struct ActionResult {
    bool        success = false;
    std::wstring message;
};

// Действия над системой: удаление файлов, записей реестра, задач,
// отключение служб, снятие подписок WMI, правка hosts.
class ActionExecutor {
public:
    // Имя намеренно не DeleteFile: в <Windows.h> это макрос.
    static ActionResult RemoveFile(const std::wstring& path);

    // "HKCU\Software\...\Run" + имя значения.
    static ActionResult RemoveRegistryValue(const std::wstring& rootAndSubKey,
                                            const std::wstring& valueName);

    static ActionResult DeleteScheduledTask(const std::wstring& taskPath);

    static ActionResult KillProcess(unsigned long pid);

    // Остановить службу и запретить ей запускаться. Удаление службы
    // необратимо и может сломать систему, если находка ложная, — поэтому
    // только отключение.
    static ActionResult DisableService(const std::wstring& serviceName);

    // Снять постоянную подписку WMI: связку и сам потребитель.
    static ActionResult RemoveWmiConsumer(const std::wstring& consumerRelPath);

    // Убрать строку из hosts. Прежний файл сохраняется рядом как hosts.bak.
    static ActionResult RemoveHostsLine(const std::wstring& line);
};
