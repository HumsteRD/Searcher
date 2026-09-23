#pragma once

#include <string>

// Результат действия
struct ActionResult {
    bool        success = false;
    std::wstring message;
};

// Выполняет действия над угрозами: удаление файлов, ключей реестра, задач.
// Карантин делается отдельно через Quarantine.
class ActionExecutor {
public:
    // Удалить файл навсегда.
    // Имя намеренно не DeleteFile: в <Windows.h> это макрос -> DeleteFileW.
    static ActionResult RemoveFile(const std::wstring& path);

    // Удалить значение из ключа автозапуска реестра.
    // regPath формата "HKCU\Software\...\Run" + valueName
    static ActionResult RemoveRegistryValue(const std::wstring& rootAndSubKey,
                                            const std::wstring& valueName);

    // Удалить запланированную задачу по полному пути (например "\MyTask")
    static ActionResult DeleteScheduledTask(const std::wstring& taskPath);

    // Завершить процесс по PID
    static ActionResult KillProcess(unsigned long pid);
};
