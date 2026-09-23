#pragma once

#include "BehaviorReport.h"

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <Windows.h>

// Изменения файловой системы под наблюдаемыми корнями.
//
// ReadDirectoryChangesW сообщает, ЧТО изменилось, но не КТО это сделал:
// автора изменения в пользовательском режиме не узнать. Поэтому события
// уходят с pid = 0, а в отчёт добавляется соответствующее ограничение.
class FileActivityWatcher {
public:
    ~FileActivityWatcher();

    // Корни, которые открыть не удалось, молча пропускаются — список
    // успешных возвращает WatchedRoots(). false — не открылся ни один.
    bool Start(const std::vector<std::wstring>& roots, BehaviorSink sink);
    void Stop();

    const std::vector<std::wstring>& WatchedRoots() const { return watched_; }

private:
    struct Root {
        OVERLAPPED   ov{};              // обязан быть первым: по нему ищем Root
        HANDLE       dir = INVALID_HANDLE_VALUE;
        std::wstring path;
        std::wstring pendingRenameFrom; // OLD_NAME приходит отдельным событием
        DWORD        buffer[16 * 1024]; // 64 КБ; выше ядро не отдаёт
    };

    bool Arm(Root& root);
    void Pump();
    void Emit(BehaviorEventType type, const std::wstring& path,
              const std::wstring& detail = {});

    // «тип+путь» → когда о нём сообщали в последний раз. Один и тот же
    // файл под двумя вложенными корнями даёт два уведомления, да и
    // обычная запись файла порождает несколько FILE_ACTION_MODIFIED
    // подряд. Читать такой отчёт невозможно.
    std::unordered_map<std::wstring, ULONGLONG> lastSeen_;

    HANDLE                             port_ = nullptr;
    std::vector<std::unique_ptr<Root>> roots_;
    std::vector<std::wstring>          watched_;
    std::thread                        thread_;
    std::atomic<bool>                  stopping_{ false };
    BehaviorSink                       sink_;
};
