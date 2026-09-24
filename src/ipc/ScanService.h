#pragma once

#include "HelperServer.h"
#include "../core/Scanner.h"

#include <QJsonObject>
#include <thread>
#include <atomic>

namespace Ipc {

// Проверка системы на стороне помощника.
//
// Здесь живёт настоящий Scanner со всеми модулями — тот самый код, что
// раньше работал в интерфейсе и тянул за собой требование прав
// администратора на всё приложение. Наружу он отдаёт ровно то, что
// раньше отдавал ScannerBridge: прогресс, найденные угрозы, состояние,
// статистику и строки журнала.
class ScanService {
public:
    explicit ScanService(HelperServer& server);
    ~ScanService();

    // Модули регистрируются в порядке AppSettings::ModuleId — по этому
    // индексу Scanner отбирает включённые. Порядок менять нельзя.
    void RegisterModules();

    // Обработка команд проверки. Возвращает false, если команда не наша.
    bool Handle(const QString& command, const QJsonObject& args,
                QString* error, QJsonObject* result);

    // Опрос состояния и рассылка событий. Останавливается вместе с каналом.
    void StartPolling();
    void StopPolling();

private:
    void PollOnce();
    static ScanConfig ConfigFromArgs(const QJsonObject& args);

    HelperServer&     server_;
    Scanner           scanner_;
    std::thread       poller_;
    std::atomic<bool> polling_{ false };

    // Что уже отправлено клиенту: события шлём только на изменения,
    // иначе канал забьётся повторами двенадцать раз в секунду.
    size_t    lastLogIndex_ = 0;
    size_t    lastThreatCount_ = 0;
    int       lastState_ = -1;
    int       lastTotal_ = -1;
    int       lastCritical_ = -1;
    long long lastObjects_ = -1;
    int       lastPercent_ = -1;
    std::string lastStage_;
    std::wstring lastItem_;
    std::vector<int> lastStatuses_;
};

} // namespace Ipc
