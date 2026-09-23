#pragma once

#include "HelperServer.h"
#include "../core/SandboxSession.h"

#include <QJsonObject>
#include <QString>
#include <thread>
#include <atomic>

namespace Ipc {

// Сеанс изолированного анализа на стороне помощника.
//
// Windows Sandbox запускается только с правами администратора, поэтому
// сеанс держит помощник целиком: раскладка, запуск виртуальной машины,
// ожидание отчёта. Наружу уходят стадии и путь к сохранённому отчёту —
// сам отчёт интерфейс читает с диска тем же кодом, что и отчёт,
// открытый пользователем вручную.
class SandboxService {
public:
    explicit SandboxService(HelperServer& server);
    ~SandboxService();

    bool Handle(const QString& command, const QJsonObject& args,
                QString* error, QJsonObject* result);

    // Прервать сеанс и дождаться потока. Зовётся при закрытии канала.
    void Stop();

private:
    void Run(const SandboxSession::Options& options);
    QString SaveReport(const BehaviorReport& report);

    HelperServer&     server_;
    std::thread       worker_;
    CancelToken       cancel_;
    std::atomic<bool> running_{ false };
};

} // namespace Ipc
