#pragma once

#include "PipeChannel.h"

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QHash>

#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <Windows.h>

namespace Ipc {

// Клиентская сторона канала — живёт в интерфейсе.
//
// Поднимает помощника через UAC и держит с ним связь до закрытия
// приложения. Первый запрос, которому нужны права, стоит пользователю
// одного согласия в диалоге UAC; дальше всё идёт по уже открытому каналу.
class HelperClient : public QObject {
    Q_OBJECT

public:
    explicit HelperClient(QObject* parent = nullptr);
    ~HelperClient() override;

    bool isConnected() const { return running_.load(); }

    // Поднять помощника и подключиться. false — не вышло, и причина
    // человеческая: отказ в UAC от «не удалось» отличается.
    bool ensureRunning(QString* error = nullptr);

    // Ответ на команду. Вызывается в потоке интерфейса.
    using Callback = std::function<void(bool ok, const QJsonObject& result,
                                        const QString& error)>;

    bool send(const QString& command, const QJsonObject& args = {},
              Callback callback = {});

    void shutdown();

signals:
    void eventReceived(QString name, QJsonObject payload);
    void disconnected();

private:
    bool LaunchHelper(const QString& pipeName, QString* error);
    bool ConnectToPipe(const QString& pipeName, QString* error);
    bool Handshake(QString* error);
    bool WriteLine(const QJsonObject& message);
    void ReadLoop();
    void HandleMessage(const QJsonObject& message);
    void Disconnect();

    PipeChannel       channel_;
    HANDLE            process_ = nullptr;
    std::thread       reader_;
    std::atomic<bool> running_{ false };
    std::atomic<int>  nextId_{ 1 };

    std::mutex            mutex_;      // таблица ожидающих ответов
    QHash<int, Callback>  callbacks_;
};

} // namespace Ipc
