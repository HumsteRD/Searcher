#pragma once

#include "PipeChannel.h"

#include <QString>
#include <QJsonObject>

#include <functional>
#include <atomic>
#include <string>
#include <Windows.h>

namespace Ipc {

// Серверная сторона канала — живёт в помощнике.
//
// Один клиент за сеанс: помощник поднимается интерфейсом под конкретную
// работу и уходит вместе с ним. Разрыв канала завершает Run(), а значит
// и сам процесс: висящий процесс с полными правами после закрытия окна
// не нужен никому.
class HelperServer {
public:
    // Обработчик команды. Пустая строка в error — успех.
    // ВАЖНО: обработчик выполняется в потоке чтения и не должен блокировать.
    // Долгую работу запускать отдельным потоком и отдавать ход событиями.
    using Handler = std::function<QJsonObject(const QString& command,
                                              const QJsonObject& args,
                                              QString* error)>;

    ~HelperServer();

    // Создать канал и дождаться клиента. expectedClient — полный путь
    // к образу, которому разрешено подключаться.
    bool Listen(const QString& pipeName, const std::wstring& expectedClient,
                QString* error);

    // Читать и обрабатывать команды до разрыва канала.
    void Run(Handler handler);

    // Событие клиенту. Можно звать из любого потока.
    void SendEvent(const QString& name, const QJsonObject& payload);

    // Закончить работу, но сначала дослать ответ на текущую команду.
    // Иначе клиент не узнает, чем кончилось его «shutdown».
    void RequestStop() { stopAfterReply_ = true; }

    void Stop();

private:
    void WriteLine(const QJsonObject& message);

    PipeChannel       channel_;
    std::atomic<bool> running_{ false };
    std::atomic<bool> stopAfterReply_{ false };
};

} // namespace Ipc
