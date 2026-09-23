#include "HelperServer.h"
#include "HelperProtocol.h"
#include "PipeSecurity.h"

#include <QJsonDocument>
#include <QByteArray>
#include <vector>

namespace Ipc {
namespace {

constexpr DWORD kBufferSize = 64 * 1024;

// Потолок на длину одной строки. Без него клиент, приславший поток без
// перевода строки, съел бы всю память помощника.
constexpr int kMaxMessageBytes = 8 * 1024 * 1024;

} // namespace

HelperServer::~HelperServer() {
    Stop();
}

bool HelperServer::Listen(const QString& pipeName,
                          const std::wstring& expectedClient, QString* error)
{
    auto fail = [&](const QString& text) {
        if (error) *error = text;
        return false;
    };

    PipeSecurity security;
    if (!security.valid())
        return fail("cannot build the pipe security descriptor");

    const std::wstring path = PipePath(pipeName).toStdWString();

    // FILE_FLAG_FIRST_PIPE_INSTANCE: если имя уже занято, значит его
    // занял не мы — молча присоединяться к чужому каналу нельзя.
    // FILE_FLAG_OVERLAPPED: иначе ответы встают в очередь за висящим
    // чтением на том же дескрипторе (см. PipeChannel).
    HANDLE pipe = CreateNamedPipeW(
        path.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,                      // единственный экземпляр
        kBufferSize, kBufferSize,
        0,
        security.attributes());

    if (pipe == INVALID_HANDLE_VALUE)
        return fail(QString("CreateNamedPipe failed, error %1").arg(GetLastError()));

    // Ожидание клиента тоже перекрывающееся — дескриптор открыт с
    // FILE_FLAG_OVERLAPPED, и синхронного варианта у него нет.
    HANDLE connectEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!connectEvent) {
        CloseHandle(pipe);
        return fail("cannot create the connect event");
    }

    OVERLAPPED overlapped{};
    overlapped.hEvent = connectEvent;

    bool connected = ConnectNamedPipe(pipe, &overlapped) != FALSE;
    if (!connected) {
        const DWORD code = GetLastError();
        if (code == ERROR_PIPE_CONNECTED) {
            connected = true;
        } else if (code == ERROR_IO_PENDING) {
            DWORD transferred = 0;
            connected = WaitForSingleObject(connectEvent, INFINITE) == WAIT_OBJECT_0 &&
                        GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
        }
    }
    CloseHandle(connectEvent);

    if (!connected) {
        const DWORD code = GetLastError();
        CloseHandle(pipe);
        return fail(QString("ConnectNamedPipe failed, error %1").arg(code));
    }

    std::wstring reason;
    if (!VerifyPipeClient(pipe, expectedClient, &reason)) {
        // Кто-то не тот занял наш конец: обслуживать его нельзя,
        // и молчать об этом тоже.
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return fail("client rejected: " + QString::fromStdWString(reason));
    }

    if (!channel_.Attach(pipe)) {
        CloseHandle(pipe);
        return fail("cannot set up the channel");
    }

    running_ = true;
    return true;
}

void HelperServer::WriteLine(const QJsonObject& message) {
    QByteArray line = QJsonDocument(message).toJson(QJsonDocument::Compact);
    line.append('\n');

    if (!channel_.Write(line.constData(), static_cast<DWORD>(line.size())))
        running_ = false;   // канал оборвался — дальше писать некому
}

void HelperServer::SendEvent(const QString& name, const QJsonObject& payload) {
    QJsonObject message = payload;
    message[kFieldEvent] = name;
    WriteLine(message);
}

void HelperServer::Run(Handler handler) {
    QByteArray pending;
    std::vector<char> chunk(kBufferSize);

    while (running_) {
        DWORD read = 0;
        if (!channel_.Read(chunk.data(), static_cast<DWORD>(chunk.size()), &read))
            break;   // клиент закрыл канал — это и есть команда на выход

        pending.append(chunk.data(), static_cast<int>(read));
        if (pending.size() > kMaxMessageBytes) break;

        int newline = pending.indexOf('\n');
        while (newline >= 0) {
            const QByteArray line = pending.left(newline);
            pending.remove(0, newline + 1);
            newline = pending.indexOf('\n');

            if (line.trimmed().isEmpty()) continue;

            const QJsonObject request = QJsonDocument::fromJson(line).object();
            const QString command = request[kFieldCommand].toString();
            const int id = request[kFieldId].toInt();

            QJsonObject response;
            response[kFieldId] = id;

            if (command.isEmpty()) {
                response[kFieldOk] = false;
                response[kFieldError] = "malformed request";
            } else {
                QString error;
                const QJsonObject result =
                    handler(command, request[kFieldArgs].toObject(), &error);

                if (error.isEmpty()) {
                    response[kFieldOk] = true;
                    response[kFieldResult] = result;
                } else {
                    response[kFieldOk] = false;
                    response[kFieldError] = error;
                }
            }

            WriteLine(response);
            if (!running_ || stopAfterReply_) { running_ = false; break; }
        }
    }
    running_ = false;
}

void HelperServer::Stop() {
    running_ = false;
    channel_.Close();
}

} // namespace Ipc
