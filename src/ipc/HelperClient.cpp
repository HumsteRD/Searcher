#include "HelperClient.h"
#include "HelperProtocol.h"
#include "../core/Logger.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QMetaObject>
#include <QDeadlineTimer>

#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

namespace Ipc {
namespace {

// Сколько ждём, пока помощник поднимет канал. Основная часть — время
// на диалог UAC, а его показывает система, и торопить её нельзя.
constexpr int kConnectTimeoutMs = 120000;
constexpr int kConnectStepMs = 200;

constexpr int kHandshakeTimeoutMs = 5000;

QString HelperPath() {
    return QDir::toNativeSeparators(
        QCoreApplication::applicationDirPath() + "/ThreatHelper.exe");
}

} // namespace

HelperClient::HelperClient(QObject* parent) : QObject(parent) {}

HelperClient::~HelperClient() {
    shutdown();
}

bool HelperClient::ensureRunning(QString* error) {
    if (running_.load()) return true;

    auto fail = [&](const QString& text) {
        if (error) *error = text;
        Disconnect();
        return false;
    };

    const QString helper = HelperPath();
    if (!QFileInfo::exists(helper))
        return fail(QObject::tr("ThreatHelper.exe is missing next to the application."));

    const QString pipeName = MakePipeName();

    QString reason;
    if (!LaunchHelper(pipeName, &reason)) return fail(reason);
    if (!ConnectToPipe(pipeName, &reason)) return fail(reason);
    if (!Handshake(&reason))               return fail(reason);

    running_ = true;
    reader_ = std::thread([this] { ReadLoop(); });

    Logger::Instance().Info("[Helper] connected");
    return true;
}

bool HelperClient::LaunchHelper(const QString& pipeName, QString* error) {
    // Помощнику сразу говорим, кого пускать: сам он этого не узнает,
    // а запустить его с чужим значением может только тот, кто и так
    // прошёл UAC, то есть уже имеет права администратора.
    const QString arguments =
        QString("--pipe %1 --client \"%2\"")
            .arg(pipeName, QDir::toNativeSeparators(
                               QCoreApplication::applicationFilePath()));

    const std::wstring file = HelperPath().toStdWString();
    const std::wstring args = arguments.toStdWString();

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask  = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"runas";          // это и есть запрос прав через UAC
    info.lpFile = file.c_str();
    info.lpParameters = args.c_str();
    info.nShow = SW_HIDE;

    if (!ShellExecuteExW(&info)) {
        const DWORD code = GetLastError();
        if (code == ERROR_CANCELLED) {
            // Пользователь отказал — это не сбой, и говорить об этом
            // надо человеческими словами.
            *error = QObject::tr("Administrator rights were not granted.");
        } else {
            *error = QObject::tr("Cannot start the helper, error %1").arg(code);
        }
        return false;
    }

    process_ = info.hProcess;
    return true;
}

bool HelperClient::ConnectToPipe(const QString& pipeName, QString* error) {
    const std::wstring path = PipePath(pipeName).toStdWString();
    QDeadlineTimer deadline(kConnectTimeoutMs);

    for (;;) {
        // FILE_FLAG_OVERLAPPED обязателен: иначе запись из потока
        // интерфейса встанет в очередь за висящим чтением потока
        // чтения — на одном дескрипторе синхронные операции идут строго
        // по очереди, и разговор в обе стороны просто останавливается.
        HANDLE pipe = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_OVERLAPPED, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            if (!channel_.Attach(pipe)) {
                CloseHandle(pipe);
                *error = QObject::tr("Cannot set up the channel.");
                return false;
            }
            return true;
        }

        // Помощник мог не дожить до создания канала — ждать его тогда
        // бессмысленно, а молчаливое ожидание до таймаута выглядит
        // как зависание.
        if (process_) {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(process_, &exitCode) &&
                exitCode != STILL_ACTIVE) {
                *error = QObject::tr("The helper exited before it was ready "
                                     "(code %1).").arg(exitCode);
                return false;
            }
        }

        if (deadline.hasExpired()) {
            *error = QObject::tr("Timed out waiting for the helper.");
            return false;
        }
        Sleep(kConnectStepMs);
    }
}

bool HelperClient::Handshake(QString* error) {
    // Рукопожатие делаем до запуска потока чтения: пока ответ один
    // и ждём мы его синхронно, разбирать его проще здесь.
    QJsonObject request;
    request[kFieldId] = 0;
    request[kFieldCommand] = QString(kCmdHello);

    if (!WriteLine(request)) {
        *error = QObject::tr("Cannot talk to the helper.");
        return false;
    }

    QByteArray pending;
    QDeadlineTimer deadline(kHandshakeTimeoutMs);

    for (;;) {
        char chunk[4096];
        DWORD read = 0;
        if (!channel_.Read(chunk, sizeof(chunk), &read)) {
            *error = QObject::tr("The helper closed the connection.");
            return false;
        }
        pending.append(chunk, static_cast<int>(read));

        const int newline = pending.indexOf('\n');
        if (newline < 0) {
            if (deadline.hasExpired()) {
                *error = QObject::tr("The helper did not answer.");
                return false;
            }
            continue;
        }

        const QJsonObject response =
            QJsonDocument::fromJson(pending.left(newline)).object();

        if (!response[kFieldOk].toBool()) {
            *error = response[kFieldError].toString();
            if (error->isEmpty()) *error = QObject::tr("The helper refused to start.");
            return false;
        }

        const int version = response[kFieldResult].toObject()["version"].toInt();
        if (version != kProtocolVersion) {
            *error = QObject::tr("The helper speaks protocol %1, the application "
                                 "expects %2.").arg(version).arg(kProtocolVersion);
            return false;
        }
        return true;
    }
}

bool HelperClient::WriteLine(const QJsonObject& message) {
    QByteArray line = QJsonDocument(message).toJson(QJsonDocument::Compact);
    line.append('\n');

    return channel_.Write(line.constData(), static_cast<DWORD>(line.size()));
}

bool HelperClient::send(const QString& command, const QJsonObject& args,
                        Callback callback)
{
    if (!running_.load()) return false;

    const int id = nextId_.fetch_add(1);

    if (callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.insert(id, std::move(callback));
    }

    QJsonObject request;
    request[kFieldId] = id;
    request[kFieldCommand] = command;
    if (!args.isEmpty()) request[kFieldArgs] = args;

    if (WriteLine(request)) return true;

    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.remove(id);
    return false;
}

void HelperClient::ReadLoop() {
    QByteArray pending;

    while (running_.load()) {
        char chunk[64 * 1024];
        DWORD read = 0;
        if (!channel_.Read(chunk, sizeof(chunk), &read)) break;

        pending.append(chunk, static_cast<int>(read));

        int newline = pending.indexOf('\n');
        while (newline >= 0) {
            const QByteArray line = pending.left(newline);
            pending.remove(0, newline + 1);
            newline = pending.indexOf('\n');

            if (!line.trimmed().isEmpty())
                HandleMessage(QJsonDocument::fromJson(line).object());
        }
    }

    if (running_.exchange(false)) {
        // Ответов больше не будет: висящий колбэк — это кнопка,
        // которая никогда не разблокируется.
        QHash<int, Callback> pendingCallbacks;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pendingCallbacks.swap(callbacks_);
        }
        QMetaObject::invokeMethod(this, [this, pendingCallbacks]() {
            for (const Callback& callback : pendingCallbacks) {
                callback(false, {}, QObject::tr("The helper disconnected."));
            }
            emit disconnected();
        }, Qt::QueuedConnection);
    }
}

void HelperClient::HandleMessage(const QJsonObject& message) {
    const QString eventName = message[kFieldEvent].toString();
    if (!eventName.isEmpty()) {
        QMetaObject::invokeMethod(this, [this, eventName, message]() {
            emit eventReceived(eventName, message);
        }, Qt::QueuedConnection);
        return;
    }

    const int id = message[kFieldId].toInt();
    Callback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = callbacks_.take(id);
    }
    if (!callback) return;

    const bool ok = message[kFieldOk].toBool();
    const QJsonObject result = message[kFieldResult].toObject();
    const QString error = message[kFieldError].toString();

    QMetaObject::invokeMethod(this, [callback, ok, result, error]() {
        callback(ok, result, error);
    }, Qt::QueuedConnection);
}

void HelperClient::shutdown() {
    if (running_.load()) {
        QJsonObject request;
        request[kFieldId] = nextId_.fetch_add(1);
        request[kFieldCommand] = kCmdShutdown;
        WriteLine(request);
    }
    Disconnect();
}

void HelperClient::Disconnect() {
    running_ = false;

    channel_.Close();   // разрыв канала завершает помощника

    if (reader_.joinable()) {
        if (reader_.get_id() == std::this_thread::get_id()) reader_.detach();
        else reader_.join();
    }

    if (process_) {
        // Помощник уходит сам по разрыву канала. Ждём недолго и только
        // потом снимаем — процесс с полными правами не должен пережить
        // приложение ни при каком раскладе.
        if (WaitForSingleObject(process_, 3000) == WAIT_TIMEOUT) {
            Logger::Instance().Warn("[Helper] did not exit, terminating");
            TerminateProcess(process_, 1);
        }
        CloseHandle(process_);
        process_ = nullptr;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.clear();
}

} // namespace Ipc
