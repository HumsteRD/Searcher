// Привилегированный помощник.
//
// Интерфейс работает от обычного пользователя и сам ничего сделать
// с системой не может: перечислить чужие процессы, вычистить ключ в
// HKLM, снять задачу, увезти файл в карантин. Всё это делает этот
// процесс — он поднимается через UAC на время работы приложения и
// уходит вместе с ним.
//
//   ThreatHelper.exe --pipe <имя> [--client <путь к тому, кто подключается>]
//
// Запускать его руками незачем: без своего канала он ничего не делает.

#include "ipc/HelperServer.h"
#include "ipc/HelperProtocol.h"
#include "ipc/ScanService.h"
#include "ipc/SandboxService.h"
#include "core/Logger.h"
#include "core/ServiceConfig.h"

#include <QProcess>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonObject>
#include <QDateTime>
#include <QTextStream>

#include <Windows.h>

namespace {

// Помощник запускается со скрытым окном, и обычный вывод в консоль
// никто не увидит. Всё, что случилось до подключения клиента, попадает
// только сюда — без этого файла упавший помощник выглядит как
// «приложение зависло на запуске».
void LogToFile(const QString& message) {
    const QString path = QDir::tempPath() + "/ThreatScanner-helper.log";
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
        return;

    QTextStream out(&file);
    out << QDateTime::currentDateTime().toString("hh:mm:ss.zzz")
        << "  " << message << "\n";
}

// Запуск ThreatService.exe с ключом. Служба ставится своим же кодом:
// дублировать работу с диспетчером служб в помощнике — значит держать
// две реализации одного и того же и чинить их порознь.
QString RunServiceCommand(const QString& argument, int* exitCode) {
    QProcess process;
    process.setProgram(QDir::toNativeSeparators(
        QCoreApplication::applicationDirPath() + "/ThreatService.exe"));
    process.setArguments({ argument });
    process.start();

    if (!process.waitForFinished(30000)) {
        process.kill();
        if (exitCode) *exitCode = -1;
        return "timed out";
    }

    if (exitCode) *exitCode = process.exitCode();
    return QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
}

ServiceConfig::Settings SettingsFromArgs(const QJsonObject& args) {
    ServiceConfig::Settings settings;
    settings.enabled       = args["enabled"].toBool();
    settings.intervalHours = args["intervalHours"].toInt(24);
    settings.deepScan      = args["deepScan"].toBool();
    return settings;
}

QString ArgumentValue(const QStringList& arguments, const QString& name) {
    const int index = arguments.indexOf(name);
    if (index < 0 || index + 1 >= arguments.size()) return {};
    return arguments.at(index + 1);
}

} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("ThreatScanner");
    QCoreApplication::setApplicationName("ThreatScanner");

    const QStringList arguments = QCoreApplication::arguments();
    const QString pipeName = ArgumentValue(arguments, "--pipe");

    if (pipeName.isEmpty()) {
        LogToFile("started without --pipe, nothing to do");
        return 2;
    }

    // Кого пускать. По умолчанию — приложение рядом с нами: помощник
    // и интерфейс всегда лежат в одной папке и обновляются вместе.
    QString expectedClient = ArgumentValue(arguments, "--client");
    if (expectedClient.isEmpty()) {
        expectedClient = QDir::toNativeSeparators(
            QCoreApplication::applicationDirPath() + "/ThreatScanner.exe");
    }

    Ipc::HelperServer server;
    QString error;
    if (!server.Listen(pipeName, expectedClient.toStdWString(), &error)) {
        LogToFile("cannot serve the pipe: " + error);
        return 3;
    }

    LogToFile("client connected: " + expectedClient);

    Ipc::ScanService scan(server);
    scan.RegisterModules();
    scan.StartPolling();

    Ipc::SandboxService sandbox(server);

    server.Run([&](const QString& command, const QJsonObject& args,
                   QString* commandError) -> QJsonObject
    {
        QJsonObject result;

        if (command == Ipc::kCmdHello) {
            result["version"] = Ipc::kProtocolVersion;
            result["pid"] = static_cast<int>(GetCurrentProcessId());
            result["elevated"] = true;
            return result;
        }

        if (command == Ipc::kCmdShutdown) {
            server.RequestStop();
            return result;
        }

        if (scan.Handle(command, args, commandError, &result)) return result;
        if (sandbox.Handle(command, args, commandError, &result)) return result;

        if (command == Ipc::kCmdServiceStatus) {
            int code = 0;
            result["status"] = RunServiceCommand("--status", &code);
            const auto settings = ServiceConfig::Read();
            result["enabled"]       = settings.enabled;
            result["intervalHours"] = settings.intervalHours;
            result["deepScan"]      = settings.deepScan;
            return result;
        }

        if (command == Ipc::kCmdServiceConfigure) {
            if (!ServiceConfig::Write(SettingsFromArgs(args)))
                *commandError = "cannot write the service settings";
            return result;
        }

        if (command == Ipc::kCmdServiceInstall) {
            // Настройку пишем до установки: служба читает её на первом
            // же круге, и пустая конфигурация означала бы «выключено».
            if (!ServiceConfig::Write(SettingsFromArgs(args))) {
                *commandError = "cannot write the service settings";
                return result;
            }
            int code = 0;
            const QString output = RunServiceCommand("--install", &code);
            result["output"] = output;
            if (code != 0) *commandError = output;
            return result;
        }

        if (command == Ipc::kCmdServiceUninstall) {
            int code = 0;
            const QString output = RunServiceCommand("--uninstall", &code);
            result["output"] = output;
            if (code != 0) *commandError = output;

            ServiceConfig::Settings off;
            off.enabled = false;
            ServiceConfig::Write(off);
            return result;
        }

        *commandError = "unknown command: " + command;
        return result;
    });

    // Останавливаем всё, что пишет в канал, до выхода: канала уже нет.
    scan.StopPolling();
    sandbox.Stop();
    LogToFile("connection closed, exiting");
    return 0;
}
