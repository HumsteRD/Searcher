// Проверка канала до помощника.
//
// Поднимает ThreatHelper.exe через UAC (система спросит согласия),
// здоровается, проверяет ответ и закрывает канал. Отдельно проверяет,
// что помощник уходит сам, когда канал обрывается: процесс с полными
// правами не должен переживать того, кто его позвал.

#include "ipc/HelperClient.h"
#include "ipc/HelperProtocol.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QTimer>
#include <QJsonObject>

#include <Windows.h>
#include <cstdio>

namespace {

int g_failures = 0;

void Check(bool ok, const char* what) {
    printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++g_failures;
}

} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("ThreatScanner");
    QCoreApplication::setApplicationName("ThreatScanner");
    SetConsoleOutputCP(CP_UTF8);

    printf("--- helper channel ---\n");
    printf("  Windows will ask for administrator rights.\n");
    fflush(stdout);

    Ipc::HelperClient client;

    QString error;
    if (!client.ensureRunning(&error)) {
        printf("  [FAIL] helper did not start: %s\n", error.toUtf8().constData());
        return 2;
    }
    Check(true, "helper started and answered the handshake");

    // Ещё один запрос по уже открытому каналу: рукопожатие проходит
    // синхронно, а обычные команды — через поток чтения и очередь,
    // и ломается обычно как раз второй путь.
    QEventLoop loop;
    bool answered = false;
    int helperPid = 0;

    client.send(Ipc::kCmdHello, {}, [&](bool ok, const QJsonObject& result,
                                        const QString& message) {
        answered = ok;
        helperPid = result["pid"].toInt();
        if (!ok) printf("  error: %s\n", message.toUtf8().constData());
        loop.quit();
    });

    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    Check(answered, "command answered over the open channel");
    Check(helperPid != 0, "helper reported its process id");

    bool unknownRejected = false;
    QEventLoop unknownLoop;
    client.send("no-such-command", {}, [&](bool ok, const QJsonObject&,
                                           const QString& message) {
        unknownRejected = !ok && !message.isEmpty();
        unknownLoop.quit();
    });
    QTimer::singleShot(5000, &unknownLoop, &QEventLoop::quit);
    unknownLoop.exec();
    Check(unknownRejected, "unknown command is refused with a reason");

    // Установка и снятие службы — по явному ключу. Молча менять состав
    // служб на машине проверка не должна.
    const QStringList arguments = QCoreApplication::arguments();
    const bool doInstall   = arguments.contains("--install-service");
    const bool doUninstall = arguments.contains("--uninstall-service");

    if (doInstall || doUninstall) {
        QJsonObject options;
        options["enabled"]       = true;
        options["intervalHours"] = 24;
        options["deepScan"]      = false;

        QEventLoop changeLoop;
        bool changed = false;
        QString message;
        client.send(doInstall ? Ipc::kCmdServiceInstall : Ipc::kCmdServiceUninstall,
                    options, [&](bool ok, const QJsonObject& result,
                                 const QString& error) {
            changed = ok;
            message = ok ? result["output"].toString() : error;
            changeLoop.quit();
        });
        QTimer::singleShot(60000, &changeLoop, &QEventLoop::quit);
        changeLoop.exec();

        Check(changed, doInstall ? "service installed" : "service removed");
        printf("  helper says: %s\n", message.toUtf8().constData());
    }

    // Состояние службы — команда только на чтение, ничего не ставит.
    QEventLoop serviceLoop;
    QString serviceStatus;
    client.send(Ipc::kCmdServiceStatus, {}, [&](bool ok, const QJsonObject& result,
                                                const QString&) {
        if (ok) serviceStatus = result["status"].toString();
        serviceLoop.quit();
    });
    QTimer::singleShot(35000, &serviceLoop, &QEventLoop::quit);
    serviceLoop.exec();

    Check(!serviceStatus.isEmpty(), "helper answers about the background service");
    printf("  service: %s\n", serviceStatus.toUtf8().constData());

    // Помощник обязан уйти сам. Держим его дескриптор до проверки:
    // иначе номер процесса успеет переиспользоваться.
    HANDLE helperProcess = helperPid
        ? OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(helperPid))
        : nullptr;

    client.shutdown();
    Check(!client.isConnected(), "channel closed");

    if (helperProcess) {
        const DWORD wait = WaitForSingleObject(helperProcess, 5000);
        Check(wait == WAIT_OBJECT_0, "helper exited with the channel");
        CloseHandle(helperProcess);
    } else {
        Check(false, "could not watch the helper process");
    }

    printf("\n%s (%d failed)\n",
           g_failures ? "FAILURES" : "ALL CHECKS PASSED", g_failures);
    return g_failures == 0 ? 0 : 1;
}
