// Служба фоновых проверок.
//
// Единственное, ради чего она существует: расписание должно работать,
// когда окно закрыто. Помощник этого не умеет — он уходит вместе с окном.
//
// У службы НЕТ командного канала, и это осознанно. Помощник принимает
// команды, потому что живёт под учётной записью пользователя и ровно
// столько, сколько открыто окно. Служба работает под SYSTEM постоянно,
// и приём команд превратил бы её в постоянно открытую дверь с полными
// правами. Настройку она читает из HKLM (писать туда может только
// администратор), результат складывает в файл в %ProgramData%.
//
//   ThreatService.exe --install     установить (нужны права администратора)
//   ThreatService.exe --uninstall   удалить
//   ThreatService.exe --status      состояние
//   ThreatService.exe --service     запуск диспетчером служб

#include "core/ServiceConfig.h"
#include "core/Scanner.h"
#include "core/Logger.h"
#include "core/FileSystemScanner.h"
#include "core/ProcessScanner.h"
#include "core/AutorunScanner.h"
#include "core/TaskSchedulerScanner.h"
#include "core/PersistenceScanner.h"
#include "core/NetworkScanner.h"
#include "core/ThreatJson.h"

#include <QCoreApplication>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#include <Windows.h>
#include <memory>
#include <string>

namespace {

SERVICE_STATUS        g_status{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE                g_stopEvent = nullptr;

std::wstring OwnPath() {
    wchar_t buffer[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, buffer, _countof(buffer));
    return buffer;
}

void ReportStatus(DWORD state, DWORD waitHint = 0) {
    g_status.dwCurrentState = state;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
}

// ─── Установка и удаление ────────────────────────────────────────────────

int Install() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!manager) {
        wprintf(L"cannot open the service manager (error %lu) — "
                L"administrator rights are required\n", GetLastError());
        return 2;
    }

    const std::wstring command = L"\"" + OwnPath() + L"\" --service";

    SC_HANDLE service = CreateServiceW(
        manager, ServiceConfig::kServiceName, ServiceConfig::kDisplayName,
        SERVICE_CHANGE_CONFIG | SERVICE_START,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,        // расписание должно пережить перезагрузку
        SERVICE_ERROR_NORMAL,
        command.c_str(),
        nullptr, nullptr, nullptr,
        nullptr,                   // LocalSystem
        nullptr);

    if (!service) {
        const DWORD error = GetLastError();
        CloseServiceHandle(manager);
        if (error == ERROR_SERVICE_EXISTS) {
            wprintf(L"already installed\n");
            return 0;
        }
        wprintf(L"cannot create the service (error %lu)\n", error);
        return 3;
    }

    SERVICE_DESCRIPTIONW description{};
    std::wstring text =
        L"Runs Threat Scanner checks on schedule while the application is closed.";
    description.lpDescription = text.data();
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description);

    StartServiceW(service, 0, nullptr);

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    wprintf(L"installed\n");
    return 0;
}

int Uninstall() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        wprintf(L"cannot open the service manager (error %lu)\n", GetLastError());
        return 2;
    }

    SC_HANDLE service = OpenServiceW(manager, ServiceConfig::kServiceName,
                                     SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!service) {
        const DWORD error = GetLastError();
        CloseServiceHandle(manager);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            wprintf(L"not installed\n");
            return 0;
        }
        wprintf(L"cannot open the service (error %lu)\n", error);
        return 3;
    }

    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);

    const bool deleted = DeleteService(service) != FALSE;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    wprintf(deleted ? L"removed\n" : L"cannot remove the service\n");
    return deleted ? 0 : 4;
}

int Status() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) { wprintf(L"unknown\n"); return 2; }

    SC_HANDLE service = OpenServiceW(manager, ServiceConfig::kServiceName,
                                     SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(manager);
        wprintf(L"not installed\n");
        return 1;
    }

    SERVICE_STATUS status{};
    const bool ok = QueryServiceStatus(service, &status) != FALSE;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    if (!ok) { wprintf(L"unknown\n"); return 2; }
    wprintf(status.dwCurrentState == SERVICE_RUNNING ? L"running\n" : L"stopped\n");
    return 0;
}

// ─── Работа ──────────────────────────────────────────────────────────────

void AppendResult(const ScanStats& stats, const std::vector<Threat>& threats, bool full) {
    const QString path = QString::fromStdWString(ServiceConfig::ResultsPath());
    if (path.isEmpty()) return;

    QJsonArray records;
    QFile file(path);
    if (file.open(QIODevice::ReadOnly)) {
        records = QJsonDocument::fromJson(file.readAll()).array();
        file.close();
    }

    QJsonObject record;
    record["when"]       = QDateTime::currentDateTime().toString(Qt::ISODate);
    record["mode"]       = full ? "Full" : "Quick";
    record["threats"]    = stats.totalThreats;
    record["critical"]   = stats.criticalThreats;
    record["objects"]    = static_cast<double>(stats.objectsScanned);
    record["durationMs"] = stats.elapsedMs;
    record["cancelled"]  = stats.cancelled;
    QJsonArray found;
    for (const Threat& t : threats) found.append(ThreatJson::ToJson(t));
    record["findings"]   = found;
    records.prepend(record);

    // Файл читает приложение при запуске; бесконечно расти ему незачем.
    while (records.size() > 50) records.removeLast();

    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    file.write(QJsonDocument(records).toJson(QJsonDocument::Indented));
}

void RunScan(bool full) {
    Scanner scanner;
    scanner.RegisterModule(std::make_shared<ProcessScanner>());
    scanner.RegisterModule(std::make_shared<AutorunScanner>());
    scanner.RegisterModule(std::make_shared<TaskSchedulerScanner>());
    scanner.RegisterModule(std::make_shared<PersistenceScanner>());
    scanner.RegisterModule(std::make_shared<NetworkScanner>());
    scanner.RegisterModule(std::make_shared<FileSystemScanner>());

    ScanConfig config;
    config.mode = full ? ScanConfig::Mode::Full : ScanConfig::Mode::Quick;
    scanner.Start(config);

    // Ждём окончания, но уступаем команде остановки: служба обязана
    // ответить диспетчеру вовремя, иначе Windows сочтёт её зависшей.
    while (scanner.State() != ScanState::Done) {
        if (WaitForSingleObject(g_stopEvent, 500) == WAIT_OBJECT_0) {
            scanner.Cancel();
            while (scanner.State() != ScanState::Done) Sleep(100);
            break;
        }
    }

    AppendResult(scanner.Stats(), scanner.Snapshot(), full);
}

void WINAPI ServiceHandler(DWORD control) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        ReportStatus(SERVICE_STOP_PENDING, 5000);
        SetEvent(g_stopEvent);
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_statusHandle = RegisterServiceCtrlHandlerW(ServiceConfig::kServiceName,
                                                 ServiceHandler);
    if (!g_statusHandle) return;

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ReportStatus(SERVICE_START_PENDING, 3000);
    ReportStatus(SERVICE_RUNNING);

    ULONGLONG lastScan = 0;   // 0 — ещё не проверяли в этом запуске

    for (;;) {
        const auto settings = ServiceConfig::Read();

        if (settings.enabled) {
            const ULONGLONG now = GetTickCount64();
            const ULONGLONG interval =
                static_cast<ULONGLONG>(settings.intervalHours) * 3600ull * 1000ull;

            // Первую проверку не запускаем сразу после старта системы:
            // загрузка и так занята, а расписание не про минуты.
            if (lastScan == 0) lastScan = now;
            else if (now - lastScan >= interval) {
                RunScan(settings.deepScan);
                lastScan = GetTickCount64();
            }
        }

        // Просыпаемся раз в минуту: настройку могли поменять, а точность
        // до минуты для суточного расписания более чем достаточна.
        if (WaitForSingleObject(g_stopEvent, 60000) == WAIT_OBJECT_0) break;
    }

    ReportStatus(SERVICE_STOPPED);
    if (g_stopEvent) CloseHandle(g_stopEvent);
}

} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("ThreatScanner");
    QCoreApplication::setApplicationName("ThreatScanner");

    const QStringList arguments = QCoreApplication::arguments();

    if (arguments.contains("--install"))   return Install();
    if (arguments.contains("--uninstall")) return Uninstall();
    if (arguments.contains("--status"))    return Status();

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(ServiceConfig::kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        wprintf(L"this program is a Windows service; "
                L"use --install, --uninstall or --status\n");
        return 1;
    }
    return 0;
}
