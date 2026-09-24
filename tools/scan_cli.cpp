// Полная проверка из командной строки — те же модули и тот же Scanner,
// что работают в помощнике, но без канала и без интерфейса. Нужна для
// замеров на реальной системе: что находит каждый модуль и сколько
// длится. Без прав администратора часть объектов не читается — это видно
// по журналу.
//
//   scan_cli [--quick | --full | --path <папка>] [--modules files,processes,...]

#include "core/AutorunScanner.h"
#include "core/FileSystemScanner.h"
#include "core/Logger.h"
#include "core/NetworkScanner.h"
#include "core/PersistenceScanner.h"
#include "core/ProcessScanner.h"
#include "core/Scanner.h"
#include "core/TaskSchedulerScanner.h"
#include "core/ThreatJson.h"

#include <QCoreApplication>
#include <QJsonDocument>

#include <Windows.h>

#include <cstdio>
#include <memory>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    SetConsoleOutputCP(CP_UTF8);

    ScanConfig config;
    config.mode = ScanConfig::Mode::Quick;
    const QStringList args = app.arguments();
    for (int i = 1; i < args.size(); ++i) {
        if (args[i] == "--full") config.mode = ScanConfig::Mode::Full;
        else if (args[i] == "--path" && i + 1 < args.size()) {
            config.mode = ScanConfig::Mode::Custom;
            config.paths.push_back(args[++i].toStdWString());
        } else if (args[i] == "--modules" && i + 1 < args.size()) {
            const QStringList on = args[++i].split(',');
            const char* names[] = { "files", "processes", "autoruns", "tasks", "services", "network" };
            for (int m = 0; m < ScanConfig::ModuleCount; ++m) config.modules[m] = on.contains(names[m]);
        }
    }

    Scanner scanner;
    scanner.RegisterModule(std::make_shared<ProcessScanner>());
    scanner.RegisterModule(std::make_shared<AutorunScanner>());
    scanner.RegisterModule(std::make_shared<TaskSchedulerScanner>());
    scanner.RegisterModule(std::make_shared<PersistenceScanner>());
    scanner.RegisterModule(std::make_shared<NetworkScanner>());
    scanner.RegisterModule(std::make_shared<FileSystemScanner>());
    scanner.Start(config);

    size_t logSeen = 0;
    int lastPercent = -2;
    std::string lastStage;
    while (scanner.State() != ScanState::Done) {
        Sleep(250);
        for (const LogEntry& e : Logger::Instance().Since(logSeen))
            if (e.level >= LogLevel::Info) std::printf("  %s\n", e.message.c_str());
        logSeen = Logger::Instance().TotalWritten();
        const ScanStats s = scanner.Stats();
        if (s.progressPercent != lastPercent || s.currentStage != lastStage) {
            std::printf("[%3d%%] %-10s objects %lld, elapsed %d s, eta %d s\n", s.progressPercent,
                        s.currentStage.c_str(), s.objectsScanned, s.elapsedMs / 1000,
                        s.etaMs < 0 ? -1 : s.etaMs / 1000);
            lastPercent = s.progressPercent;
            lastStage = s.currentStage;
        }
    }
    for (const LogEntry& e : Logger::Instance().Since(logSeen))
        if (e.level >= LogLevel::Info) std::printf("  %s\n", e.message.c_str());

    const ScanStats s = scanner.Stats();
    const auto threats = scanner.Snapshot();
    std::printf("\n=== %zu findings, %lld objects, %d s ===\n", threats.size(), s.objectsScanned,
                s.elapsedMs / 1000);
    for (const Threat& t : threats) {
        const QByteArray json = QJsonDocument(ThreatJson::ToJson(t)).toJson(QJsonDocument::Indented);
        std::printf("%s\n", json.constData());
    }
    return 0;
}
