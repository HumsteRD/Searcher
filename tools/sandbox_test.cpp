// Проверка слоя песочницы без самой песочницы.
//
// Здесь проверяются две вещи, которые от наличия Windows Sandbox не
// зависят и потому проверяемы на любой редакции:
//   1. отчёт переживает дорогу «структура → JSON → файл → структура»
//      без потерь, включая кириллицу, кавычки и обратные слэши;
//   2. на системе без песочницы сеанс отказывается стартовать и
//      объясняет причину, а не падает и не делает вид, что работает.

#include "core/BehaviorReport.h"
#include "core/BehaviorReportJson.h"
#include "core/SandboxEnvironment.h"
#include "core/SandboxSession.h"
#include "core/BehaviorVerdict.h"

#include <QCoreApplication>
#include <QDir>

#include <Windows.h>
#include <cstdio>
#include <string>

namespace {

int g_failures = 0;

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

void Check(bool ok, const char* what) {
    printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++g_failures;
}

void CheckEqual(const std::wstring& actual, const std::wstring& expected,
                const char* what)
{
    const bool ok = (actual == expected);
    printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) {
        printf("        expected: %s\n", Utf8(expected).c_str());
        printf("        actual  : %s\n", Utf8(actual).c_str());
        ++g_failures;
    }
}

// Отчёт со всем, обо что обычно спотыкается ручная сборка JSON.
BehaviorReport MakeAwkwardReport() {
    BehaviorReport report;
    report.target        = L"C:\\Users\\Дмитрий\\Загрузки\\счёт \"важный\".exe";
    report.arguments     = L"--path \"C:\\tmp\\a b\" --tab\tseparated";
    report.durationMs    = 12345;
    report.timedOut      = true;
    report.killed        = true;
    report.launchFailed  = false;
    report.failureReason = L"";
    report.rootExitCode  = 3221225477u;   // 0xC0000005, больше INT_MAX

    ObservedProcess root;
    root.pid = 4242;
    root.parentPid = 17;
    root.image = L"C:\\sample\\счёт.exe";
    root.commandLine = L"\"C:\\sample\\счёт.exe\" /квартал:4";
    root.startedAtMs = 5;
    root.exitedAtMs = 900;
    root.exitCode = 7;
    root.isRoot = true;
    report.processes.push_back(root);

    ObservedProcess child;
    child.pid = 4243;
    child.parentPid = 4242;
    child.image = L"C:\\Windows\\System32\\cmd.exe";
    child.startedAtMs = 120;
    child.exitedAtMs = -1;          // не завершился к концу наблюдения
    report.processes.push_back(child);

    BehaviorEvent file;
    file.type = BehaviorEventType::FileCreated;
    file.atMs = 30;
    file.pid = 0;
    file.target = L"C:\\Users\\Дмитрий\\AppData\\Local\\Temp\\полезная\\нагрузка.dll";
    file.detail = L"перенос\nстроки и \"кавычки\"";
    report.events.push_back(file);

    BehaviorEvent registry;
    registry.type = BehaviorEventType::RegistryValueChanged;
    registry.atMs = 640;
    registry.target = L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|Обновление";
    registry.detail = L"старое -> новое";
    report.events.push_back(registry);

    BehaviorEvent network;
    network.type = BehaviorEventType::NetworkConnection;
    network.atMs = 900;
    network.pid = 4242;
    network.target = L"203.0.113.7:443";
    network.detail = L"TCP, established";
    report.events.push_back(network);

    report.limitations.push_back(L"Ядра нет — внедрение в память не видно.");
    report.limitations.push_back(L"Backslash \\ and quote \" survive too.");
    return report;
}

void TestJsonRoundTrip() {
    printf("--- report round trip ---\n");

    const BehaviorReport original = MakeAwkwardReport();
    const std::wstring path =
        (QDir::tempPath() + "/ts-sandbox-roundtrip.json").toStdWString();

    std::wstring error;
    if (!WriteBehaviorReportJson(original, path, &error)) {
        Check(false, "report written");
        printf("        %s\n", Utf8(error).c_str());
        return;
    }
    Check(true, "report written");

    BehaviorReport restored;
    if (!SandboxSession::ReadReportJson(path, restored, &error)) {
        Check(false, "report parsed back");
        printf("        %s\n", Utf8(error).c_str());
        DeleteFileW(path.c_str());
        return;
    }
    Check(true, "report parsed back");

    CheckEqual(restored.target, original.target, "target survived");
    CheckEqual(restored.arguments, original.arguments, "arguments survived");
    Check(restored.durationMs == original.durationMs, "duration survived");
    Check(restored.timedOut == original.timedOut, "timedOut survived");
    Check(restored.killed == original.killed, "killed survived");
    Check(restored.rootExitCode == original.rootExitCode,
          "exit code above INT_MAX survived");

    Check(restored.processes.size() == original.processes.size(),
          "process count survived");
    if (restored.processes.size() == original.processes.size()) {
        for (size_t i = 0; i < restored.processes.size(); ++i) {
            const auto& a = restored.processes[i];
            const auto& b = original.processes[i];
            Check(a.pid == b.pid && a.parentPid == b.parentPid &&
                  a.startedAtMs == b.startedAtMs &&
                  a.exitedAtMs == b.exitedAtMs &&
                  a.exitCode == b.exitCode && a.isRoot == b.isRoot,
                  "process numbers survived");
            CheckEqual(a.image, b.image, "process image survived");
            CheckEqual(a.commandLine, b.commandLine, "command line survived");
        }
    }

    Check(restored.events.size() == original.events.size(),
          "event count survived");
    if (restored.events.size() == original.events.size()) {
        for (size_t i = 0; i < restored.events.size(); ++i) {
            const auto& a = restored.events[i];
            const auto& b = original.events[i];
            Check(a.type == b.type && a.atMs == b.atMs && a.pid == b.pid,
                  "event type and numbers survived");
            CheckEqual(a.target, b.target, "event target survived");
            CheckEqual(a.detail, b.detail, "event detail survived");
        }
    }

    Check(restored.limitations == original.limitations,
          "limitations survived");

    // Неизвестный тип события: отчёт от более новой версии агента не
    // должен ни ронять разбор, ни тихо исчезать.
    BehaviorReport newer;
    newer.events.push_back(BehaviorEvent{});
    std::string json = BehaviorReportToJson(newer);
    const std::string from = "\"type\": \"monitor_note\"";
    const std::string to   = "\"type\": \"quantum_tunnelling\"";
    if (auto pos = json.find(from); pos != std::string::npos)
        json.replace(pos, from.size(), to);

    FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"wb") == 0 && file) {
        fwrite(json.data(), 1, json.size(), file);
        fclose(file);

        BehaviorReport unknown;
        const bool parsed = SandboxSession::ReadReportJson(path, unknown, &error);
        Check(parsed && unknown.events.size() == 1,
              "unknown event type does not break parsing");
        if (parsed && unknown.events.size() == 1) {
            Check(unknown.events[0].detail.find(L"quantum_tunnelling")
                      != std::wstring::npos,
                  "unknown event type is kept visible");
        }
    }

    DeleteFileW(path.c_str());
}

void TestSessionOnThisMachine() {
    printf("\n--- session on this machine ---\n");

    const auto& environment = SandboxEnvironment::Get();
    printf("  edition: %s\n", Utf8(environment.editionName).c_str());

    SandboxSession::Options options;
    options.samplePath = QCoreApplication::applicationFilePath().toStdWString();
    options.observeTimeoutMs = 5000;
    options.waitForReportMs  = 5000;

    CancelToken cancel;
    SandboxSession session;
    const auto outcome = session.Run(options, cancel);

    if (environment.status == SandboxEnvironment::Status::Available) {
        // Здесь этой ветки не будет, но на машине с Pro проверка должна
        // говорить о деле, а не молчать.
        printf("  sandbox is available: session result %d\n",
               static_cast<int>(outcome.result));
        Check(outcome.result != SandboxSession::Result::Unavailable,
              "session did not report the sandbox as missing");
        return;
    }

    Check(outcome.result == SandboxSession::Result::Unavailable,
          "session refuses to start without a sandbox");
    Check(!outcome.message.empty(), "refusal explains why");
    printf("  reason: %s\n", Utf8(outcome.message).c_str());

    if (environment.status == SandboxEnvironment::Status::NotOnThisEdition) {
        Check(outcome.howToFix.empty(),
              "no false promise of a fix on Home editions");
    }

    // Ничего не запускалось — значит и мусора остаться не должно.
    Check(outcome.workFolder.empty() ||
              !QDir(QString::fromStdWString(outcome.workFolder)).exists(),
          "no work folder left behind");
}

// ─── Вердикт по поведению ───────────────────────────────────────────────

BehaviorEvent MakeEvent(BehaviorEventType type, const wchar_t* target,
                        const wchar_t* detail = L"", DWORD pid = 0)
{
    BehaviorEvent event;
    event.type   = type;
    event.target = target;
    event.detail = detail;
    event.pid    = pid;
    return event;
}

ObservedProcess MakeProcess(DWORD pid, const wchar_t* image,
                            const wchar_t* commandLine)
{
    ObservedProcess process;
    process.pid = pid;
    process.parentPid = 1000;
    process.image = image;
    process.commandLine = commandLine;
    return process;
}

void TestVerdict() {
    printf("\n--- behaviour verdict ---\n");

    // Тихий образец: пара файлов в %TEMP% и соединение с самим собой.
    // Это поведение половины установщиков, приговором быть не должно.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\setup.exe";
        report.events.push_back(MakeEvent(BehaviorEventType::FileModified,
            L"C:\\Users\\u\\AppData\\Local\\Temp\\setup.log"));
        report.events.push_back(MakeEvent(BehaviorEventType::NetworkConnection,
            L"127.0.0.1:5000", L"TCP, established", 42));

        const auto verdict = JudgeBehavior(report);
        Check(verdict.severity == Severity::Info && verdict.score == 0,
              "quiet sample is not accused");
        Check(verdict.summary.find(L"not proof") != std::wstring::npos,
              "empty result is not sold as a clean bill of health");
    }

    // Закрепление плюс сброшенный исполняемый файл — это уже поведение,
    // за которое надо ругаться.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\dropper.exe";
        report.events.push_back(MakeEvent(BehaviorEventType::RegistryValueSet,
            L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|Updater",
            L"C:\\Users\\u\\AppData\\Roaming\\svc.exe"));
        report.events.push_back(MakeEvent(BehaviorEventType::FileCreated,
            L"C:\\Users\\u\\AppData\\Roaming\\svc.exe"));

        const auto verdict = JudgeBehavior(report);
        Check(verdict.score == 8, "autorun plus dropped executable scores 8");
        Check(verdict.severity == Severity::High, "that combination reads as high");
        Check(verdict.findings.size() == 2, "both findings are listed");
        Check(!verdict.findings.empty() &&
                  verdict.findings[0].weight >= verdict.findings.back().weight,
              "findings are ordered by weight");
    }

    // Подмена отладчика не становится безобидной оттого, что она одна.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\x.exe";
        report.events.push_back(MakeEvent(BehaviorEventType::RegistryValueSet,
            L"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\"
            L"Image File Execution Options\\taskmgr.exe|Debugger",
            L"C:\\Users\\u\\AppData\\Local\\Temp\\x.exe"));

        const auto verdict = JudgeBehavior(report);
        Check(verdict.severity == Severity::Critical,
              "a single unambiguous finding still reads as critical");
    }

    // conhost прилагается к каждой консольной программе и уликой не является,
    // а powershell со скрытой закодированной командой — является.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\x.exe";
        report.processes.push_back(
            MakeProcess(2, L"C:\\Windows\\System32\\conhost.exe",
                        L"conhost.exe 0xffffffff -ForceV1"));

        auto quiet = JudgeBehavior(report);
        Check(quiet.score == 0, "conhost alone is not evidence");

        report.processes.push_back(
            MakeProcess(3, L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                           L"powershell.exe",
                        L"powershell.exe -w hidden -enc SQBFAFgA"));

        auto loud = JudgeBehavior(report);
        Check(loud.score == 9 && loud.severity == Severity::High,
              "hidden encoded powershell is evidence");
    }

    // Соединение внутри локальной сети — не выход наружу.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\x.exe";
        report.events.push_back(MakeEvent(BehaviorEventType::NetworkConnection,
            L"192.168.1.10:445", L"TCP, established", 7));
        Check(JudgeBehavior(report).score == 0, "LAN address is not an outside address");

        report.events.push_back(MakeEvent(BehaviorEventType::NetworkConnection,
            L"203.0.113.7:443", L"TCP, established", 7));
        Check(JudgeBehavior(report).score == 3, "public address counts once");
    }

    // Угроза заводится по файлу на хосте, а не по пути внутри песочницы:
    // карантину нужен файл, который выбрал пользователь.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\dropper.exe";   // путь ВНУТРИ песочницы
        report.events.push_back(MakeEvent(BehaviorEventType::RegistryValueSet,
            L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|Updater",
            L"C:\\Users\\u\\AppData\\Roaming\\svc.exe"));
        report.events.push_back(MakeEvent(BehaviorEventType::FileCreated,
            L"C:\\Users\\u\\AppData\\Roaming\\svc.exe"));

        const auto verdict = JudgeBehavior(report);
        Check(VerdictWarrantsThreat(verdict), "high verdict becomes a threat");

        const std::wstring hostPath = L"D:\\Downloads\\счёт.exe";
        const Threat threat = ThreatFromBehaviour(hostPath, report, verdict);

        CheckEqual(threat.filePath, hostPath, "threat points at the host file");
        CheckEqual(threat.name, L"счёт.exe", "threat is named after the host file");
        Check(threat.severity == verdict.severity, "severity carried over");
        bool namesAutorun = false;
        for (const std::string& r : threat.reasons)
            if (r.find("behavior.finding") == 0 && r.find("autorun") != std::string::npos)
                namesAutorun = true;
        Check(namesAutorun, "reasons name what it did");
    }

    // Слабый вердикт угрозой не становится: ложное срабатывание дороже.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\setup.exe";
        report.events.push_back(MakeEvent(BehaviorEventType::NetworkListen,
            L"0.0.0.0:8080", L"TCP", 9));

        Check(!VerdictWarrantsThreat(JudgeBehavior(report)),
              "a single light finding is not a threat");
    }

    // Не запустился — значит и судить не о чем.
    {
        BehaviorReport report;
        report.target = L"C:\\sample\\broken.exe";
        report.launchFailed = true;
        report.events.push_back(MakeEvent(BehaviorEventType::RegistryValueSet,
            L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|X", L"y"));

        const auto verdict = JudgeBehavior(report);
        Check(verdict.severity == Severity::Info && verdict.findings.empty(),
              "a sample that never started is not judged");
    }
}

} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("ThreatScanner");
    QCoreApplication::setApplicationName("ThreatScanner");
    SetConsoleOutputCP(CP_UTF8);

    TestJsonRoundTrip();
    TestVerdict();
    TestSessionOnThisMachine();

    printf("\n%s (%d failed)\n",
           g_failures ? "FAILURES" : "ALL CHECKS PASSED", g_failures);
    return g_failures == 0 ? 0 : 1;
}
