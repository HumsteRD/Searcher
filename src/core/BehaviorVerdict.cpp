#include "BehaviorVerdict.h"
#include "Hasher.h"

#include <algorithm>
#include <cwctype>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

// Порог, после которого поведение считается вредоносным. Подобран так,
// чтобы одиночная улика среднего веса его не брала: установщик, который
// пишет файл в %TEMP% и открывает соединение, наберёт 6 и остановится
// на «стоит посмотреть», а не на приговоре.
constexpr int kMaliciousScore = 10;
constexpr int kSuspiciousScore = 6;

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

bool Contains(const std::wstring& haystack, const wchar_t* needle) {
    return haystack.find(needle) != std::wstring::npos;
}

bool EndsWith(const std::wstring& text, const wchar_t* suffix) {
    const std::wstring s(suffix);
    return text.size() >= s.size() &&
           text.compare(text.size() - s.size(), s.size(), s) == 0;
}

bool IsExecutableName(const std::wstring& lowerPath) {
    static const wchar_t* kExtensions[] = {
        L".exe", L".dll", L".scr", L".sys", L".bat", L".cmd",
        L".ps1", L".vbs", L".js",  L".jse", L".wsf", L".hta", L".lnk",
    };
    for (const wchar_t* extension : kExtensions)
        if (EndsWith(lowerPath, extension)) return true;
    return false;
}

// Программы, которыми пользуются, чтобы не приносить свой код: они есть
// в каждой Windows и потому не вызывают подозрений сами по себе.
bool IsLivingOffTheLand(const std::wstring& lowerImage) {
    static const wchar_t* kNames[] = {
        L"powershell.exe", L"pwsh.exe", L"wscript.exe", L"cscript.exe",
        L"mshta.exe", L"rundll32.exe", L"regsvr32.exe", L"certutil.exe",
        L"bitsadmin.exe", L"installutil.exe", L"msbuild.exe",
        L"schtasks.exe", L"vssadmin.exe", L"wmic.exe",
    };
    const std::wstring name = ToLower(fs::path(lowerImage).filename().wstring());
    for (const wchar_t* known : kNames)
        if (name == known) return true;
    return false;
}

// Адрес за пределами машины и локальной сети. Соединение с самим собой
// или с роутером уликой не является.
bool IsExternalAddress(const std::wstring& target) {
    if (target.empty()) return false;
    if (Contains(target, L"127.0.0.1") || Contains(target, L"[::1]")) return false;
    if (target.rfind(L"10.", 0) == 0) return false;
    if (target.rfind(L"192.168.", 0) == 0) return false;
    if (target.rfind(L"169.254.", 0) == 0) return false;
    if (target.rfind(L"[fe80", 0) == 0) return false;

    if (target.rfind(L"172.", 0) == 0) {
        const size_t dot = target.find(L'.', 4);
        if (dot != std::wstring::npos) {
            const int second = _wtoi(target.substr(4, dot - 4).c_str());
            if (second >= 16 && second <= 31) return false;
        }
    }
    return true;
}

// Улика с накоплением: сам факт важен один раз, но примеры полезны.
struct Evidence {
    bool         hit = false;
    int          count = 0;
    std::wstring first;

    void note(const std::wstring& sample) {
        ++count;
        if (!hit) { hit = true; first = sample; }
    }

    std::wstring detail() const {
        if (count <= 1) return first;
        return first + L"  (+" + std::to_wstring(count - 1) + L" more)";
    }
};

} // namespace

BehaviorVerdict JudgeBehavior(const BehaviorReport& report) {
    BehaviorVerdict verdict;

    const std::wstring sampleName =
        ToLower(fs::path(report.target).filename().wstring());

    Evidence autorun, winlogon, ifeo, service, startup, hosts, driver;
    Evidence dropped, lolbin, hiddenShell, external, listening, selfDelete;

    for (const auto& event : report.events) {
        const std::wstring target = ToLower(event.target);
        const std::wstring detail = ToLower(event.detail);

        switch (event.type) {
        case BehaviorEventType::RegistryValueSet:
        case BehaviorEventType::RegistryValueChanged:
            if (Contains(target, L"currentversion\\run") ||
                Contains(target, L"policies\\explorer\\run")) {
                autorun.note(event.target + L"  =  " + event.detail);
            }
            if (Contains(target, L"winlogon") &&
                (Contains(target, L"|shell") || Contains(target, L"|userinit"))) {
                winlogon.note(event.target + L"  =  " + event.detail);
            }
            if (Contains(target, L"image file execution options") &&
                Contains(target, L"|debugger")) {
                ifeo.note(event.target + L"  =  " + event.detail);
            }
            break;

        case BehaviorEventType::RegistryKeyCreated:
            if (Contains(target, L"currentcontrolset\\services\\"))
                service.note(event.target);
            break;

        case BehaviorEventType::FileCreated:
        case BehaviorEventType::FileModified:
        case BehaviorEventType::FileRenamed:
            if (Contains(target, L"\\start menu\\programs\\startup\\"))
                startup.note(event.target);
            else if (EndsWith(target, L"\\drivers\\etc\\hosts"))
                hosts.note(event.target);
            else if (Contains(target, L"\\system32\\drivers\\") &&
                     EndsWith(target, L".sys"))
                driver.note(event.target);
            else if (event.type == BehaviorEventType::FileCreated &&
                     IsExecutableName(target)) {
                dropped.note(event.target);
            }
            break;

        case BehaviorEventType::FileDeleted:
            if (!sampleName.empty() && EndsWith(target, (L"\\" + sampleName).c_str()))
                selfDelete.note(event.target);
            break;

        case BehaviorEventType::NetworkConnection:
            if (IsExternalAddress(event.target))
                external.note(event.target + L"  " + event.detail);
            break;

        case BehaviorEventType::NetworkListen:
            listening.note(event.target + L"  " + event.detail);
            break;

        default:
            break;
        }
        (void)detail;
    }

    for (const auto& process : report.processes) {
        if (process.isRoot) continue;

        const std::wstring image = ToLower(process.image);
        const std::wstring command = ToLower(process.commandLine);

        // conhost прилагается к любой консольной программе — он не улика.
        if (EndsWith(image, L"\\conhost.exe")) continue;

        if (IsLivingOffTheLand(image))
            lolbin.note(process.image + L"  " + process.commandLine);

        if (Contains(command, L"-enc") || Contains(command, L"encodedcommand") ||
            Contains(command, L"frombase64string") ||
            Contains(command, L"-w hidden") ||
            Contains(command, L"windowstyle hidden") ||
            Contains(command, L"-nop") || Contains(command, L"noprofile")) {
            hiddenShell.note(process.commandLine);
        }
    }

    auto add = [&](const Evidence& evidence, Severity severity, int weight,
                   const wchar_t* title) {
        if (!evidence.hit) return;
        verdict.findings.push_back(
            BehaviorFinding{ severity, weight, title, evidence.detail() });
        verdict.score += weight;
    };

    // Вес — это цена ошибки. Подмена отладчика или драйвер в system32
    // не бывают побочным эффектом установки; файл в %TEMP% бывает всегда.
    add(ifeo,        Severity::Critical, 8, L"Hijacked the launch of another program");
    add(winlogon,    Severity::Critical, 8, L"Replaced a system logon component");
    add(driver,      Severity::Critical, 8, L"Dropped a driver into the system folder");
    add(hosts,       Severity::High,     6, L"Rewrote the hosts file");
    add(service,     Severity::High,     6, L"Registered a Windows service");
    add(startup,     Severity::High,     5, L"Placed a file into the startup folder");
    add(autorun,     Severity::High,     5, L"Added an autorun entry");
    add(hiddenShell, Severity::High,     5, L"Started a hidden or encoded command");
    add(lolbin,      Severity::Medium,   4, L"Used a built-in Windows tool to run code");
    add(selfDelete,  Severity::Medium,   3, L"Deleted itself after running");
    add(external,    Severity::Medium,   3, L"Connected to an outside address");
    add(dropped,     Severity::Medium,   3, L"Wrote an executable file");
    add(listening,   Severity::Low,      2, L"Opened a port for incoming connections");

    if (report.processes.size() > 10) {
        verdict.findings.push_back(BehaviorFinding{
            Severity::Low, 2, L"Started an unusual number of processes",
            std::to_wstring(report.processes.size()) + L" processes" });
        verdict.score += 2;
    }

    std::stable_sort(verdict.findings.begin(), verdict.findings.end(),
                     [](const BehaviorFinding& a, const BehaviorFinding& b) {
                         return a.weight > b.weight;
                     });

    // Уровень берётся по сумме, но одиночная безусловная улика тянет
    // вердикт вверх сама: подменённый отладчик не становится безобидным
    // оттого, что больше ничего не случилось.
    Severity fromScore = Severity::Info;
    if (verdict.score >= kMaliciousScore)       fromScore = Severity::Critical;
    else if (verdict.score >= kSuspiciousScore) fromScore = Severity::High;
    else if (verdict.score > 0)                 fromScore = Severity::Low;

    Severity fromFindings = Severity::Info;
    for (const auto& finding : verdict.findings)
        fromFindings = std::max(fromFindings, finding.severity);

    verdict.severity = std::max(fromScore, fromFindings);

    switch (verdict.severity) {
    case Severity::Critical:
        verdict.summary = L"This behaviour is typical of malware.";
        break;
    case Severity::High:
        verdict.summary = L"The file did things that ordinary programs rarely do.";
        break;
    case Severity::Medium:
    case Severity::Low:
        verdict.summary = L"Some activity was observed, none of it typical of malware.";
        break;
    default:
        // Пустой результат — это не справка о безопасности. Образец мог
        // ждать перезагрузки, проверять, не следят ли за ним, или просто
        // делать то, чего наблюдение не видит.
        verdict.summary = L"Nothing notable happened while it was watched. "
                          L"That is not proof the file is safe.";
        break;
    }

    if (report.launchFailed) {
        verdict.severity = Severity::Info;
        verdict.score = 0;
        verdict.findings.clear();
        verdict.summary = L"The sample did not start, so there was nothing to watch.";
    }

    return verdict;
}

bool VerdictWarrantsThreat(const BehaviorVerdict& verdict) {
    return verdict.severity >= Severity::High && !verdict.findings.empty();
}

Threat ThreatFromBehaviour(const std::wstring& hostPath,
                           const BehaviorReport& report,
                           const BehaviorVerdict& verdict)
{
    Threat threat;
    threat.kind     = ThreatKind::File;
    threat.severity = verdict.severity;
    threat.name     = fs::path(hostPath).filename().wstring();
    threat.source   = hostPath;
    threat.filePath = hostPath;
    threat.summary  = verdict.summary;

    // Причины — кодами: текст строит интерфейс. Заголовки улик уже
    // человеческие, но английские — интерфейс переводит их по словарю.
    threat.reasons.push_back("behavior");
    for (const auto& f : verdict.findings) {
        std::string title;
        for (wchar_t c : f.title) title += c < 128 ? static_cast<char>(c) : '?';
        threat.reasons.push_back("behavior.finding\t" + title);
    }
    if (report.timedOut) threat.reasons.push_back("behavior.timeout");

    // Хэш нужен для проверки в VirusTotal: файл лежит у пользователя.
    if (auto sha = Hasher::Sha256File(hostPath); sha.has_value()) threat.sha256 = *sha;
    return threat;
}
