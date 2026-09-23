#include "ThreatActions.h"
#include "Logger.h"

#include <Windows.h>

namespace {

std::wstring SeverityToW(Severity s) {
    switch (s) {
        case Severity::Critical: return L"CRIT";
        case Severity::High:     return L"HIGH";
        case Severity::Medium:   return L"MED";
        case Severity::Low:      return L"LOW";
        default:                 return L"INFO";
    }
}

// HKEY -> "HKLM" / "HKCU" / ... для ActionExecutor::RemoveRegistryValue
std::wstring RootPrefix(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER)  return L"HKCU";
    if (root == HKEY_CLASSES_ROOT)  return L"HKCR";
    if (root == HKEY_USERS)         return L"HKU";
    return L"HKLM";
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

ActionResult QuarantineThreat(Threat& t) {
    // Реестр/задача — это не файлы. "Карантин" для них = удаление.
    switch (t.kind) {
        case ThreatKind::RegistryValue: {
            std::wstring full = RootPrefix(t.regRoot) + L"\\" + t.regSubKey;
            return ActionExecutor::RemoveRegistryValue(full, t.regValueName);
        }
        case ThreatKind::ScheduledTask:
            return ActionExecutor::DeleteScheduledTask(t.taskFullPath);

        case ThreatKind::Process:
            ActionExecutor::KillProcess(t.pid);   // сначала убиваем
            [[fallthrough]];
        case ThreatKind::File:
        default: {
            const std::wstring& path = t.filePath.empty() ? t.source : t.filePath;
            auto id = Quarantine::Instance().QuarantineFile(
                path, t.name, SeverityToW(t.severity));
            if (id) return { true, L"Quarantined (id=" +
                             std::wstring(id->begin(), id->end()) + L")" };
            return { false, L"Quarantine failed." };
        }
    }
}

ActionResult DeleteThreat(Threat& t) {
    switch (t.kind) {
        case ThreatKind::RegistryValue: {
            std::wstring full = RootPrefix(t.regRoot) + L"\\" + t.regSubKey;
            return ActionExecutor::RemoveRegistryValue(full, t.regValueName);
        }
        case ThreatKind::ScheduledTask:
            return ActionExecutor::DeleteScheduledTask(t.taskFullPath);

        case ThreatKind::Process:
            ActionExecutor::KillProcess(t.pid);
            [[fallthrough]];
        case ThreatKind::File:
        default: {
            const std::wstring& path = t.filePath.empty() ? t.source : t.filePath;
            return ActionExecutor::RemoveFile(path);
        }
    }
}

} // namespace

ActionResult ApplyThreatAction(Threat& t, int action) {
    ActionResult r;

    if (action == 2) {                       // Ignore
        t.status = ThreatStatus::Ignored;
        r = { true, L"Ignored." };
    } else if (action == 0) {                // Quarantine
        r = QuarantineThreat(t);
        // В карантин реально кладутся только файлы. Для реестра и задач
        // "карантин" — это удаление, и статус не должен обещать обратное.
        const bool storable = (t.kind == ThreatKind::File ||
                               t.kind == ThreatKind::Process);
        t.status = r.success
            ? (storable ? ThreatStatus::Quarantined : ThreatStatus::Deleted)
            : ThreatStatus::Failed;
    } else {                                 // Delete
        r = DeleteThreat(t);
        t.status = r.success ? ThreatStatus::Deleted : ThreatStatus::Failed;
    }

    t.actionMessage = r.message;
    Logger::Instance().Info(
        std::string("[Action] ") +
        (action == 0 ? "QUAR " : action == 1 ? "DEL  " : "IGN  ") +
        WideToUtf8(t.name) + " -> " + WideToUtf8(r.message));
    return r;
}
