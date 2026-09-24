#include "ThreatActions.h"
#include "Logger.h"

#include <Windows.h>

#include <filesystem>

namespace {

std::wstring SeverityCode(Severity s) {
    switch (s) {
        case Severity::Critical: return L"CRIT";
        case Severity::High:     return L"HIGH";
        case Severity::Medium:   return L"MED";
        case Severity::Low:      return L"LOW";
        default:                 return L"INFO";
    }
}

std::wstring RootPrefix(HKEY root) {
    if (root == HKEY_CURRENT_USER) return L"HKCU";
    if (root == HKEY_CLASSES_ROOT) return L"HKCR";
    if (root == HKEY_USERS)        return L"HKU";
    return L"HKLM";
}

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n,
                        nullptr, nullptr);
    return out;
}

std::wstring DisplayName(const Threat& t) {
    if (!t.family.empty()) return std::wstring(t.family.begin(), t.family.end());
    if (!t.summary.empty()) return t.summary;
    return t.name;
}

// Запускаемый файл в карантин. Пустой путь или отсутствующий файл —
// не ошибка: запись автозапуска могла ссылаться на уже удалённое.
ActionResult QuarantineTarget(const Threat& t, bool* pendingReboot) {
    std::error_code ec;
    if (t.filePath.empty() || !std::filesystem::exists(t.filePath, ec))
        return { false, L"missing" };
    auto id = Quarantine::Instance().QuarantineFile(t.filePath, DisplayName(t), SeverityCode(t.severity));
    if (!id) return { false, L"denied" };
    if (pendingReboot) *pendingReboot = Quarantine::Instance().LastPendingReboot();
    return { true, L"quarantined" };
}

ActionResult DeleteTarget(const Threat& t) {
    if (t.filePath.empty()) return { false, L"missing" };
    return ActionExecutor::RemoveFile(t.filePath);
}

// Убрать саму запись: значение реестра, задачу, службу, подписку, строку.
ActionResult RemoveEntry(const Threat& t) {
    switch (t.kind) {
    case ThreatKind::RegistryValue:
        return ActionExecutor::RemoveRegistryValue(RootPrefix(t.regRoot) + L"\\" + t.regSubKey,
                                                   t.regValueName);
    case ThreatKind::ScheduledTask: return ActionExecutor::DeleteScheduledTask(t.taskFullPath);
    case ThreatKind::Service:       return ActionExecutor::DisableService(t.serviceName);
    case ThreatKind::WmiConsumer:   return ActionExecutor::RemoveWmiConsumer(t.wmiConsumerPath);
    case ThreatKind::HostsEntry:    return ActionExecutor::RemoveHostsLine(t.hostsLine);
    default:                        return { false, L"unsupported" };
    }
}

} // namespace

ActionResult ApplyThreatAction(Threat& t, int action) {
    ActionResult r;

    if (action == 2) {
        t.status = ThreatStatus::Ignored;
        r = { true, L"ignored" };
    } else if (t.kind == ThreatKind::File || t.kind == ThreatKind::Process) {
        // Процесс сначала останавливаем: запущенный файл не удалить.
        if (t.kind == ThreatKind::Process && t.pid) {
            ActionExecutor::KillProcess(t.pid);
            Sleep(300);
        }
        bool reboot = false;
        r = action == 0 ? QuarantineTarget(t, &reboot) : DeleteTarget(t);
        if (r.success && reboot) r.message = L"quarantined-reboot";
        t.status = r.success ? (action == 0 ? ThreatStatus::Quarantined : ThreatStatus::Deleted)
                             : ThreatStatus::Failed;
    } else {
        // Запись автозапуска, задача, служба, WMI, hosts: сама запись
        // убирается (служба — отключается), а запускаемый ею файл, если он
        // опознан как вредоносный, идёт в карантин или удаляется.
        r = RemoveEntry(t);
        if (r.success && !t.filePath.empty()) {
            bool reboot = false;
            const ActionResult f = action == 0 ? QuarantineTarget(t, &reboot) : DeleteTarget(t);
            if (f.success) r.message += action == 0 ? (reboot ? L"+quarantined-reboot" : L"+quarantined")
                                                    : L"+deleted";
            else if (f.message != L"missing") r.message += L"+file-failed";
        }
        t.status = !r.success ? ThreatStatus::Failed
                 : t.kind == ThreatKind::Service ? ThreatStatus::Disabled
                 : ThreatStatus::Deleted;
    }

    t.actionMessage = r.message;
    Logger::Instance().Info(std::string("[Action] ") +
                            (action == 0 ? "quarantine " : action == 1 ? "delete " : "ignore ") +
                            Utf8(t.source) + " -> " + Utf8(r.message));
    return r;
}
