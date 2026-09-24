#include "TaskSchedulerScanner.h"
#include "CommandTarget.h"
#include "Detections.h"
#include "Logger.h"

#include "../engine/FileAnalyzer.h"

#include <Windows.h>
#include <comdef.h>
#include <taskschd.h>

#include <vector>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

using Detections::Reason;
using Detections::Utf8;

namespace {

struct TaskAction {
    std::wstring taskPath;
    std::wstring taskName;
    std::wstring command;     // путь + аргументы
    bool         enabled = true;
};

std::wstring Bstr(BSTR b) { return b ? std::wstring(b, SysStringLen(b)) : std::wstring(); }

void CollectActions(ITaskFolder* folder, std::vector<TaskAction>& out, CancelToken& cancel, int depth) {
    if (!folder || cancel.IsCancelled() || depth > 16) return;

    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count && !cancel.IsCancelled(); ++i) {
            IRegisteredTask* task = nullptr;
            if (FAILED(tasks->get_Item(_variant_t(i), &task)) || !task) continue;

            BSTR name = nullptr, path = nullptr;
            task->get_Name(&name);
            task->get_Path(&path);
            VARIANT_BOOL enabled = VARIANT_TRUE;
            task->get_Enabled(&enabled);

            ITaskDefinition* def = nullptr;
            IActionCollection* actions = nullptr;
            if (SUCCEEDED(task->get_Definition(&def)) && def &&
                SUCCEEDED(def->get_Actions(&actions)) && actions)
            {
                LONG n = 0;
                actions->get_Count(&n);
                for (LONG k = 1; k <= n; ++k) {
                    IAction* action = nullptr;
                    if (FAILED(actions->get_Item(k, &action)) || !action) continue;
                    TASK_ACTION_TYPE type{};
                    action->get_Type(&type);
                    if (type == TASK_ACTION_EXEC) {
                        IExecAction* exec = nullptr;
                        if (SUCCEEDED(action->QueryInterface(IID_IExecAction,
                                                             reinterpret_cast<void**>(&exec))) && exec) {
                            BSTR p = nullptr, a = nullptr;
                            exec->get_Path(&p);
                            exec->get_Arguments(&a);
                            TaskAction ta;
                            ta.taskPath = Bstr(path);
                            ta.taskName = Bstr(name);
                            std::wstring exe = Bstr(p);
                            if (!exe.empty() && exe.front() != L'"' && exe.find(L' ') != std::wstring::npos)
                                exe = L"\"" + exe + L"\"";
                            ta.command = exe + (a && SysStringLen(a) ? L" " + Bstr(a) : L"");
                            ta.enabled = enabled != VARIANT_FALSE;
                            out.push_back(std::move(ta));
                            if (p) SysFreeString(p);
                            if (a) SysFreeString(a);
                            exec->Release();
                        }
                    }
                    action->Release();
                }
                actions->Release();
            }
            if (def) def->Release();
            if (name) SysFreeString(name);
            if (path) SysFreeString(path);
            task->Release();
        }
        tasks->Release();
    }

    ITaskFolderCollection* subs = nullptr;
    if (SUCCEEDED(folder->GetFolders(0, &subs)) && subs) {
        LONG count = 0;
        subs->get_Count(&count);
        for (LONG i = 1; i <= count && !cancel.IsCancelled(); ++i) {
            ITaskFolder* sub = nullptr;
            if (SUCCEEDED(subs->get_Item(_variant_t(i), &sub)) && sub) {
                CollectActions(sub, out, cancel, depth + 1);
                sub->Release();
            }
        }
        subs->Release();
    }
}

} // namespace

void TaskSchedulerScanner::Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) {
    const HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    std::vector<TaskAction> actions;
    ITaskService* service = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_ITaskService, reinterpret_cast<void**>(&service))) && service)
    {
        if (SUCCEEDED(service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
            ITaskFolder* root = nullptr;
            if (SUCCEEDED(service->GetFolder(_bstr_t(L"\\"), &root)) && root) {
                CollectActions(root, actions, cancel, 0);
                root->Release();
            }
        } else {
            Logger::Instance().Error("[Tasks] cannot connect to the Task Scheduler");
        }
        service->Release();
    }
    Logger::Instance().Info("[Tasks] " + std::to_string(actions.size()) + " task actions");

    FileAnalyzer::Options opt;
    opt.reportPua = config.reportPua;
    long long checked = 0;

    for (size_t i = 0; i < actions.size() && !cancel.IsCancelled(); ++i) {
        const TaskAction& a = actions[i];
        sink.Progress("Tasks", static_cast<int>(100 * i / std::max<size_t>(actions.size(), 1)));
        sink.Item(a.taskPath);
        sink.Checked(++checked);

        Threat t;
        t.kind = ThreatKind::ScheduledTask;
        t.name = a.taskName;
        t.source = a.taskPath;
        t.taskFullPath = a.taskPath;
        t.evidence = a.command;

        bool flagged = false;
        const CommandTarget::Parsed parsed = CommandTarget::Parse(a.command);
        std::vector<std::wstring> targets;
        if (!parsed.executable.empty()) targets.push_back(parsed.executable);
        targets.insert(targets.end(), parsed.payloads.begin(), parsed.payloads.end());

        for (const std::wstring& target : targets) {
            if (config.IsExcludedPath(target)) continue;
            const Verdict v = FileAnalyzer::Analyze(target, opt);
            if (v.level == Verdict::Clean || config.IsAllowedHash(v.sha256)) continue;
            Detections::FillFromVerdict(t, v);
            t.summary = Detections::SummaryOf(v);
            t.filePath = target;
            flagged = true;
        }

        // Встроенные задачи Windows (\Microsoft\...) сами пользуются
        // PowerShell и rundll32 — приёмы в их командах не улика; их файлы
        // при этом всё равно проверены анализатором выше.
        const bool builtin = a.taskPath.rfind(L"\\Microsoft\\", 0) == 0;
        for (const std::string& r : builtin ? std::vector<std::string>{}
                                            : CommandTarget::AbuseReasons(a.command)) {
            t.reasons.push_back(r);
            if (static_cast<int>(t.severity) < static_cast<int>(Severity::High)) t.severity = Severity::High;
            if (t.summary.empty()) t.summary = L"Scheduled task abuses a system program";
            flagged = true;
        }

        if (!flagged) continue;
        t.reasons.insert(t.reasons.begin(), Reason({ "task", Utf8(a.taskPath) }));
        if (!parsed.executable.empty()) t.reasons.push_back(Reason({ "runs", Utf8(parsed.executable) }));
        if (!a.enabled) t.reasons.push_back("task.disabled");
        sink.Report(t);
        Logger::Instance().Warn("[Tasks] flagged: " + Utf8(a.taskPath));
    }

    if (SUCCEEDED(co)) CoUninitialize();
    Logger::Instance().Info("[Tasks] done");
}
