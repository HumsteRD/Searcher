#pragma once

#include "IScanModule.h"
#include "ThreatReport.h"
#include "ActionExecutor.h"   // ActionResult

#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <memory>
#include <string>
#include <unordered_set>
#include <chrono>

enum class ScanState {
    Idle,
    Running,
    Cancelling,
    Done
};

struct ScanStats {
    int  totalThreats = 0;
    int  criticalThreats = 0;
    int  progressPercent = 0;
    std::string  currentStage;

    // Что происходит прямо сейчас и сколько уже проверено.
    long long    objectsScanned = 0;
    std::wstring currentItem;
    int          elapsedMs = 0;
    int          etaMs = -1;   // -1 = оценить пока нельзя
};

class Scanner : public IReportSink {
public:
    Scanner();
    ~Scanner();

    void RegisterModule(std::shared_ptr<IScanModule> module);

    void Start();
    void Cancel();

    ScanState           State() const { return state_.load(); }
    ScanStats           Stats();
    std::vector<Threat> Snapshot();

    // Достать копию угрозы по индексу в Snapshot(). false — индекс невалиден.
    bool GetThreat(size_t index, Threat& out);

    // Применить действие к угрозе: 0 = Quarantine, 1 = Delete, 2 = Ignore.
    // Файловые операции выполняются вне мьютекса, чтобы не блокировать скан.
    ActionResult ApplyAction(size_t index, int action);

    void Report(const Threat& threat) override;
    void Item(const std::wstring& path) override;
    void Progress(const std::string& stage, int percent) override;

private:
    void Worker();

    std::atomic<ScanState> state_{ ScanState::Idle };
    CancelToken            cancel_;
    std::thread            worker_;

    std::mutex                                mutex_;
    std::vector<std::shared_ptr<IScanModule>> modules_;
    std::vector<Threat>                       threats_;
    // Ключи уже сообщённых объектов: файловый модуль и анализатор
    // скриптов видят одни и те же .ps1/.bat, и без этого один файл
    // попадал в список дважды.
    std::unordered_set<std::wstring>          reported_;
    ScanStats                                 stats_;

    // Пересчёт прогресса модуля в общий: модуль знает только свои 0..100.
    int  moduleIndex_ = 0;
    int  moduleCount_ = 1;
    std::chrono::steady_clock::time_point startedAt_;
};