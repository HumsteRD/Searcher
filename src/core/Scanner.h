#pragma once

#include "IScanModule.h"
#include "ThreatReport.h"
#include "ActionExecutor.h"   // ActionResult

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

enum class ScanState {
    Idle,
    Running,
    Cancelling,
    Done
};

struct ScanStats {
    int  totalThreats = 0;
    int  criticalThreats = 0;
    int  progressPercent = 0;       // -1 — пока неизвестен (идёт подсчёт)
    std::string  currentStage;

    long long    objectsScanned = 0;
    std::wstring currentItem;
    int          elapsedMs = 0;
    int          etaMs = -1;        // -1 — оценить пока нельзя
    bool         cancelled = false;
    bool         paused = false;
};

class Scanner : public IReportSink {
public:
    Scanner();
    ~Scanner();

    void RegisterModule(std::shared_ptr<IScanModule> module);

    // Подготовить базы (компиляция правил YARA, чтение базы хэшей)
    // и запустить проверку в рабочем потоке.
    void Start(const ScanConfig& config);
    void Cancel();

    // Пауза: проверка дочитывает текущие файлы и ждёт. Время на паузе
    // в длительность и в оценку остатка не входит.
    void SetPaused(bool paused);
    bool Paused() const { return cancel_.IsPaused(); }

    ScanState           State() const { return state_.load(); }
    ScanStats           Stats();
    std::vector<Threat> Snapshot();

    bool GetThreat(size_t index, Threat& out);

    // Действие над угрозой: 0 — карантин, 1 — удаление, 2 — пропустить.
    ActionResult ApplyAction(size_t index, int action);

    void Report(const Threat& threat) override;
    void Item(const std::wstring& path) override;
    void Progress(const std::string& stage, int percent) override;
    void Checked(long long count) override;

private:
    void Worker(ScanConfig config);

    std::atomic<ScanState> state_{ ScanState::Idle };
    CancelToken            cancel_;
    std::thread            worker_;

    std::mutex                                mutex_;
    std::vector<std::shared_ptr<IScanModule>> modules_;
    std::vector<Threat>                       threats_;
    std::unordered_set<std::wstring>          reported_;
    ScanStats                                 stats_;

    // Общий прогресс — взвешенная сумма прогресса модулей.
    int       weightDone_ = 0;       // сумма весов законченных модулей
    int       weightTotal_ = 1;
    int       currentWeight_ = 1;
    long long checkedBefore_ = 0;    // проверено законченными модулями
    long long checkedCurrent_ = 0;
    std::chrono::steady_clock::time_point startedAt_;
    std::chrono::steady_clock::time_point pausedAt_;
    std::chrono::steady_clock::duration   pausedTotal_{};

    // Прошло с начала проверки без учёта пауз. Зовётся под mutex_.
    int ElapsedMsLocked() const;
};
