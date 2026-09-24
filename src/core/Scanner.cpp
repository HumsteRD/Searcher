#include "Scanner.h"
#include "Logger.h"
#include "ThreatActions.h"

#include "../engine/FileAnalyzer.h"
#include "../engine/HashDatabase.h"
#include "../engine/YaraEngine.h"

#include <algorithm>

Scanner::Scanner() = default;

Scanner::~Scanner() {
    Cancel();
    if (worker_.joinable()) worker_.join();
}

void Scanner::RegisterModule(std::shared_ptr<IScanModule> module) {
    std::lock_guard<std::mutex> lock(mutex_);
    modules_.push_back(std::move(module));
}

void Scanner::Start(const ScanConfig& config) {
    if (state_.load() == ScanState::Running) return;
    if (worker_.joinable()) worker_.join();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        threats_.clear();
        reported_.clear();
        stats_ = {};
        stats_.progressPercent = 0;
        weightDone_ = 0;
        weightTotal_ = 1;
        currentWeight_ = 1;
        checkedBefore_ = checkedCurrent_ = 0;
        startedAt_ = std::chrono::steady_clock::now();
    }

    cancel_.requested.store(false);
    state_.store(ScanState::Running);
    worker_ = std::thread([this, config] { Worker(config); });
}

void Scanner::Cancel() {
    if (state_.load() == ScanState::Running) {
        state_.store(ScanState::Cancelling);
        cancel_.Cancel();
    }
}

ScanStats Scanner::Stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    ScanStats out = stats_;
    const ScanState st = state_.load();
    if (st == ScanState::Running || st == ScanState::Cancelling) {
        out.elapsedMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startedAt_).count());
        // Оценку даём, только когда процент честный и прошло достаточно,
        // чтобы скорость успела установиться.
        if (out.progressPercent >= 3 && out.elapsedMs > 3000) {
            const double done = out.progressPercent / 100.0;
            out.etaMs = static_cast<int>(out.elapsedMs * (1.0 - done) / done);
        } else {
            out.etaMs = -1;
        }
    }
    return out;
}

std::vector<Threat> Scanner::Snapshot() {
    std::lock_guard<std::mutex> lock(mutex_);
    return threats_;
}

bool Scanner::GetThreat(size_t index, Threat& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= threats_.size()) return false;
    out = threats_[index];
    return true;
}

ActionResult Scanner::ApplyAction(size_t index, int action) {
    Threat copy;
    if (!GetThreat(index, copy)) return { false, L"missing" };

    // Пропущенную угрозу можно вернуть к действию: «пропустить» — не
    // окончательное решение, а отметка «разберусь потом».
    if (copy.status != ThreatStatus::Pending && copy.status != ThreatStatus::Ignored &&
        copy.status != ThreatStatus::Failed)
        return { false, L"already-handled" };

    ActionResult r = ApplyThreatAction(copy, action);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (index < threats_.size()) {
            threats_[index].status        = copy.status;
            threats_[index].actionMessage = copy.actionMessage;
        }
    }
    return r;
}

void Scanner::Report(const Threat& threat) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Ключ объекта: вид + расположение. Один файл, найденный и обходом
    // диска, и через автозапуск, в списке должен быть один раз — но
    // запись автозапуска и сам файл — разные находки с разными действиями.
    std::wstring key = threat.source;
    std::transform(key.begin(), key.end(), key.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    key = std::to_wstring(static_cast<int>(threat.kind)) + L"|" + key;
    if (threat.kind == ThreatKind::Process) key += L"|" + std::to_wstring(threat.pid);
    if (!reported_.insert(key).second) return;

    threats_.push_back(threat);
    stats_.totalThreats++;
    if (threat.severity == Severity::Critical) stats_.criticalThreats++;
}

void Scanner::Progress(const std::string& stage, int percent) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.currentStage = stage;
    if (percent < 0) {
        // Модуль ещё считает объём работы. Показываем долю уже
        // законченных модулей, а не ноль — шкала не должна прыгать назад.
        stats_.progressPercent = weightDone_ * 100 / std::max(weightTotal_, 1);
        return;
    }
    const int local = std::clamp(percent, 0, 100);
    const int overall = (weightDone_ * 100 + currentWeight_ * local) / std::max(weightTotal_, 1);
    stats_.progressPercent = std::max(stats_.progressPercent, std::clamp(overall, 0, 100));
}

void Scanner::Item(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.currentItem = path;
}

void Scanner::Checked(long long count) {
    std::lock_guard<std::mutex> lock(mutex_);
    checkedCurrent_ = count;
    stats_.objectsScanned = checkedBefore_ + checkedCurrent_;
}

void Scanner::Worker(ScanConfig config) {
    Logger::Instance().Info("=== Scan started ===");
    ScanConfig::SetCurrent(config);
    FileAnalyzer::ResetCache();

    // Базы: правила компилируются один раз на запуск помощника и
    // пересобираются, только если файлы правил обновились.
    Progress("Preparing", -1);
    HashDatabase::Get().Reload();
    std::string error;
    if (!YaraEngine::Get().Prepare(config.extendedRules, &error)) {
        Logger::Instance().Error("[Scan] signature rules unavailable: " + error);
    }

    std::vector<std::shared_ptr<IScanModule>> active;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& m : modules_)
            if (config.ModuleOn(m->Id())) active.push_back(m);
        weightTotal_ = 0;
        for (const auto& m : active) weightTotal_ += m->Weight();
        weightTotal_ = std::max(weightTotal_, 1);
    }

    for (const auto& m : active) {
        if (cancel_.IsCancelled()) break;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            currentWeight_ = m->Weight();
            checkedCurrent_ = 0;
        }
        Logger::Instance().Info("[Module] " + m->Name());
        Progress(m->Name(), 0);
        try {
            m->Scan(*this, cancel_, config);
        } catch (const std::exception& e) {
            Logger::Instance().Error("Module " + m->Name() + " crashed: " + e.what());
        } catch (...) {
            Logger::Instance().Error("Module " + m->Name() + " crashed");
        }
        std::lock_guard<std::mutex> lock(mutex_);
        weightDone_ += m->Weight();
        checkedBefore_ += checkedCurrent_;
        checkedCurrent_ = 0;
        stats_.objectsScanned = checkedBefore_;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.cancelled = cancel_.IsCancelled();
        if (!stats_.cancelled) stats_.progressPercent = 100;
        stats_.currentStage = "Done";
        stats_.currentItem.clear();
        stats_.elapsedMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startedAt_).count());
        stats_.etaMs = 0;
    }
    Logger::Instance().Info("=== Scan finished ===");
    state_.store(ScanState::Done);
}
