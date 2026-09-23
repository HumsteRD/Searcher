#include "Scanner.h"
#include "Logger.h"
#include "ThreatActions.h"
#include "AppSettings.h"

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

void Scanner::Start() {
    if (state_.load() == ScanState::Running) return;
    if (worker_.joinable()) worker_.join();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        threats_.clear();
        reported_.clear();
        stats_ = {};
        moduleIndex_ = 0;
        moduleCount_ = static_cast<int>(modules_.size());
        startedAt_ = std::chrono::steady_clock::now();
    }

    cancel_.requested.store(false);
    state_.store(ScanState::Running);

    worker_ = std::thread([this] { Worker(); });
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

    // Время считаем здесь, а не в Progress(): модули зовут Progress редко
    // (раз на каталог), поэтому таймер стоял бы почти всё сканирование.
    if (state_.load() == ScanState::Running) {
        const auto now = std::chrono::steady_clock::now();
        out.elapsedMs = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - startedAt_).count());

        if (out.progressPercent >= 3 && out.elapsedMs > 1500) {
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
    if (!GetThreat(index, copy)) {
        return { false, L"Threat no longer exists." };
    }
    if (copy.status != ThreatStatus::Pending) {
        return { false, L"An action was already applied to this threat." };
    }

    // Вне мьютекса: чтение/запись файла в карантин может занять секунды,
    // а под этим же мьютексом рабочий поток репортит новые угрозы.
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

    // Ключ объекта: для файлов — путь, для остального — источник.
    // Регистр не учитываем: в Windows пути регистронезависимы.
    std::wstring key = threat.filePath.empty() ? threat.source : threat.filePath;
    std::transform(key.begin(), key.end(), key.begin(),
                   [](wchar_t c) { return (wchar_t)towlower(c); });
    key = std::to_wstring(static_cast<int>(threat.kind)) + L"|" + key;

    if (!reported_.insert(key).second) {
        // Уже сообщали об этом объекте в текущей проверке.
        return;
    }

    threats_.push_back(threat);
    stats_.totalThreats++;
    if (threat.severity == Severity::Critical) {
        stats_.criticalThreats++;
    }
}

void Scanner::Progress(const std::string& stage, int percent) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.currentStage = stage;

    // percent приходит от модуля и означает его собственные 0..100.
    // Раньше он писался в общий прогресс напрямую, поэтому шкала
    // дёргалась и в итоге прыгала с нуля сразу на сотню.
    const int local = std::clamp(percent, 0, 100);
    stats_.progressPercent =
        std::clamp((moduleIndex_ * 100 + local) / std::max(moduleCount_, 1), 0, 100);

}

void Scanner::Item(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.objectsScanned;
    stats_.currentItem = path;
}

void Scanner::Worker() {
    Logger::Instance().Info("=== Scan started ===");

    std::vector<std::shared_ptr<IScanModule>> mods;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        mods = modules_;
    }

    Logger::Instance().Info("Worker: modules count = " + std::to_string(mods.size()));

    // Отбрасываем выключенные модули до начала работы: иначе прогресс
    // считался бы от общего числа и застревал на пропущенных отрезках.
    std::vector<std::shared_ptr<IScanModule>> active;
    for (size_t k = 0; k < mods.size(); ++k) {
        if (AppSettings::Get().ModuleEnabled(static_cast<int>(k))) {
            active.push_back(mods[k]);
        } else {
            Logger::Instance().Info("[Module] " + mods[k]->Name() + " skipped (disabled)");
        }
    }
    mods.swap(active);

    int i = 0;
    for (auto& m : mods) {
        if (cancel_.IsCancelled()) break;

        Logger::Instance().Info("[Module] " + m->Name() + " ...");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            moduleIndex_ = i;
            moduleCount_ = static_cast<int>(mods.size());
        }
        Progress(m->Name(), 0);

        try {
            m->Scan(*this, cancel_);
        } catch (const std::exception& e) {
            Logger::Instance().Error(std::string("Module crashed: ") + e.what());
        } catch (...) {
            Logger::Instance().Error("Module crashed (unknown exception)");
        }
        ++i;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        moduleIndex_ = moduleCount_;
    }
    Progress("Done", 0);
    Logger::Instance().Info("=== Scan finished ===");
    state_.store(ScanState::Done);
}