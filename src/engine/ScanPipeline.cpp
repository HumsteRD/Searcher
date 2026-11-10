#include "ScanPipeline.h"

#include <Windows.h>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace {

// Файл стоит не только своих байтов: открыть и закрыть его — тоже работа.
// Без этой поправки папка из тысячи мелких файлов «проходилась» за 0%.
constexpr uint64_t kPerFileWeight = 64 * 1024;

class Queue {
public:
    explicit Queue(size_t capacity) : capacity_(capacity) {}

    bool Push(FileWalker::Candidate&& c, const std::atomic<bool>& cancel) {
        std::unique_lock<std::mutex> lock(mutex_);
        notFull_.wait(lock, [&] { return items_.size() < capacity_ || cancel.load(); });
        if (cancel.load()) return false;
        items_.push_back(std::move(c));
        notEmpty_.notify_one();
        return true;
    }

    bool Pop(FileWalker::Candidate& out, const std::atomic<bool>& cancel) {
        std::unique_lock<std::mutex> lock(mutex_);
        notEmpty_.wait(lock, [&] { return !items_.empty() || closed_ || cancel.load(); });
        if (cancel.load() || items_.empty()) return false;
        out = std::move(items_.front());
        items_.pop_front();
        notFull_.notify_one();
        return true;
    }

    void Close() {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        notEmpty_.notify_all();
    }

    void Wake() {
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

private:
    std::mutex                          mutex_;
    std::condition_variable             notEmpty_, notFull_;
    std::deque<FileWalker::Candidate>   items_;
    size_t                              capacity_;
    bool                                closed_ = false;
};

bool HasExecutableMagic(const std::wstring& path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    uint8_t head[8] = {};
    DWORD got = 0;
    ReadFile(f, head, sizeof(head), &got, nullptr);
    CloseHandle(f);
    return FileAnalyzer::IsCandidateByMagic(head, got);
}

} // namespace

void ScanPipeline::Run(const Config& config, const std::atomic<bool>& cancel,
                       const VerdictSink& onVerdict,
                       const std::function<void(const Progress&)>& onProgress)
{
    FileWalker::Stats walkStats;
    Queue queue(4096);
    std::atomic<bool> walkDone{ false };
    std::atomic<uint64_t> checked{ 0 }, bytesDone{ 0 }, failed{ 0 };

    std::mutex currentLock;
    std::wstring current;

    // Пауза: потоки дочитывают текущий файл и ждут. Отмена паузу снимает.
    auto waitWhilePaused = [&] {
        while (config.pause && config.pause->load() && !cancel.load()) Sleep(40);
    };

    std::thread walker([&] {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        FileWalker::Walk(config.roots, config.excludes, cancel, walkStats,
                         [&](FileWalker::Candidate&& c) {
                             waitWhilePaused();
                             queue.Push(std::move(c), cancel);
                         });
        walkDone.store(true);
        queue.Close();
    });

    int threads = config.threads;
    if (threads <= 0) {
        const int cores = static_cast<int>(std::thread::hardware_concurrency());
        threads = std::clamp(cores - 1, 2, 8);
    }
    threads = std::clamp(threads, 1, 32);

    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&] {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            FileWalker::Candidate c;
            while (queue.Pop(c, cancel)) {
                waitWhilePaused();
                if (cancel.load()) break;
                {
                    std::lock_guard<std::mutex> lock(currentLock);
                    current = c.path;
                }
                // Исключение в одном файле — не повод останавливать поток:
                // без перехвата оно завершило бы весь процесс.
                try {
                    if (!c.sniff || HasExecutableMagic(c.path)) {
                        const Verdict v = FileAnalyzer::Analyze(c.path, config.analyzer);
                        if (v.skipped && v.skipReason == "error") ++failed;
                        if (v.level != Verdict::Clean && onVerdict) onVerdict(c.path, v);
                    }
                } catch (...) {
                    ++failed;
                }
                bytesDone += c.size + kPerFileWeight;
                ++checked;
            }
        });
    }

    // Отчёт о ходе работы — из вызывающего потока, раз в 100 мс.
    auto report = [&] {
        Progress p;
        p.filesSeen    = walkStats.files.load();
        p.candidates   = walkStats.candidates.load();
        p.checked      = checked.load();
        p.failed       = failed.load();
        p.bytesTotal   = walkStats.candidateBytes.load() + p.candidates * kPerFileWeight;
        p.bytesDone    = bytesDone.load();
        p.walkFinished = walkDone.load();
        if (p.walkFinished && p.bytesTotal > 0) {
            p.percent = static_cast<int>(std::min<uint64_t>(100, p.bytesDone * 100 / p.bytesTotal));
        }
        {
            std::lock_guard<std::mutex> lock(currentLock);
            p.current = current;
        }
        if (onProgress) onProgress(p);
    };

    for (;;) {
        if (cancel.load()) queue.Wake();
        report();
        if (walkDone.load() && checked.load() >= walkStats.candidates.load()) break;
        if (cancel.load()) break;
        Sleep(100);
    }

    queue.Wake();
    walker.join();
    for (auto& w : workers) w.join();
    report();
}
