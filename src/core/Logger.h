#pragma once

#include <string>
#include <deque>
#include <mutex>
#include <vector>
#include <chrono>

enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical
};

struct LogEntry {
    LogLevel level;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
};

class Logger {
public:
    static Logger& Instance();

    void Log(LogLevel level, std::string message);

    void Debug(std::string m) { Log(LogLevel::Debug, std::move(m)); }
    void Info(std::string m) { Log(LogLevel::Info, std::move(m)); }
    void Warn(std::string m) { Log(LogLevel::Warn, std::move(m)); }
    void Error(std::string m) { Log(LogLevel::Error, std::move(m)); }
    void Critical(std::string m) { Log(LogLevel::Critical, std::move(m)); }

    std::vector<LogEntry> Snapshot(size_t maxN = 1000);

    // Сколько записей всего накопилось за время работы (с учётом вытесненных).
    size_t TotalWritten();

    // Только записи, появившиеся после указанного номера. Мост опрашивает
    // журнал 12 раз в секунду, и копировать ради этого весь буфер (до 5000
    // записей) — чистая трата процессора.
    std::vector<LogEntry> Since(size_t writtenIndex);
    void Clear();

private:
    Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static constexpr size_t kCapacity = 5000;

    std::deque<LogEntry> buffer_;
    size_t               written_ = 0;
    std::mutex mutex_;
};