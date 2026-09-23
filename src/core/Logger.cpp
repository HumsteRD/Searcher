#include "Logger.h"
#include <algorithm>

Logger& Logger::Instance() {
    static Logger instance;
    return instance;
}

void Logger::Log(LogLevel level, std::string message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (buffer_.size() >= kCapacity) {
        buffer_.pop_front();
    }
    ++written_;
    buffer_.push_back(LogEntry{
        level,
        std::move(message),
        std::chrono::system_clock::now()
    });
}

std::vector<LogEntry> Logger::Snapshot(size_t maxN) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t n = std::min(maxN, buffer_.size());
    return std::vector<LogEntry>(buffer_.end() - n, buffer_.end());
}

void Logger::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    buffer_.clear();
}
size_t Logger::TotalWritten() {
    std::lock_guard<std::mutex> lock(mutex_);
    return written_;
}

std::vector<LogEntry> Logger::Since(size_t writtenIndex) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (writtenIndex >= written_) return {};

    // Часть записей могла быть вытеснена из кольцевого буфера —
    // тогда отдаём всё, что осталось.
    const size_t missed = written_ - writtenIndex;
    const size_t take   = std::min(missed, buffer_.size());

    return std::vector<LogEntry>(buffer_.end() - take, buffer_.end());
}
