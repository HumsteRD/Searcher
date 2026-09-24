#pragma once

#include <algorithm>
#include <atomic>
#include <functional>
#include <thread>
#include <vector>

// Простой параллельный цикл: n задач на нескольких потоках. Для модулей,
// где объектов сотни, а проверка каждого — чтение файла и сигнатуры.
inline void ParallelFor(size_t n, const std::function<void(size_t)>& body, int threads = 0) {
    if (n == 0) return;
    if (threads <= 0) threads = std::clamp(static_cast<int>(std::thread::hardware_concurrency()) - 1, 2, 8);
    threads = std::min<int>(threads, static_cast<int>(n));
    std::atomic<size_t> next{ 0 };
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t) {
        pool.emplace_back([&] {
            for (size_t i = next++; i < n; i = next++) body(i);
        });
    }
    for (auto& th : pool) th.join();
}
