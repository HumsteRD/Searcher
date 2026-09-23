#pragma once

#include "BehaviorReport.h"

#include <string>
#include <set>
#include <thread>
#include <atomic>
#include <functional>
#include <Windows.h>

// Сетевая активность наблюдаемых процессов.
//
// Здесь, в отличие от файлов и реестра, автор известен: таблица
// соединений хранит PID владельца. Зато известен не всё: таблица
// опрашивается периодически, и соединение, открытое и закрытое между
// двумя опросами, в отчёт не попадёт. Имена узлов (DNS-запросы) в
// пользовательском режиме без ETW не видны — только адреса.
class NetworkActivityWatcher {
public:
    // Возвращает true для процессов, за которыми следим.
    using PidFilter = std::function<bool(DWORD)>;

    ~NetworkActivityWatcher();

    bool Start(PidFilter filter, BehaviorSink sink, int pollMs = 400);
    void Stop();

private:
    void Pump(int pollMs);
    void PollOnce();
    void EmitOnce(BehaviorEventType type, DWORD pid,
                  const std::wstring& target, const std::wstring& detail);

    std::set<std::wstring> seen_;   // чтобы не повторять одно соединение
    HANDLE            stopEvent_ = nullptr;
    std::thread       thread_;
    std::atomic<bool> stopping_{ false };
    PidFilter         filter_;
    BehaviorSink      sink_;
};
