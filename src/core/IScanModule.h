#pragma once

#include "ThreatReport.h"
#include <atomic>
#include <string>

struct CancelToken {
    std::atomic<bool> requested{ false };
    bool IsCancelled() const noexcept { return requested.load(); }
    void Cancel() noexcept { requested.store(true); }
};

class IScanModule {
public:
    virtual ~IScanModule() = default;
    virtual std::string Name() const = 0;
    virtual void Scan(IReportSink& sink, CancelToken& cancel) = 0;
};