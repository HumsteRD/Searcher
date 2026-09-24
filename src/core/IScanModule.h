#pragma once

#include "ThreatReport.h"
#include "ScanConfig.h"

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
    virtual ScanConfig::Module Id() const = 0;

    // Доля модуля в общем прогрессе. Файлы — это почти вся работа,
    // процессы и реестр проходятся за секунды: равные доли дали бы
    // шкалу, которая пробегает половину пути мгновенно и потом стоит.
    virtual int Weight() const { return 1; }

    virtual void Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) = 0;
};
