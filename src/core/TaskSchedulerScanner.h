#pragma once

#include "IScanModule.h"

// Задачи планировщика: что именно запускает каждое действие задачи.
class TaskSchedulerScanner : public IScanModule {
public:
    std::string Name() const override { return "Tasks"; }
    ScanConfig::Module Id() const override { return ScanConfig::Tasks; }
    int Weight() const override { return 2; }
    void Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) override;
};
