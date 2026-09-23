#pragma once

#include "IScanModule.h"

class TaskSchedulerScanner : public IScanModule {
public:
    std::string Name() const override { return "Scheduled tasks"; }
    void Scan(IReportSink& sink, CancelToken& cancel) override;
};
