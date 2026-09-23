#pragma once

#include "IScanModule.h"

class ProcessScanner : public IScanModule {
public:
    std::string Name() const override { return "Processes"; }
    void Scan(IReportSink& sink, CancelToken& cancel) override;
};
