#pragma once

#include "IScanModule.h"

class NetworkScanner : public IScanModule {
public:
    std::string Name() const override { return "Network"; }
    void Scan(IReportSink& sink, CancelToken& cancel) override;
};
