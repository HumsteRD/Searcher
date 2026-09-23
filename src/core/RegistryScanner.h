#pragma once

#include "IScanModule.h"

class RegistryScanner : public IScanModule {
public:
    std::string Name() const override { return "Registry / Autorun"; }
    void Scan(IReportSink& sink, CancelToken& cancel) override;
};