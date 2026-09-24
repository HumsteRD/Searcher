#pragma once

#include "IScanModule.h"

// Сетевые соединения: связь с пулами майнинга и с портами, типичными для
// удалённого управления, у неподписанных программ из рискованных папок.
class NetworkScanner : public IScanModule {
public:
    std::string Name() const override { return "Network"; }
    ScanConfig::Module Id() const override { return ScanConfig::Network; }
    int Weight() const override { return 1; }
    void Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) override;
};
