#pragma once

#include "IScanModule.h"

// Службы и драйверы, постоянные подписки WMI, файл hosts.
class PersistenceScanner : public IScanModule {
public:
    std::string Name() const override { return "Services"; }
    ScanConfig::Module Id() const override { return ScanConfig::Services; }
    int Weight() const override { return 3; }
    void Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) override;

private:
    void ScanServices(IReportSink& sink, CancelToken& cancel, const ScanConfig& config);
    void ScanWmi(IReportSink& sink, const ScanConfig& config);
    void ScanHosts(IReportSink& sink);
};
