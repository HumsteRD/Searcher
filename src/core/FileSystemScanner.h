#pragma once

#include "IScanModule.h"

// Файлы на дисках: быстрая проверка — рискованные папки, полная — все
// локальные диски, выборочная — то, что указал пользователь.
class FileSystemScanner : public IScanModule {
public:
    std::string Name() const override { return "Files"; }
    ScanConfig::Module Id() const override { return ScanConfig::Files; }
    int Weight() const override { return 20; }
    void Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) override;
};
