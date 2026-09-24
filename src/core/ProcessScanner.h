#pragma once

#include "IScanModule.h"

// Запущенные процессы: файл, из которого процесс запущен, маскировка
// под системные программы, командная строка интерпретаторов.
class ProcessScanner : public IScanModule {
public:
    std::string Name() const override { return "Processes"; }
    ScanConfig::Module Id() const override { return ScanConfig::Processes; }
    int Weight() const override { return 3; }
    void Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) override;
};
