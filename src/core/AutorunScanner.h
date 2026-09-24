#pragma once

#include "IScanModule.h"

// Всё, что Windows запускает сама при входе: ключи Run и RunOnce,
// Winlogon, подмена отладчика (IFEO), AppInit_DLLs и папки автозагрузки.
// Запись проверяется по тому, ЧТО она запускает: сам запускаемый файл
// идёт через анализатор, командная строка — на известные приёмы.
class AutorunScanner : public IScanModule {
public:
    std::string Name() const override { return "Autoruns"; }
    ScanConfig::Module Id() const override { return ScanConfig::Autoruns; }
    int Weight() const override { return 2; }
    void Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) override;
};
