#pragma once

#include "IScanModule.h"

class FileSystemScanner : public IScanModule {
public:
    std::string Name() const override { return "File system"; }
    void Scan(IReportSink& sink, CancelToken& cancel) override;
};
