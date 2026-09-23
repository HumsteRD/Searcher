#pragma once

#include "IScanModule.h"

// Места закрепления, которые мы до сих пор не проверяли:
//
//  • подписки WMI — самый незаметный способ закрепиться: в автозагрузке
//    и планировщике его не видно вообще;
//  • файл hosts — подмена адресов, часто чтобы отрезать антивирусы
//    от их серверов обновлений;
//  • службы Windows, запускаемые из временных и пользовательских папок.
//
// Направления подсказаны разбором открытого проекта MinerSearch;
// реализация своя — тот проект написан на C# и повторно не используется.
class PersistenceScanner : public IScanModule {
public:
    std::string Name() const override { return "System persistence"; }
    void Scan(IReportSink& sink, CancelToken& cancel) override;

private:
    void ScanHosts(IReportSink& sink);
    void ScanServices(IReportSink& sink, CancelToken& cancel);
    void ScanWmiSubscriptions(IReportSink& sink);
};
