#pragma once

#include "ThreatReport.h"

#include <QJsonObject>
#include <QString>

// Находка ⇄ JSON: канал помощника, результаты службы, история.
namespace ThreatJson {

QJsonObject ToJson(const Threat& t);
Threat      FromJson(const QJsonObject& o);

QString SeverityCode(Severity s);          // "CRIT", "HIGH", ...
Severity SeverityFromCode(const QString& code);

QString StatusCode(ThreatStatus s);        // "pending", "quarantined", ...
ThreatStatus StatusFromCode(const QString& code);

} // namespace ThreatJson
