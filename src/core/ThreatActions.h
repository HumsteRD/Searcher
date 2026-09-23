#pragma once

#include "ThreatReport.h"
#include "ActionExecutor.h"   // ActionResult
#include "Quarantine.h"

// Применяет действие к угрозе в зависимости от её kind.
// action: 0 = Quarantine, 1 = Delete, 2 = Ignore.
// Меняет t.status и t.actionMessage. Возвращает результат.
ActionResult ApplyThreatAction(Threat& t, int action);
