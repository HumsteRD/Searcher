#pragma once

#include "ThreatReport.h"
#include "../engine/Verdict.h"

#include <initializer_list>
#include <string>

// Общие части всех модулей: вердикт анализатора → находка, коды причин.
namespace Detections {

// Код причины: части через табуляцию. Reason({"autorun", "HKCU Run"}).
std::string Reason(std::initializer_list<std::string> parts);
std::string Utf8(const std::wstring& w);
std::wstring Wide(const std::string& s);

Severity ToSeverity(int level);   // 0..4

// Перенести в находку всё, что знает вердикт: уровень, тип, семейство,
// хэш, подпись и причины.
void FillFromVerdict(Threat& t, const Verdict& v);

// Англоязычная строка для журнала: «Stealer/RedLine (hash match)».
std::wstring SummaryOf(const Verdict& v);

} // namespace Detections
