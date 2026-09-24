#pragma once

#include "Verdict.h"

#include <string>

// Разбор имён правил и семейств в понятные категории.
namespace Classify {

// Тип угрозы по имени правила YARA или семейства из базы хэшей.
MalwareClass FromName(const std::string& name);

// Сила правила. Автоматически сгенерированные и общие правила
// (упаковщики, обфускаторы, «подозрительные индикаторы») в одиночку
// дают слишком много ложных срабатываний — им нужно подтверждение.
enum class Strength { Indicator, Weak, Normal, Strong };
Strength RuleStrength(const std::string& rule, int score);

// Семейство из имени правила: MALPEDIA_Win_Lumma_Auto -> "Lumma".
std::string FamilyFromRule(const std::string& rule);

// Короткое англоязычное имя класса для журнала.
const char* ClassCode(MalwareClass cls);

} // namespace Classify
