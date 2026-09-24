#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Эвристика для сценариев (PowerShell, batch, VBScript, JScript, Python).
//
// Сигнатуры YARA ловят известное; сценарий, написанный вчера, они не
// знают. Здесь — признаки НАМЕРЕНИЯ: скачать и выполнить, спрятать
// команду, отключить защиту, закрепиться. Решение — по сумме весов
// с порогом: одиночный признак у честного сценария встречается часто.
namespace ScriptHeuristics {

struct Result {
    int                      score = 0;
    std::vector<std::string> rules;   // коды сработавших правил, без повторов
};

bool IsScriptExtension(const std::wstring& extLower);

Result Analyze(const uint8_t* data, size_t size);

// Пороги: от kSuspicious — подозрительно, от kMalicious — опасно.
inline constexpr int kSuspicious = 6;
inline constexpr int kMalicious  = 12;

} // namespace ScriptHeuristics
