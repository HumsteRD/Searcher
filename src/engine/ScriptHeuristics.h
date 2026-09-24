#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Эвристика для сценариев (PowerShell, batch, Windows Script Host, Python).
//
// Сигнатуры YARA ловят известное; сценарий, написанный вчера, они не
// знают. Здесь — признаки НАМЕРЕНИЯ: скачать и выполнить, спрятать
// команду, отключить защиту, закрепиться. Решение — по сумме весов
// с порогом: одиночный признак у честного сценария встречается часто.
//
// Правила привязаны к языку. JavaScript проверяется, только если это
// сценарий Windows Script Host (WScript, ActiveXObject): обычный JS из
// библиотек и сайтов — не то, что запускает Windows, и правила под
// PowerShell давали на нём сплошные ложные срабатывания.
namespace ScriptHeuristics {

struct Result {
    int                      score = 0;
    std::vector<std::string> rules;   // коды сработавших правил, без повторов
};

bool IsScriptExtension(const std::wstring& extLower);

// pathLower — полный путь в нижнем регистре: библиотеки в node_modules
// и site-packages не разбираются.
Result Analyze(const uint8_t* data, size_t size, const std::wstring& extLower,
               const std::wstring& pathLower);

// Пороги: от kSuspicious — подозрительно, от kMalicious — опасно.
inline constexpr int kSuspicious = 10;
inline constexpr int kMalicious  = 16;

} // namespace ScriptHeuristics
