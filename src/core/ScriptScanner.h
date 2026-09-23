#pragma once

#include "IScanModule.h"

#include <string>
#include <vector>

// Статический анализ скриптов: PowerShell, batch, VBScript, JScript, Python.
//
// Рассчитан на случай «человек купил скрипт и не знает языка»: ищет то,
// что честному скрипту не нужно, и объясняет находку словами, а не
// названием паттерна.
//
// Важно: анализ статический. Он даёт «подозрительно», а не «вредонос»,
// и хорошо запутанную закладку может не увидеть.
class ScriptScanner : public IScanModule {
public:
    std::string Name() const override { return "Scripts"; }
    void Scan(IReportSink& sink, CancelToken& cancel) override;

    // Разбор одного файла — вынесен наружу, чтобы этим же кодом можно было
    // проверить файл, который перетащили или выбрали вручную.
    struct Hit {
        Severity     severity;
        int          line;        // 1-based
        std::wstring what;        // что именно нашли, по-человечески
        std::wstring evidence;    // фрагмент строки
    };
    static std::vector<Hit> Analyze(const std::wstring& path);

    static bool IsScriptFile(const std::wstring& extLower);
};
