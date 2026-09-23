#pragma once

#include "BehaviorReport.h"
#include "ThreatReport.h"   // Severity

#include <string>
#include <vector>

// Вердикт по поведению: что из увиденного действительно опасно.
//
// Отчёт наблюдения — это лента из десятков событий, и разбираться в ней
// самому пользователь не обязан. Здесь события превращаются в конечный
// список улик с весами; вердикт складывается из суммы, как в
// `ScriptScanner`. Одиночный признак почти никогда не приговор: запись
// файла в %TEMP% делает половина установщиков, и весит она поэтому мало.
//
// Правило то же, что и во всём остальном приложении: ложное срабатывание
// дороже пропуска. Поэтому «ничего не нашли» здесь означает ровно
// «ничего не нашли», а не «файл безопасен» — об этом сказано и в самом
// тексте вердикта.

struct BehaviorFinding {
    Severity     severity = Severity::Info;
    int          weight = 0;
    std::wstring title;    // что произошло
    std::wstring detail;   // конкретная улика: путь, значение, адрес
};

struct BehaviorVerdict {
    int          score = 0;
    Severity     severity = Severity::Info;
    std::wstring summary;
    std::vector<BehaviorFinding> findings;   // от тяжёлых к лёгким
};

BehaviorVerdict JudgeBehavior(const BehaviorReport& report);

// Стоит ли заводить угрозу по результатам наблюдения. Порог намеренно
// высокий: «активность есть, но ничего характерного» — это не находка,
// а строчка в истории.
bool VerdictWarrantsThreat(const BehaviorVerdict& verdict);

// Угроза по итогам наблюдения.
//
// hostPath передаётся отдельно и обязателен: внутри песочницы образец
// лежит по пути C:\sample\<имя>, и `report.target` содержит именно его.
// На хосте по этому пути нет ничего, а карантину и удалению нужен файл,
// который выбрал пользователь.
Threat ThreatFromBehaviour(const std::wstring& hostPath,
                           const BehaviorReport& report,
                           const BehaviorVerdict& verdict);
