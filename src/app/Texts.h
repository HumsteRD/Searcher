#pragma once

#include "../core/ThreatReport.h"

#include <QList>
#include <QString>

// Тексты для людей: что это за угроза, почему она найдена, что сделано.
// Всё строится из кодов, которые присылает ядро, на текущем языке.
namespace Texts {

QString classTitle(int malwareClass);          // «Похититель данных»
QString classExplain(int malwareClass);        // одно предложение: чем опасна
QString severityLabel(Severity s);             // «Критическая»
QString severityCode(Severity s);              // "CRIT" — для цвета
QString statusLabel(ThreatStatus s);           // «В карантине»
QString statusTone(ThreatStatus s);            // тон пилюли
QString kindLabel(ThreatKind k);               // «Файл», «Автозапуск»
QString stageLabel(const QString& stage);      // «Процессы»
QString actionResult(const QString& code, bool ok);
QString modeLabel(int mode);                   // «Быстрая проверка»

struct Reason {
    QString text;     // человеческая фраза
    QString detail;   // техническая подробность (имя правила, путь), может быть пусто
    bool    technical = false;   // показывать в «Подробностях», а не в основном списке
};
QList<Reason> reasons(const Threat& t);

// Что делать: одна фраза-рекомендация под вердиктом.
QString advice(const Threat& t);

// Короткое название находки для списка: «RedLine — похититель данных».
QString headline(const Threat& t);

} // namespace Texts
