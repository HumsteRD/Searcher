#pragma once

#include "BehaviorReport.h"

#include <string>

// Отчёт наблюдения в JSON и обратно.
//
// Через этот формат отчёт переезжает из песочницы на хост: агент внутри
// песочницы кладёт файл в единственную папку с записью, приложение
// снаружи его читает. Поэтому запись сделана без Qt — агент не тащит
// за собой библиотеку интерфейса ради одной строки.
//
// Слаги типов событий (`file_created`, `registry_value_set`, ...) —
// часть формата: их читает другая программа, и менять их нельзя так же,
// как нельзя менять имена полей.

const char*       BehaviorEventTypeSlug(BehaviorEventType type);
BehaviorEventType BehaviorEventTypeFromSlug(const char* slug, bool* ok = nullptr);

std::string BehaviorReportToJson(const BehaviorReport& report);

// error — куда положить причину неудачи; может быть nullptr.
bool WriteBehaviorReportJson(const BehaviorReport& report,
                             const std::wstring& path,
                             std::wstring* error = nullptr);
