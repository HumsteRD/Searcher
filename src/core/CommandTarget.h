#pragma once

#include <string>
#include <vector>

// Разбор командной строки автозапуска, задачи или службы: какие файлы
// она на самом деле запускает, и нет ли в ней известных приёмов
// злоупотребления системными программами.
namespace CommandTarget {

struct Parsed {
    std::wstring executable;              // запускаемая программа
    std::vector<std::wstring> payloads;   // сценарий или DLL, которые она выполнит
    std::wstring arguments;
};

// Развернуть переменные среды, снять кавычки, найти исполняемый файл
// (в том числе незакавыченный путь с пробелами), вытащить сценарий для
// интерпретатора и DLL для rundll32/regsvr32.
Parsed Parse(const std::wstring& commandLine);

// Путь в формате служб: \SystemRoot\..., system32\drivers\..., \??\C:\...
std::wstring NormalizeImagePath(const std::wstring& imagePath);

// Коды причин для злоупотреблений системными программами:
// cmd.encoded, cmd.download, cmd.mshta, cmd.regsvr32, cmd.rundll32-script,
// cmd.certutil, cmd.bitsadmin, cmd.hidden-script.
std::vector<std::string> AbuseReasons(const std::wstring& commandLine);

} // namespace CommandTarget
