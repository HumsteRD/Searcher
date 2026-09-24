#pragma once

#include "Verdict.h"

#include <cstdint>
#include <string>

// Проверка одного файла целиком: хэш, база известных вредоносов,
// сигнатуры YARA, вложенное содержимое (ZIP, PyInstaller), обманные имена,
// цифровая подпись. Возвращает вердикт с уликами.
//
// Потокобезопасно — файловый модуль гоняет его в нескольких потоках.
namespace FileAnalyzer {

struct Options {
    bool     useYara = true;
    bool     unpack = true;
    bool     reportPua = false;              // хакерские инструменты и PUA
    uint64_t maxContentSize = 256ull << 20;  // больше — только хэш
    uint64_t maxHashSize = 2048ull << 20;
};

Verdict Analyze(const std::wstring& path, const Options& options = {});

// Стоит ли вообще открывать файл при обходе каталога. Решение по имени,
// без чтения: обход диска упирается в число открытых файлов.
bool IsCandidateByName(const std::wstring& fileName);

// Для файлов без понятного расширения — по первым байтам.
bool IsCandidateByMagic(const uint8_t* head, size_t n);

// Обманное имя: «документ.pdf.exe», символ смены направления текста,
// длинная вереница пробелов перед расширением.
bool IsDeceptiveName(const std::wstring& fileName, std::string* why = nullptr);

// Сбросить кэш вердиктов (в начале каждой проверки).
void ResetCache();

} // namespace FileAnalyzer
