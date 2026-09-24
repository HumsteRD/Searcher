#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// Обход томов и папок для проверки.
//
// Главное отличие от прежнего обхода по «горячим папкам»: полная проверка
// идёт по всем локальным дискам целиком, с исключениями, которые нельзя
// проверять (базы других антивирусов, файлы подкачки, облачные заглушки),
// а не по двум десяткам заранее известных каталогов.
namespace FileWalker {

struct Root {
    std::wstring path;
    int          maxDepth = 64;     // глубина от корня
    bool         risky = false;     // сюда вредонос попадает чаще всего
};

struct Candidate {
    std::wstring path;
    uint64_t     size = 0;
    bool         sniff = false;     // тип по расширению неясен — смотреть байты
};

struct Stats {
    std::atomic<uint64_t> directories{ 0 };
    std::atomic<uint64_t> files{ 0 };
    std::atomic<uint64_t> candidates{ 0 };
    std::atomic<uint64_t> candidateBytes{ 0 };
};

// Области проверки.
std::vector<Root> QuickRoots();      // рискованные папки пользователя и системы
std::vector<Root> FullRoots();       // все локальные несъёмные диски
std::vector<Root> CustomRoots(const std::vector<std::wstring>& paths);

// Обойти корни и выдать кандидатов на проверку. Остановка — через cancel.
// Пути в выдаче — обычные, без префикса \\?\.
void Walk(const std::vector<Root>& roots, const std::vector<std::wstring>& userExcludes,
          const std::atomic<bool>& cancel, Stats& stats,
          const std::function<void(Candidate&&)>& sink);

// Исключения по умолчанию, в нижнем регистре, без завершающего слэша.
std::vector<std::wstring> DefaultExcludes();

// Путь в «рискованной» зоне: загрузки, рабочий стол, временные папки,
// AppData, автозагрузка, общая папка.
bool IsRiskyLocation(const std::wstring& path);

} // namespace FileWalker
