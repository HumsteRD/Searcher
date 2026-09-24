#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Извлечение вложенного содержимого для повторной проверки.
//
// Сигнатуры пишутся по настоящему коду программы, а он часто лежит не
// в самом файле, а внутри: в ZIP из «Загрузок» или в архиве, который
// PyInstaller приклеивает к своему загрузчику. Без распаковки такой файл
// выглядит как безобидная обёртка.
//
// Все пределы жёсткие: извлечение не должно стать способом положить
// проверку (архив с коэффициентом сжатия в тысячи раз).
namespace Unpack {

struct Item {
    std::string          name;      // имя внутри контейнера, UTF-8
    std::vector<uint8_t> data;
};

struct Result {
    std::string       container;    // "zip", "pyinstaller" или пусто
    std::vector<Item> items;
    bool              encrypted = false;   // были зашифрованные записи
    int               skipped = 0;         // не извлечено из-за пределов
};

struct Limits {
    size_t maxItemSize  = 48u * 1024 * 1024;
    size_t maxTotalSize = 160u * 1024 * 1024;
    int    maxItems     = 400;
};

// Определить контейнер по содержимому и извлечь то, что имеет смысл
// проверять. Ничего не пишет на диск.
Result Extract(const uint8_t* data, size_t size, const Limits& limits = {});

// zlib-поток (с заголовком) или «сырой» deflate. false — поток испорчен
// или распакованный размер превышает limit.
bool Inflate(const uint8_t* data, size_t size, bool raw, size_t expected,
             size_t limit, std::vector<uint8_t>& out);

} // namespace Unpack
