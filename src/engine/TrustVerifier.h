#pragma once

#include <string>

// Проверка цифровой подписи файла: встроенной (Authenticode) и каталожной.
//
// Каталожная подпись — это то, чем подписана большая часть файлов Windows:
// в самом файле подписи нет, его хэш записан в подписанный каталог .cat.
// Прежняя проверка смотрела только встроенную подпись, и системные файлы
// выглядели неподписанными — отсюда ложные срабатывания на Microsoft.
namespace TrustVerifier {

struct Result {
    bool         signedValid = false;   // подпись есть и проверена
    bool         catalog     = false;   // подпись каталожная
    bool         trustedVendor = false; // издатель из списка крупных вендоров
    std::wstring publisher;             // CN сертификата подписанта
};

// Результат кэшируется по пути, размеру и времени изменения.
Result Check(const std::wstring& path);

// Точное сравнение издателя со списком — без подстрок: "msi" не должен
// совпадать с любым именем, где встречаются эти три буквы.
bool IsTrustedVendor(const std::wstring& publisher);

} // namespace TrustVerifier
