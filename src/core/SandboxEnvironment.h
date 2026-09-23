#pragma once

#include <string>
#include <vector>

// Доступна ли на этой машине Windows Sandbox — и если нет, то почему.
//
// Ответ «нет» здесь не менее важен, чем «да»: без изоляции запускать
// подозрительный файл нельзя, и пользователю надо честно сказать, что
// именно мешает и можно ли это исправить. Разница между «у вас домашняя
// редакция» и «компонент выключен» — это разница между «никак» и
// «включается за две минуты».
class SandboxEnvironment {
public:
    enum class Status {
        Available,          // всё на месте, можно запускать
        NotOnThisEdition,   // Home: компонента нет и не будет
        ComponentMissing,   // редакция подходит, компонент не установлен
        NoVirtualization,   // виртуализация выключена в прошивке
        Unknown,            // определить не удалось — считаем недоступной
    };

    struct Info {
        Status       status = Status::Unknown;
        std::wstring editionName;    // как система себя называет
        std::wstring reason;         // что именно мешает
        std::wstring howToFix;       // пусто, если исправить нельзя
        bool         hasExecutable = false;   // найден WindowsSandbox.exe
    };

    // Результат кэшируется: за время работы приложения редакция Windows
    // не меняется, а установка компонента требует перезагрузки.
    static const Info& Get();
    static bool IsAvailable() { return Get().status == Status::Available; }

    // Пересчитать заново. Нужно только тестам.
    static void Invalidate();
};
