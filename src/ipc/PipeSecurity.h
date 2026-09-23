#pragma once

#include <string>
#include <Windows.h>

namespace Ipc {

// Кто имеет право открыть канал помощника.
//
// Канал создаёт процесс с полными правами, а открывает его процесс без
// прав — то есть это ровно та граница, через которую в обратную сторону
// Windows не пускает никого. Значит, защищать её должны мы сами:
// список доступа только на текущего пользователя, SYSTEM и администраторов.
//
// Чего это НЕ даёт: защиты от другого процесса того же пользователя.
// В модели Windows всё, что запущено под одной учётной записью, равно
// в правах — такой процесс может и подменить сам исполняемый файл
// интерфейса. UAC не является границей безопасности, и притворяться,
// что здесь она есть, нельзя.
class PipeSecurity {
public:
    PipeSecurity();
    ~PipeSecurity();

    PipeSecurity(const PipeSecurity&) = delete;
    PipeSecurity& operator=(const PipeSecurity&) = delete;

    bool valid() const { return valid_; }
    SECURITY_ATTRIBUTES* attributes() { return valid_ ? &attributes_ : nullptr; }

private:
    PSECURITY_DESCRIPTOR descriptor_ = nullptr;
    SECURITY_ATTRIBUTES  attributes_{};
    bool                 valid_ = false;
};

// Проверка подключившегося: та же учётная запись и ожидаемый образ.
// expectedImage — полный путь к тому, что имеет право подключаться.
// reason заполняется при отказе; может быть nullptr.
bool VerifyPipeClient(HANDLE pipe, const std::wstring& expectedImage,
                      std::wstring* reason = nullptr);

} // namespace Ipc
