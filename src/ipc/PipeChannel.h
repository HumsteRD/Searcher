#pragma once

#include <mutex>
#include <atomic>
#include <Windows.h>

namespace Ipc {

// Дуплексный канал поверх одного дескриптора именованного канала.
//
// Существует ровно из-за одной особенности Windows: синхронные операции
// на одном дескрипторе выполняются по очереди. Поток чтения стоит в
// ReadFile, который ждёт данных, — и запись из другого потока встаёт
// в очередь за ним и не выполняется никогда. Разговор в обе стороны
// на одном дескрипторе возможен только через перекрывающийся ввод-вывод
// с отдельным событием на каждое направление.
class PipeChannel {
public:
    PipeChannel() = default;
    ~PipeChannel();

    PipeChannel(const PipeChannel&) = delete;
    PipeChannel& operator=(const PipeChannel&) = delete;

    // Принимает дескриптор, открытый с FILE_FLAG_OVERLAPPED.
    bool Attach(HANDLE pipe);

    bool valid() const { return pipe_ != INVALID_HANDLE_VALUE; }

    // Блокирующее чтение. false — канал закрыт или оборван.
    bool Read(void* buffer, DWORD size, DWORD* read);

    // Блокирующая запись целиком. Потокобезопасна.
    bool Write(const void* data, DWORD size);

    // Прерывает висящие операции и закрывает дескриптор.
    void Close();

private:
    HANDLE     pipe_ = INVALID_HANDLE_VALUE;
    HANDLE     readEvent_ = nullptr;
    HANDLE     writeEvent_ = nullptr;
    std::mutex writeMutex_;
    std::atomic<bool> closing_{ false };
};

} // namespace Ipc
