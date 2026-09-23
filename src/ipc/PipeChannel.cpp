#include "PipeChannel.h"

namespace Ipc {

PipeChannel::~PipeChannel() {
    Close();
}

bool PipeChannel::Attach(HANDLE pipe) {
    if (pipe == INVALID_HANDLE_VALUE || pipe == nullptr) return false;

    // События с ручным сбросом: с автосбросом ожидание и GetOverlappedResult
    // начинают спорить за одно и то же состояние.
    readEvent_  = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    writeEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!readEvent_ || !writeEvent_) {
        if (readEvent_)  CloseHandle(readEvent_);
        if (writeEvent_) CloseHandle(writeEvent_);
        readEvent_ = writeEvent_ = nullptr;
        return false;
    }

    pipe_ = pipe;
    closing_ = false;
    return true;
}

bool PipeChannel::Read(void* buffer, DWORD size, DWORD* read) {
    if (pipe_ == INVALID_HANDLE_VALUE) return false;

    OVERLAPPED overlapped{};
    overlapped.hEvent = readEvent_;
    ResetEvent(readEvent_);

    if (ReadFile(pipe_, buffer, size, read, &overlapped)) return *read > 0;

    if (GetLastError() != ERROR_IO_PENDING) return false;

    if (WaitForSingleObject(readEvent_, INFINITE) != WAIT_OBJECT_0) return false;
    if (closing_) return false;

    return GetOverlappedResult(pipe_, &overlapped, read, FALSE) && *read > 0;
}

bool PipeChannel::Write(const void* data, DWORD size) {
    std::lock_guard<std::mutex> lock(writeMutex_);
    if (pipe_ == INVALID_HANDLE_VALUE) return false;

    const char* cursor = static_cast<const char*>(data);
    DWORD left = size;

    while (left > 0) {
        OVERLAPPED overlapped{};
        overlapped.hEvent = writeEvent_;
        ResetEvent(writeEvent_);

        DWORD written = 0;
        if (!WriteFile(pipe_, cursor, left, &written, &overlapped)) {
            if (GetLastError() != ERROR_IO_PENDING) return false;
            if (WaitForSingleObject(writeEvent_, INFINITE) != WAIT_OBJECT_0)
                return false;
            if (closing_) return false;
            if (!GetOverlappedResult(pipe_, &overlapped, &written, FALSE))
                return false;
        }
        if (written == 0) return false;

        cursor += written;
        left -= written;
    }
    return true;
}

void PipeChannel::Close() {
    if (pipe_ == INVALID_HANDLE_VALUE) return;

    closing_ = true;
    // Снимаем висящее чтение: без этого поток чтения останется в ожидании
    // события, которого уже никто не подаст.
    CancelIoEx(pipe_, nullptr);

    HANDLE pipe = pipe_;
    pipe_ = INVALID_HANDLE_VALUE;

    {
        std::lock_guard<std::mutex> lock(writeMutex_);
        CloseHandle(pipe);
    }

    if (readEvent_)  { CloseHandle(readEvent_);  readEvent_ = nullptr; }
    if (writeEvent_) { CloseHandle(writeEvent_); writeEvent_ = nullptr; }
}

} // namespace Ipc
