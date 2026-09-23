#include "PipeSecurity.h"

#include <sddl.h>
#include <vector>
#include <algorithm>
#include <cwctype>

#pragma comment(lib, "advapi32.lib")

namespace Ipc {
namespace {

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

// SID текущего пользователя строкой. У помощника, поднятого через UAC,
// учётная запись та же, что у интерфейса, — на этом и держится проверка.
bool CurrentUserSidString(std::wstring& out) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0) { CloseHandle(token); return false; }

    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);

    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &text)) return false;

    out = text;
    LocalFree(text);
    return true;
}

// SID пользователя, от имени которого работает чужой процесс.
bool ProcessUserSidString(HANDLE process, std::wstring& out) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
        return false;

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0) { CloseHandle(token); return false; }

    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);

    auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &text)) return false;

    out = text;
    LocalFree(text);
    return true;
}

std::wstring ProcessImagePath(HANDLE process) {
    wchar_t buffer[MAX_PATH * 4] = {};
    DWORD size = _countof(buffer);
    std::wstring path;
    if (QueryFullProcessImageNameW(process, 0, buffer, &size))
        path.assign(buffer, size);
    return path;
}

} // namespace

PipeSecurity::PipeSecurity() {
    std::wstring sid;
    if (!CurrentUserSidString(sid)) return;

    // D:P — свой список без наследования. Полный доступ системе и
    // администраторам, чтение и запись — текущему пользователю: именно
    // он и открывает канал из непривилегированного интерфейса.
    const std::wstring sddl =
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + sid + L")";

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor_, nullptr)) {
        return;
    }

    attributes_.nLength = sizeof(attributes_);
    attributes_.lpSecurityDescriptor = descriptor_;
    attributes_.bInheritHandle = FALSE;
    valid_ = true;
}

PipeSecurity::~PipeSecurity() {
    if (descriptor_) LocalFree(descriptor_);
}

bool VerifyPipeClient(HANDLE pipe, const std::wstring& expectedImage,
                      std::wstring* reason)
{
    auto fail = [&](const std::wstring& text) {
        if (reason) *reason = text;
        return false;
    };

    std::wstring ours;
    if (!CurrentUserSidString(ours)) return fail(L"cannot read own user SID");

    // Через олицетворение проверять нельзя: ImpersonateNamedPipeClient
    // работает только после того, как клиент что-то прислал, а мы
    // проверяем его до первой команды — принимать команды от непроверенного
    // как раз и не хочется. Поэтому смотрим прямо на процесс.
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid))
        return fail(L"cannot read the client process id");

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return fail(L"cannot open the client process");

    // Обе проверки — по одному дескриптору: если брать их по номеру
    // процесса дважды, между ними номер может достаться другому процессу.
    std::wstring theirs;
    const bool gotSid = ProcessUserSidString(process, theirs);
    const std::wstring image = ProcessImagePath(process);
    CloseHandle(process);

    if (!gotSid) return fail(L"cannot read the client user SID");
    if (theirs != ours) return fail(L"the client runs as a different user");

    // Тот самый образ. Подменить его может только процесс того же
    // пользователя — то есть тот, кто и так может всё, что может
    // пользователь. Проверка отсекает случайное, а не злонамеренное.
    if (image.empty()) return fail(L"cannot read the client image path");
    if (ToLower(image) != ToLower(expectedImage))
        return fail(L"the client is not the application: " + image);

    return true;
}

} // namespace Ipc
