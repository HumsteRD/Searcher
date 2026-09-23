#include "ServiceConfig.h"

#include <Windows.h>
#include <ShlObj.h>

namespace ServiceConfig {
namespace {

DWORD ReadDword(HKEY key, const wchar_t* name, DWORD fallback) {
    DWORD value = 0, size = sizeof(value), type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type,
                         reinterpret_cast<BYTE*>(&value), &size) == ERROR_SUCCESS
        && type == REG_DWORD) {
        return value;
    }
    return fallback;
}

} // namespace

Settings Read() {
    Settings settings;

    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKeyPath, 0, KEY_READ, &key)
        != ERROR_SUCCESS) {
        return settings;   // ключа нет — служба не настраивалась
    }

    settings.enabled       = ReadDword(key, L"Enabled", 0) != 0;
    settings.intervalHours = static_cast<int>(ReadDword(key, L"IntervalHours", 24));
    settings.deepScan      = ReadDword(key, L"DeepScan", 0) != 0;
    RegCloseKey(key);

    // Слишком частая фоновая проверка — это не «надёжнее», а постоянно
    // занятый диск. Реже раза в неделю расписание теряет смысл.
    if (settings.intervalHours < 1)   settings.intervalHours = 1;
    if (settings.intervalHours > 168) settings.intervalHours = 168;
    return settings;
}

bool Write(const Settings& settings) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kKeyPath, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return false;
    }

    const DWORD enabled  = settings.enabled ? 1 : 0;
    const DWORD interval = static_cast<DWORD>(settings.intervalHours);
    const DWORD deep     = settings.deepScan ? 1 : 0;

    bool ok = RegSetValueExW(key, L"Enabled", 0, REG_DWORD,
                             reinterpret_cast<const BYTE*>(&enabled),
                             sizeof(enabled)) == ERROR_SUCCESS;
    ok = ok && RegSetValueExW(key, L"IntervalHours", 0, REG_DWORD,
                              reinterpret_cast<const BYTE*>(&interval),
                              sizeof(interval)) == ERROR_SUCCESS;
    ok = ok && RegSetValueExW(key, L"DeepScan", 0, REG_DWORD,
                              reinterpret_cast<const BYTE*>(&deep),
                              sizeof(deep)) == ERROR_SUCCESS;

    RegCloseKey(key);
    return ok;
}

State QueryState() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return State::Unknown;

    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
    if (!service) {
        const DWORD error = GetLastError();
        CloseServiceHandle(manager);
        return error == ERROR_SERVICE_DOES_NOT_EXIST ? State::NotInstalled
                                                     : State::Unknown;
    }

    SERVICE_STATUS status{};
    const bool ok = QueryServiceStatus(service, &status) != FALSE;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    if (!ok) return State::Unknown;
    return status.dwCurrentState == SERVICE_RUNNING ? State::Running
                                                    : State::Stopped;
}

std::wstring ResultsPath() {
    // %ProgramData%: служба под SYSTEM и приложение под пользователем
    // должны видеть один и тот же файл, а профиль пользователя службе
    // недоступен.
    PWSTR folder = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &folder)))
        return {};

    std::wstring path(folder);
    CoTaskMemFree(folder);

    path += L"\\ThreatScanner";
    CreateDirectoryW(path.c_str(), nullptr);
    return path + L"\\service-scans.json";
}

} // namespace ServiceConfig
