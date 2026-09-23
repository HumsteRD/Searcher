#include "ActionExecutor.h"
#include "Logger.h"

#include <Windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <filesystem>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

namespace fs = std::filesystem;

namespace {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

// Разбирает "HKCU\Software\..." -> HKEY + субключ
bool ParseRegRoot(const std::wstring& full, HKEY& root, std::wstring& subKey) {
    size_t slash = full.find(L'\\');
    if (slash == std::wstring::npos) return false;

    std::wstring rootStr = full.substr(0, slash);
    subKey = full.substr(slash + 1);

    if      (rootStr == L"HKCU" || rootStr == L"HKEY_CURRENT_USER")  root = HKEY_CURRENT_USER;
    else if (rootStr == L"HKLM" || rootStr == L"HKEY_LOCAL_MACHINE") root = HKEY_LOCAL_MACHINE;
    else if (rootStr == L"HKCR" || rootStr == L"HKEY_CLASSES_ROOT")  root = HKEY_CLASSES_ROOT;
    else if (rootStr == L"HKU"  || rootStr == L"HKEY_USERS")         root = HKEY_USERS;
    else return false;

    return true;
}

} // namespace

ActionResult ActionExecutor::RemoveFile(const std::wstring& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        return { false, L"File no longer exists." };
    }

    if (fs::remove(path, ec)) {
        Logger::Instance().Info("[Action] deleted file: " + WideToUtf8(path));
        return { true, L"File deleted." };
    }

    Logger::Instance().Error("[Action] failed to delete: " + WideToUtf8(path));
    return { false, L"Could not delete (file in use or access denied)." };
}

ActionResult ActionExecutor::RemoveRegistryValue(
    const std::wstring& rootAndSubKey, const std::wstring& valueName)
{
    HKEY root;
    std::wstring subKey;
    if (!ParseRegRoot(rootAndSubKey, root, subKey)) {
        return { false, L"Invalid registry path." };
    }

    HKEY hKey;
    LONG r = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (r != ERROR_SUCCESS) {
        return { false, L"Cannot open registry key." };
    }

    r = RegDeleteValueW(hKey, valueName.c_str());
    RegCloseKey(hKey);

    if (r == ERROR_SUCCESS) {
        Logger::Instance().Info("[Action] removed registry value: " +
                                WideToUtf8(valueName));
        return { true, L"Registry value removed." };
    }
    return { false, L"Could not remove registry value." };
}

ActionResult ActionExecutor::DeleteScheduledTask(const std::wstring& taskPath) {
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(hrInit);

    ITaskService* service = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
        CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&service);
    if (FAILED(hr) || !service) {
        if (needUninit) CoUninitialize();
        return { false, L"Cannot connect to Task Scheduler." };
    }

    service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

    ITaskFolder* root = nullptr;
    hr = service->GetFolder(_bstr_t(L"\\"), &root);
    if (FAILED(hr) || !root) {
        service->Release();
        if (needUninit) CoUninitialize();
        return { false, L"Cannot open task folder." };
    }

    // taskPath может быть вида "\MyTask" — DeleteTask хочет имя относительно корня
    std::wstring name = taskPath;
    if (!name.empty() && name.front() == L'\\') name.erase(name.begin());

    hr = root->DeleteTask(_bstr_t(name.c_str()), 0);

    root->Release();
    service->Release();
    if (needUninit) CoUninitialize();

    if (SUCCEEDED(hr)) {
        Logger::Instance().Info("[Action] deleted task: " + WideToUtf8(taskPath));
        return { true, L"Scheduled task deleted." };
    }
    return { false, L"Could not delete scheduled task." };
}

ActionResult ActionExecutor::KillProcess(unsigned long pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        return { false, L"Cannot open process (already gone or access denied)." };
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);

    if (ok) {
        Logger::Instance().Info("[Action] killed PID " + std::to_string(pid));
        return { true, L"Process terminated." };
    }
    return { false, L"Could not terminate process." };
}
