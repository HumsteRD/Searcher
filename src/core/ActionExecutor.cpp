#include "ActionExecutor.h"
#include "Logger.h"

#include <Windows.h>
#include <comdef.h>
#include <taskschd.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <Wbemidl.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "wbemuuid.lib")

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
        return { false, L"missing" };
    }

    if (fs::remove(path, ec)) {
        Logger::Instance().Info("[Action] deleted file: " + WideToUtf8(path));
        return { true, L"deleted" };
    }

    Logger::Instance().Error("[Action] failed to delete: " + WideToUtf8(path));
    return { false, L"denied" };
}

ActionResult ActionExecutor::RemoveRegistryValue(
    const std::wstring& rootAndSubKey, const std::wstring& valueName)
{
    HKEY root;
    std::wstring subKey;
    if (!ParseRegRoot(rootAndSubKey, root, subKey)) {
        return { false, L"bad-path" };
    }

    HKEY hKey;
    LONG r = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (r != ERROR_SUCCESS) {
        return { false, L"denied" };
    }

    r = RegDeleteValueW(hKey, valueName.c_str());
    RegCloseKey(hKey);

    if (r == ERROR_SUCCESS) {
        Logger::Instance().Info("[Action] removed registry value: " +
                                WideToUtf8(valueName));
        return { true, L"entry-removed" };
    }
    return { false, L"denied" };
}

ActionResult ActionExecutor::DeleteScheduledTask(const std::wstring& taskPath) {
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(hrInit);

    ITaskService* service = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
        CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&service);
    if (FAILED(hr) || !service) {
        if (needUninit) CoUninitialize();
        return { false, L"unavailable" };
    }

    service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

    ITaskFolder* root = nullptr;
    hr = service->GetFolder(_bstr_t(L"\\"), &root);
    if (FAILED(hr) || !root) {
        service->Release();
        if (needUninit) CoUninitialize();
        return { false, L"unavailable" };
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
        return { true, L"entry-removed" };
    }
    return { false, L"denied" };
}

ActionResult ActionExecutor::KillProcess(unsigned long pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        return { false, L"missing" };
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);

    if (ok) {
        Logger::Instance().Info("[Action] killed PID " + std::to_string(pid));
        return { true, L"killed" };
    }
    return { false, L"denied" };
}

ActionResult ActionExecutor::DisableService(const std::wstring& serviceName) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return { false, L"denied" };
    SC_HANDLE svc = OpenServiceW(scm, serviceName.c_str(),
                                 SERVICE_CHANGE_CONFIG | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return { false, L"missing" };
    }
    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    const BOOL ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!ok) return { false, L"denied" };
    Logger::Instance().Info("[Action] service disabled: " + WideToUtf8(serviceName));
    return { true, L"disabled" };
}

ActionResult ActionExecutor::RemoveWmiConsumer(const std::wstring& consumerRelPath) {
    if (consumerRelPath.empty()) return { false, L"bad-path" };
    const HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;
    ActionResult result{ false, L"unavailable" };

    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                                   reinterpret_cast<void**>(&loc))) && loc &&
        SUCCEEDED(loc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr, nullptr, 0,
                                     nullptr, nullptr, &svc)) && svc)
    {
        CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                          RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

        // Сначала связки, которые ссылаются на потребителя, — иначе
        // останется «висящая» подписка на несуществующий объект.
        IEnumWbemClassObject* en = nullptr;
        if (SUCCEEDED(svc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT * FROM __FilterToConsumerBinding"),
                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en)) && en)
        {
            IWbemClassObject* obj = nullptr;
            ULONG got = 0;
            while (en->Next(WBEM_INFINITE, 1, &obj, &got) == S_OK && got) {
                VARIANT consumer{}, rel{};
                obj->Get(L"Consumer", 0, &consumer, nullptr, nullptr);
                obj->Get(L"__RELPATH", 0, &rel, nullptr, nullptr);
                if (consumer.vt == VT_BSTR && rel.vt == VT_BSTR && consumer.bstrVal &&
                    std::wstring(consumer.bstrVal).find(consumerRelPath) != std::wstring::npos)
                {
                    svc->DeleteInstance(rel.bstrVal, 0, nullptr, nullptr);
                }
                VariantClear(&consumer);
                VariantClear(&rel);
                obj->Release();
            }
            en->Release();
        }
        const HRESULT hr = svc->DeleteInstance(_bstr_t(consumerRelPath.c_str()), 0, nullptr, nullptr);
        result = SUCCEEDED(hr) ? ActionResult{ true, L"entry-removed" } : ActionResult{ false, L"denied" };
    }
    if (svc) svc->Release();
    if (loc) loc->Release();
    if (SUCCEEDED(co)) CoUninitialize();
    if (result.success) Logger::Instance().Info("[Action] WMI consumer removed: " + WideToUtf8(consumerRelPath));
    return result;
}

ActionResult ActionExecutor::RemoveHostsLine(const std::wstring& line) {
    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    const fs::path hosts = fs::path(sysDir) / L"drivers" / L"etc" / L"hosts";
    const std::string target = WideToUtf8(line);

    std::ifstream in(hosts, std::ios::binary);
    if (!in) return { false, L"missing" };
    std::vector<std::string> lines;
    std::string l;
    bool removed = false;
    while (std::getline(in, l)) {
        std::string trimmed = l;
        if (!trimmed.empty() && trimmed.back() == 13) trimmed.pop_back();
        if (!removed && trimmed == target) { removed = true; continue; }
        lines.push_back(l);
    }
    in.close();
    if (!removed) return { false, L"missing" };

    std::error_code ec;
    fs::copy_file(hosts, fs::path(hosts).concat(L".bak"), fs::copy_options::overwrite_existing, ec);
    std::ofstream out(hosts, std::ios::binary | std::ios::trunc);
    if (!out) return { false, L"denied" };
    for (const std::string& x : lines) out << x << '\n';
    Logger::Instance().Info("[Action] hosts line removed: " + target);
    return { true, L"entry-removed" };
}
