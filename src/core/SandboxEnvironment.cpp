#include "SandboxEnvironment.h"
#include "Logger.h"

#include <Windows.h>
#include <filesystem>
#include <mutex>
#include <optional>

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

std::wstring ReadCurrentVersionString(const wchar_t* name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &key) != ERROR_SUCCESS) {
        return {};
    }

    wchar_t buf[512] = {};
    DWORD   size = sizeof(buf);
    DWORD   type = 0;
    std::wstring out;
    if (RegQueryValueExW(key, name, nullptr, &type,
                         reinterpret_cast<BYTE*>(buf), &size) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        out = buf;
    }
    RegCloseKey(key);
    return out;
}

// Домашние редакции. Windows Sandbox в них не включается никак:
// это не выключенный компонент, а отсутствующий.
bool IsHomeEdition(const std::wstring& editionId) {
    DWORD product = 0;
    if (GetProductInfo(10, 0, 0, 0, &product)) {
        switch (product) {
        case PRODUCT_CORE:                  // Home
        case PRODUCT_CORE_N:
        case PRODUCT_CORE_SINGLELANGUAGE:
        case PRODUCT_CORE_COUNTRYSPECIFIC:
        case PRODUCT_HOME_BASIC:
        case PRODUCT_HOME_PREMIUM:
        case PRODUCT_HOME_BASIC_N:
        case PRODUCT_HOME_PREMIUM_N:
            return true;
        default:
            break;
        }
    }
    // Запасной путь: EditionID домашних редакций начинается с "Core".
    return editionId.rfind(L"Core", 0) == 0;
}

std::wstring SandboxExecutablePath() {
    wchar_t sys[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sys, _countof(sys))) return {};
    return std::wstring(sys) + L"\\WindowsSandbox.exe";
}

SandboxEnvironment::Info Detect() {
    using Status = SandboxEnvironment::Status;
    SandboxEnvironment::Info info;

    const std::wstring editionId  = ReadCurrentVersionString(L"EditionID");
    std::wstring       productName = ReadCurrentVersionString(L"ProductName");

    // На Windows 11 значение ProductName в реестре так и осталось
    // «Windows 10 ...» — Microsoft его не обновила. Показывать это
    // пользователю нельзя: он смотрит на своё окно и видит другое.
    // Настоящая версия определяется номером сборки.
    const std::wstring build = ReadCurrentVersionString(L"CurrentBuildNumber");
    if (!productName.empty() && !build.empty() && _wtoi(build.c_str()) >= 22000) {
        const size_t pos = productName.find(L"Windows 10");
        if (pos != std::wstring::npos) productName.replace(pos, 10, L"Windows 11");
    }

    info.editionName = productName.empty() ? editionId : productName;

    std::error_code ec;
    const std::wstring exe = SandboxExecutablePath();
    info.hasExecutable = !exe.empty() && fs::exists(exe, ec);

    if (info.hasExecutable) {
        // Файл на месте — значит компонент установлен. Запустится ли он,
        // покажет только сам запуск: проверить это заранее, не запуская
        // виртуальную машину, всё равно нельзя.
        info.status = Status::Available;
        return info;
    }

    if (IsHomeEdition(editionId)) {
        info.status  = Status::NotOnThisEdition;
        info.reason  = L"Windows Sandbox is not part of Home editions of Windows.";
        info.howToFix.clear();   // починить нельзя, врать об этом не будем
        return info;
    }

    // PF_VIRT_FIRMWARE_ENABLED отвечает на вопрос о прошивке, а не о
    // компоненте. Спрашиваем только тогда, когда компонента нет: если
    // виртуализация выключена, включать компонент бессмысленно.
    if (!IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED)) {
        info.status   = Status::NoVirtualization;
        info.reason   = L"Hardware virtualization is disabled in firmware.";
        info.howToFix = L"Enable virtualization (Intel VT-x or AMD-V) in the "
                        L"UEFI setup, then install the Windows Sandbox component.";
        return info;
    }

    info.status   = Status::ComponentMissing;
    info.reason   = L"The Windows Sandbox component is not installed.";
    info.howToFix = L"Turn on \"Windows Sandbox\" in Windows Features, "
                    L"or run as administrator: DISM /Online /Enable-Feature "
                    L"/FeatureName:Containers-DisposableClientVM /All";
    return info;
}

std::optional<SandboxEnvironment::Info> g_cached;
std::mutex g_mutex;

} // namespace

const SandboxEnvironment::Info& SandboxEnvironment::Get() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_cached) {
        g_cached = Detect();
        Logger::Instance().Info(
            "[Sandbox] edition: " + WideToUtf8(g_cached->editionName) +
            ", status: " + std::to_string(static_cast<int>(g_cached->status)) +
            (g_cached->reason.empty() ? "" : ", " + WideToUtf8(g_cached->reason)));
    }
    return *g_cached;
}

void SandboxEnvironment::Invalidate() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_cached.reset();
}
