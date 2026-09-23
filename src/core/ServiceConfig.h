#pragma once

#include <string>

// Настройка фоновой службы. Лежит в HKLM, потому что читает её служба
// под учётной записью SYSTEM, а туда, где живут настройки пользователя,
// она не заглядывает.
//
// Писать в HKLM может только администратор — то есть помощник. Служба
// эту ветку только читает: даже если её конфигурацию кто-то подменит,
// он должен уже иметь права администратора, а с ними подмена настроек
// службы — далеко не самое интересное, что можно сделать.
namespace ServiceConfig {

inline constexpr const wchar_t* kKeyPath =
    L"SOFTWARE\\ThreatScanner\\Service";

inline constexpr const wchar_t* kServiceName = L"ThreatScannerService";
inline constexpr const wchar_t* kDisplayName = L"Threat Scanner background scans";

struct Settings {
    bool enabled = false;
    int  intervalHours = 24;      // как часто проверять
    bool deepScan = false;
};

// Чтение доступно всем, запись — только с правами администратора.
Settings Read();
bool     Write(const Settings& settings);

// Состояние службы. Спрашивать диспетчер служб о состоянии может кто
// угодно — права нужны только чтобы ставить и снимать. Поэтому интерфейс
// узнаёт его сам, без помощника и без запроса UAC на каждом открытии
// настроек.
enum class State { NotInstalled, Stopped, Running, Unknown };
State QueryState();

// Куда служба складывает результаты: у неё нет своего окна, и показать
// их некому до следующего запуска приложения.
std::wstring ResultsPath();

} // namespace ServiceConfig
