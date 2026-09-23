#include "RegistryActivityWatcher.h"
#include "Logger.h"

#include <sstream>
#include <iomanip>

namespace {

// Разделитель «ключ|значение» в слепке. В именах ключей реестра
// вертикальная черта не встречается, поэтому склейка однозначна.
constexpr wchar_t kSep = L'|';

// Маркер существования подключа: у ключа нет собственного значения,
// но его появление и исчезновение — тоже событие.
const wchar_t* kKeyMarker = L"<key>";

// Потолок на размер слепка. Без него наблюдение за Services на машине
// с сотнями служб превращается в перебор десятков тысяч значений
// после каждого чиха.
constexpr int kSnapshotBudget = 20000;

// Задержка перед пересъёмкой: изменения приходят пачками (запись
// значения — это несколько операций), и без неё диф делается по
// полуготовому состоянию, а потом ещё раз по готовому.
constexpr DWORD kDebounceMs = 120;

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring RootName(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE)  return L"HKLM";
    if (root == HKEY_CURRENT_USER)   return L"HKCU";
    if (root == HKEY_CLASSES_ROOT)   return L"HKCR";
    if (root == HKEY_USERS)          return L"HKU";
    if (root == HKEY_CURRENT_CONFIG) return L"HKCC";
    return L"HKEY";
}

std::wstring ValueToString(DWORD type, const BYTE* data, DWORD size) {
    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        std::wstring s(reinterpret_cast<const wchar_t*>(data),
                       size / sizeof(wchar_t));
        while (!s.empty() && s.back() == L'\0') s.pop_back();
        return s;
    }
    case REG_MULTI_SZ: {
        std::wstring out;
        const wchar_t* p = reinterpret_cast<const wchar_t*>(data);
        const wchar_t* end = p + size / sizeof(wchar_t);
        while (p < end && *p) {
            if (!out.empty()) out += L"; ";
            out += p;
            p += wcslen(p) + 1;
        }
        return out;
    }
    case REG_DWORD:
        if (size >= sizeof(DWORD))
            return std::to_wstring(*reinterpret_cast<const DWORD*>(data));
        return L"";
    case REG_QWORD:
        if (size >= sizeof(ULONGLONG))
            return std::to_wstring(*reinterpret_cast<const ULONGLONG*>(data));
        return L"";
    default: {
        // Двоичное значение целиком в отчёт не нужно: важен сам факт
        // изменения, а не гигабайт шестнадцатеричных цифр.
        std::wostringstream os;
        os << L"binary[" << size << L"]";
        DWORD shown = size < 16 ? size : 16;
        if (shown) {
            os << L" ";
            for (DWORD i = 0; i < shown; ++i)
                os << std::hex << std::setw(2) << std::setfill(L'0')
                   << static_cast<unsigned>(data[i]);
            if (shown < size) os << L"...";
        }
        return os.str();
    }
    }
}

// Обрезка длинных строк: командные строки дропперов бывают на килобайт.
std::wstring Shorten(const std::wstring& s, size_t limit = 300) {
    if (s.size() <= limit) return s;
    return s.substr(0, limit) + L"...";
}

void SnapshotKey(HKEY handle, const std::wstring& display,
                 int depth, int maxDepth,
                 std::map<std::wstring, std::wstring>& out, int& budget)
{
    if (budget <= 0) return;

    // Значения самого ключа.
    for (DWORD i = 0; budget > 0; ++i) {
        wchar_t name[16384];
        DWORD   nameLen = _countof(name);
        DWORD   type = 0;
        DWORD   dataLen = 0;

        LONG rc = RegEnumValueW(handle, i, name, &nameLen, nullptr,
                                &type, nullptr, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA) break;

        std::wstring repr;
        if (dataLen > 0 && dataLen <= 64 * 1024) {
            std::vector<BYTE> data(dataLen);
            DWORD got = dataLen;
            nameLen = _countof(name);
            if (RegEnumValueW(handle, i, name, &nameLen, nullptr,
                              &type, data.data(), &got) == ERROR_SUCCESS) {
                repr = ValueToString(type, data.data(), got);
            }
        } else if (dataLen > 64 * 1024) {
            repr = L"binary[" + std::to_wstring(dataLen) + L"]";
        }

        out[display + kSep + std::wstring(name, nameLen)] = repr;
        --budget;
    }

    // Подключи: имена фиксируем всегда, внутрь заходим по глубине.
    for (DWORD i = 0; budget > 0; ++i) {
        wchar_t sub[512];
        DWORD   subLen = _countof(sub);
        LONG rc = RegEnumKeyExW(handle, i, sub, &subLen,
                                nullptr, nullptr, nullptr, nullptr);
        if (rc != ERROR_SUCCESS) break;

        std::wstring childDisplay = display + L"\\" + std::wstring(sub, subLen);
        out[childDisplay + kSep] = kKeyMarker;
        --budget;

        if (depth + 1 < maxDepth) {
            HKEY child = nullptr;
            if (RegOpenKeyExW(handle, sub, 0, KEY_READ, &child) == ERROR_SUCCESS) {
                SnapshotKey(child, childDisplay, depth + 1, maxDepth, out, budget);
                RegCloseKey(child);
            }
        }
    }
}

} // namespace

std::vector<RegistryActivityWatcher::WatchedKey>
RegistryActivityWatcher::DefaultKeys()
{
    return {
        { HKEY_CURRENT_USER,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          L"HKCU Run", false, 1 },
        { HKEY_CURRENT_USER,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          L"HKCU RunOnce", false, 1 },
        { HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          L"HKLM Run", false, 1 },
        { HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          L"HKLM RunOnce", false, 1 },
        { HKEY_LOCAL_MACHINE,
          L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
          L"HKLM Run (Wow64)", false, 1 },
        { HKEY_CURRENT_USER,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
          L"HKCU Policies Run", false, 1 },
        { HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
          L"HKLM Policies Run", false, 1 },

        // Winlogon: Shell и Userinit подменяют, чтобы стартовать до explorer.
        { HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
          L"Winlogon", true, 1 },

        // IFEO: значение Debugger подменяет запуск любой программы.
        { HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
          L"Image File Execution Options", true, 2 },

        // Службы: интересен факт появления новой, а не её содержимое,
        // поэтому глубина 1 — только имена подключей.
        { HKEY_LOCAL_MACHINE,
          L"System\\CurrentControlSet\\Services",
          L"Services", true, 1 },

        { HKEY_CURRENT_USER, L"Environment",
          L"User environment", false, 1 },
        { HKEY_LOCAL_MACHINE,
          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
          L"Browser Helper Objects", true, 1 },
    };
}

RegistryActivityWatcher::~RegistryActivityWatcher() {
    Stop();
}

bool RegistryActivityWatcher::Start(const std::vector<WatchedKey>& keys,
                                    BehaviorSink sink)
{
    if (stopEvent_) return false;
    sink_ = std::move(sink);

    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) return false;

    // WaitForMultipleObjects берёт максимум 64 объекта, один занят
    // событием остановки.
    const size_t kMaxKeys = MAXIMUM_WAIT_OBJECTS - 1;

    for (const auto& k : keys) {
        if (entries_.size() >= kMaxKeys) {
            Logger::Instance().Warn("[Dyn/Reg] key limit reached, rest skipped");
            break;
        }

        Entry e;
        e.key = k;
        if (RegOpenKeyExW(k.root, k.subKey.c_str(), 0,
                          KEY_READ | KEY_NOTIFY, &e.handle) != ERROR_SUCCESS) {
            // Ключа может не быть (Wow6432Node на чистой системе) или
            // не хватать прав — это не повод валить всё наблюдение.
            continue;
        }

        e.event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!e.event) {
            RegCloseKey(e.handle);
            continue;
        }

        int budget = kSnapshotBudget;
        SnapshotKey(e.handle, RootName(k.root) + L"\\" + k.subKey,
                    0, k.recursive ? k.maxDepth : 1, e.snapshot, budget);

        entries_.push_back(std::move(e));
        if (!Arm(entries_.back())) {
            Logger::Instance().Warn("[Dyn/Reg] notify failed for " +
                                    WideToUtf8(k.label));
            continue;
        }
        watched_.push_back(k.label);
    }

    if (entries_.empty()) {
        Stop();
        return false;
    }

    thread_ = std::thread([this] { Pump(); });
    return true;
}

bool RegistryActivityWatcher::Arm(Entry& entry) {
    return RegNotifyChangeKeyValue(
               entry.handle,
               entry.key.recursive ? TRUE : FALSE,
               REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET |
                   REG_NOTIFY_THREAD_AGNOSTIC,
               entry.event,
               TRUE) == ERROR_SUCCESS;
}

void RegistryActivityWatcher::Stop() {
    if (!stopEvent_) return;

    stopping_ = true;
    SetEvent(stopEvent_);
    if (thread_.joinable()) thread_.join();

    for (auto& e : entries_) {
        if (e.handle) RegCloseKey(e.handle);
        if (e.event)  CloseHandle(e.event);
    }
    entries_.clear();
    watched_.clear();

    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
    stopping_ = false;
}

void RegistryActivityWatcher::Emit(BehaviorEventType type,
                                   const std::wstring& target,
                                   const std::wstring& detail)
{
    if (!sink_) return;
    BehaviorEvent e;
    e.type   = type;
    e.pid    = 0;    // автор изменения в пользовательском режиме не виден
    e.target = target;
    e.detail = detail;
    sink_(std::move(e));
}

void RegistryActivityWatcher::DiffAndEmit(Entry& entry) {
    Snapshot fresh;
    int budget = kSnapshotBudget;
    SnapshotKey(entry.handle,
                RootName(entry.key.root) + L"\\" + entry.key.subKey,
                0, entry.key.recursive ? entry.key.maxDepth : 1,
                fresh, budget);

    for (const auto& [path, value] : fresh) {
        auto it = entry.snapshot.find(path);
        const bool isKey = !path.empty() && path.back() == kSep;

        if (it == entry.snapshot.end()) {
            Emit(isKey ? BehaviorEventType::RegistryKeyCreated
                       : BehaviorEventType::RegistryValueSet,
                 path, isKey ? std::wstring() : Shorten(value));
        } else if (!isKey && it->second != value) {
            Emit(BehaviorEventType::RegistryValueChanged, path,
                 Shorten(it->second) + L" -> " + Shorten(value));
        }
    }

    for (const auto& [path, value] : entry.snapshot) {
        if (fresh.find(path) != fresh.end()) continue;
        const bool isKey = !path.empty() && path.back() == kSep;
        Emit(isKey ? BehaviorEventType::RegistryKeyDeleted
                   : BehaviorEventType::RegistryValueDeleted,
             path, isKey ? std::wstring() : Shorten(value));
    }

    entry.snapshot = std::move(fresh);
}

void RegistryActivityWatcher::Pump() {
    std::vector<HANDLE> handles;
    handles.reserve(entries_.size() + 1);
    for (auto& e : entries_) handles.push_back(e.event);
    handles.push_back(stopEvent_);   // последний индекс — остановка

    const DWORD stopIndex = static_cast<DWORD>(handles.size() - 1);

    for (;;) {
        DWORD rc = WaitForMultipleObjects(static_cast<DWORD>(handles.size()),
                                          handles.data(), FALSE, INFINITE);
        if (rc == WAIT_FAILED) break;

        DWORD index = rc - WAIT_OBJECT_0;
        if (index == stopIndex || stopping_) break;
        if (index >= entries_.size()) break;

        Entry& entry = entries_[index];

        // Сначала перезаряжаем подписку, потом снимаем слепок: иначе
        // изменение между слепком и перезарядкой пропадёт совсем.
        // Лишний холостой сигнал безобиден — диф просто выйдет пустым.
        Arm(entry);

        if (WaitForSingleObject(stopEvent_, kDebounceMs) == WAIT_OBJECT_0) break;

        DiffAndEmit(entry);
    }
}
