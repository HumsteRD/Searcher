#include "AppSettings.h"

#include <QSettings>
#include <QString>

namespace {

// Явные org/app, чтобы не зависеть от того, выставил ли их main().
// QSettings некопируем, поэтому создаём его на месте, а не возвращаем из функции.
constexpr const char* kOrg = "ThreatScanner";
constexpr const char* kApp = "ThreatScanner";

constexpr const char* kKeyDeepScan   = "scan/deepScan";
constexpr const char* kKeyAutoQuar   = "scan/autoQuarantine";
constexpr const char* kKeyVtApiKey   = "integrations/virusTotalKey";
constexpr const char* kKeyMode       = "scan/mode";
constexpr const char* kKeyCustom     = "scan/customPath";
constexpr const char* kKeyModule     = "scan/module";

} // namespace

AppSettings& AppSettings::Get() {
    static AppSettings s;
    return s;
}

AppSettings::AppSettings() {
    QSettings store(kOrg, kApp);
    deepScan_.store(store.value(kKeyDeepScan, false).toBool());
    autoQuarantine_.store(store.value(kKeyAutoQuar, false).toBool());
    vtKey_ = store.value(kKeyVtApiKey, QString()).toString().toStdString();

    mode_.store(store.value(kKeyMode, 1).toInt());
    customPath_ = store.value(kKeyCustom, QString()).toString().toStdWString();
    for (int i = 0; i < ModuleCount; ++i) {
        modules_[i].store(
            store.value(QString(kKeyModule) + QString::number(i), true).toBool());
    }
}

void AppSettings::Save() {
    QSettings store(kOrg, kApp);
    store.setValue(kKeyDeepScan, deepScan_.load());
    store.setValue(kKeyAutoQuar, autoQuarantine_.load());
    {
        std::lock_guard<std::mutex> lock(mutex_);
        store.setValue(kKeyVtApiKey, QString::fromStdString(vtKey_));
    }
    store.setValue(kKeyMode, mode_.load());
    {
        std::lock_guard<std::mutex> lock(mutex_);
        store.setValue(kKeyCustom, QString::fromStdWString(customPath_));
    }
    for (int i = 0; i < ModuleCount; ++i) {
        store.setValue(QString(kKeyModule) + QString::number(i),
                       modules_[i].load());
    }
    store.sync();
}

void AppSettings::SetMode(ScanMode m) {
    mode_.store(static_cast<int>(m));
    Save();
}

std::wstring AppSettings::CustomPath() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return customPath_;
}

void AppSettings::SetCustomPath(const std::wstring& path) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        customPath_ = path;
    }
    Save();
}

bool AppSettings::ModuleEnabled(int id) const {
    if (id < 0 || id >= ModuleCount) return true;
    return modules_[id].load();
}

void AppSettings::SetModuleEnabled(int id, bool on) {
    if (id < 0 || id >= ModuleCount) return;
    modules_[id].store(on);
    Save();
}

void AppSettings::SetDeepScan(bool v) {
    deepScan_.store(v);
    Save();
}

void AppSettings::SetAutoQuarantine(bool v) {
    autoQuarantine_.store(v);
    Save();
}

std::string AppSettings::VirusTotalKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return vtKey_;
}

void AppSettings::SetVirusTotalKey(const std::string& key) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        vtKey_ = key;
    }
    Save();
}
