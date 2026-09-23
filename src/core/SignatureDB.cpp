#include "SignatureDB.h"
#include "Logger.h"

#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <Windows.h>
#include <Shlobj.h>

SignatureDB& SignatureDB::Get() {
    static SignatureDB db;
    return db;
}

static std::wstring EnvVar(const wchar_t* name) {
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD n = GetEnvironmentVariableW(name, buf, sizeof(buf) / sizeof(wchar_t));
    if (n == 0 || n >= sizeof(buf) / sizeof(wchar_t)) return {};
    return std::wstring(buf, n);
}

SignatureDB::SignatureDB() {
    LoadBuiltin();
    LoadExternal();
}

void SignatureDB::LoadBuiltin() {
    // === Паттерны подозрительных имён файлов ===
    // Регулярки case-insensitive. Главная идея — поймать:
    //   - маскировку под системные процессы вне System32 (svchost123.exe)
    //   - типичные имена майнеров (xmrig.exe, *miner*.exe)
    //   - типичные имена стилеров (*stealer*, redline.exe)
    //   - длинные случайные имена (a3f7e9d8c4.exe)
    //   - "опасные" расширения (.scr, .pif)
    fileNameRegex_ = {
        std::wregex(LR"(^(svchost|csrss|lsass|services|winlogon|smss|spoolsv|conhost|dwm|explorer)\d+\.exe$)",
                    std::regex::icase),
        std::wregex(LR"(^[a-z0-9]{16,}\.exe$)",     std::regex::icase),
        std::wregex(LR"(^xmrig.*\.exe$)",           std::regex::icase),
        std::wregex(LR"(^.*miner.*\.exe$)",         std::regex::icase),
        std::wregex(LR"(^.*stealer.*\.exe$)",       std::regex::icase),
        std::wregex(LR"(^redline.*\.exe$)",         std::regex::icase),
        std::wregex(LR"(^(unsecapp|sihost|taskhost)\d+\.exe$)", std::regex::icase),
        std::wregex(LR"(^.*\.(scr|pif|com)$)",      std::regex::icase),
    };

    // === Подозрительные пути ===
    pathRegex_ = {
        std::wregex(LR"(.*\\AppData\\Roaming\\[a-z0-9]{8,}\.exe$)",  std::regex::icase),
        std::wregex(LR"(.*\\ProgramData\\[a-z0-9]{8,}\\.+\.exe$)",   std::regex::icase),
        std::wregex(LR"(.*\\Temp\\.+\.(exe|bat|ps1|vbs|js)$)",       std::regex::icase),
        std::wregex(LR"(.*\\Public\\.+\.(exe|dll|bat|ps1)$)",        std::regex::icase),
    };

    // === Известные SHA-256 малвари (примеры, для теста) ===
    // В реальном проекте подгружаются из фидов (MalwareBazaar, abuse.ch).
    // Сейчас пусто — false-positive не получим, но и реальных совпадений тоже.
    knownHashes_ = {
        // "abc123..."
    };

    // === Известные майнинг-пулы (для NetworkScanner) ===
    miningPools_ = {
        "pool.minexmr.com", "xmr.2miners.com", "xmrpool.eu",
        "pool.supportxmr.com", "monero.crypto-pool.fr",
        "gulf.moneroocean.stream", "rx.unmineable.com",
        "ethermine.org", "eth.2miners.com", "f2pool.com",
        "nanopool.org",
    };

    // === Горячие директории для скана ===
    wchar_t winDir[MAX_PATH] = {};
    wchar_t sysDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    GetSystemDirectoryW(sysDir, MAX_PATH);

    auto add = [&](std::wstring p) {
        if (!p.empty()) hotDirs_.push_back(std::move(p));
    };

    // Порядок значим: быстрая проверка берёт первые три каталога,
    // поэтому во главе списка стоит то, куда вредонос попадает чаще всего.
    //
    // Папки профиля раньше отсутствовали целиком — и «Загрузки» в том
    // числе. Из-за этого сканер не заходил в самое очевидное место:
    // туда, куда пользователь скачивает файлы из интернета.
    const std::wstring profile = EnvVar(L"USERPROFILE");
    auto inProfile = [&](const wchar_t* sub) {
        return profile.empty() ? std::wstring() : profile + L"\\" + sub;
    };

    add(EnvVar(L"TEMP"));
    add(inProfile(L"Downloads"));
    add(EnvVar(L"LOCALAPPDATA"));

    // Дальше — то, что обходит только полная проверка.
    add(EnvVar(L"APPDATA"));
    add(inProfile(L"Desktop"));
    add(inProfile(L"Documents"));
    add(EnvVar(L"PROGRAMDATA"));
    add(EnvVar(L"PUBLIC"));
    add(EnvVar(L"ProgramFiles"));
    add(EnvVar(L"ProgramFiles(x86)"));
    add(std::wstring(winDir) + L"\\Tasks");
    add(std::wstring(winDir) + L"\\Prefetch");
    add(std::wstring(sysDir) + L"\\Tasks");

    // Съёмные и дополнительные диски: вредонос часто приезжает на флешке
    // или лежит на втором разделе, куда мы не заглядывали вовсе.
    // Системный диск уже покрыт папками выше, поэтому его пропускаем.
    wchar_t systemDrive[MAX_PATH] = {};
    GetEnvironmentVariableW(L"SystemDrive", systemDrive, MAX_PATH);

    DWORD mask = GetLogicalDrives();
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        if (!(mask & (1u << (letter - L'A')))) continue;

        const std::wstring root = std::wstring(1, letter) + L":";
        if (root == systemDrive) continue;

        const UINT type = GetDriveTypeW((root + L"\\").c_str());
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;

        add(root + L"\\");
    }
}

bool SignatureDB::IsSuspiciousFileName(const std::wstring& name) const {
    for (const auto& r : fileNameRegex_) {
        if (std::regex_match(name, r)) return true;
    }
    return false;
}

bool SignatureDB::IsSuspiciousPath(const std::wstring& path) const {
    for (const auto& r : pathRegex_) {
        if (std::regex_search(path, r)) return true;
    }
    return false;
}

bool SignatureDB::IsKnownMaliciousHash(const std::string& sha) const {
    return knownHashes_.find(sha) != knownHashes_.end();
}

bool SignatureDB::IsKnownMiningPool(const std::string& host) const {
    return miningPools_.find(host) != miningPools_.end();
}

// ─────────────────────────────────────────────────────────────
// Внешняя база: JSON рядом с настройками. Встроенные сигнатуры
// остаются, внешние добавляются поверх — так пользовательский файл
// не может случайно обнулить защиту.
// ─────────────────────────────────────────────────────────────

std::wstring SignatureDB::ExternalPath() {
    const QString dir =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return (dir + "/signatures.json").toStdWString();
}

void SignatureDB::LoadExternal() {
    extHashes_ = extPatterns_ = extPools_ = 0;

    QFile f(QString::fromStdWString(ExternalPath()));
    if (!f.open(QIODevice::ReadOnly)) return;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        Logger::Instance().Error("[SignatureDB] signatures.json is not valid JSON: "
                                 + err.errorString().toStdString());
        return;
    }

    const QJsonObject root = doc.object();

    for (const QJsonValue& v : root["hashes"].toArray()) {
        const QString h = v.toString().trimmed().toLower();
        if (h.size() != 64) continue;          // только SHA-256
        knownHashes_.insert(h.toStdString());
        ++extHashes_;
    }

    for (const QJsonValue& v : root["fileNamePatterns"].toArray()) {
        const QString p = v.toString();
        if (p.isEmpty()) continue;
        try {
            fileNameRegex_.emplace_back(p.toStdWString(), std::regex::icase);
            ++extPatterns_;
        } catch (const std::regex_error&) {
            // Кривое выражение не должно ронять запуск приложения.
            Logger::Instance().Warn("[SignatureDB] bad regex skipped: "
                                    + p.toStdString());
        }
    }

    for (const QJsonValue& v : root["miningPools"].toArray()) {
        const QString h = v.toString().trimmed().toLower();
        if (h.isEmpty()) continue;
        miningPools_.insert(h.toStdString());
        ++extPools_;
    }

    Logger::Instance().Info(
        "[SignatureDB] external signatures loaded: hashes=" +
        std::to_string(extHashes_) + ", patterns=" + std::to_string(extPatterns_) +
        ", pools=" + std::to_string(extPools_));
}

void SignatureDB::Reload() {
    knownHashes_.clear();
    fileNameRegex_.clear();
    miningPools_.clear();
    pathRegex_.clear();
    hotDirs_.clear();

    LoadBuiltin();
    LoadExternal();
}
