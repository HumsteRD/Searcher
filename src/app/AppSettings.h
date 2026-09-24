#pragma once

#include <string>
#include <atomic>
#include <mutex>

// Настройки приложения.
// Заголовок намеренно свободен от Qt, чтобы его мог включать чистый
// core-код (FileSystemScanner и т.п.). Персист через QSettings — в .cpp.
class AppSettings {
public:
    static AppSettings& Get();

    // Глубокое сканирование: хэшировать все исполняемые файлы,
    // а не только помеченные эвристикой, и обходить дерево глубже.
    bool DeepScan() const { return deepScan_.load(); }
    void SetDeepScan(bool v);

    // Автоматически отправлять Critical-угрозы в карантин.
    bool AutoQuarantine() const { return autoQuarantine_.load(); }
    void SetAutoQuarantine(bool v);

    std::string VirusTotalKey() const;
    void SetVirusTotalKey(const std::string& key);

    // ─── Область проверки ───
    // Quick  — только самые рискованные папки, малая глубина;
    // Full   — весь список рискованных папок;
    // Custom — одна выбранная пользователем папка.
    enum class ScanMode { Quick = 0, Full = 1, Custom = 2 };

    ScanMode Mode() const { return static_cast<ScanMode>(mode_.load()); }
    void SetMode(ScanMode m);

    std::wstring CustomPath() const;
    void SetCustomPath(const std::wstring& path);

    // Включённые модули. Индекс — ModuleId.
    // Порядок обязан совпадать с порядком регистрации модулей
    // в MainWindow: Scanner отбирает их по этому индексу.
    enum ModuleId { ModRegistry = 0, ModFiles, ModProcesses,
                    ModNetwork, ModTasks, ModScripts, ModPersistence,
                    ModuleCount };

    bool ModuleEnabled(int id) const;
    void SetModuleEnabled(int id, bool on);

private:
    AppSettings();
    AppSettings(const AppSettings&) = delete;
    AppSettings& operator=(const AppSettings&) = delete;

    void Save();

    std::atomic<bool> deepScan_{ false };
    std::atomic<bool> autoQuarantine_{ false };

    std::atomic<int>  mode_{ 1 };   // по умолчанию полная проверка
    std::atomic<bool> modules_[ModuleCount] =
        { {true}, {true}, {true}, {true}, {true}, {true}, {true} };

    mutable std::mutex mutex_;
    std::string        vtKey_;
    std::wstring       customPath_;
};
