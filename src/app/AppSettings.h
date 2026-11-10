#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QStringList>

// Настройки интерфейса и проверки (HKCU\Software\ThreatScanner).
// Помощник их не читает: всё, что нужно проверке, уезжает к нему
// вместе с командой start_scan (scanArgs).
class AppSettings {
public:
    static AppSettings& Get();

    // ─── Проверка ───
    int  scanMode() const;                 // ScanConfig::Mode
    void setScanMode(int mode);
    QStringList customPaths() const;
    void setCustomPaths(const QStringList& paths);
    bool moduleEnabled(int id) const;      // ScanConfig::Module
    void setModuleEnabled(int id, bool on);
    bool extendedRules() const;
    void setExtendedRules(bool on);
    bool reportPua() const;
    void setReportPua(bool on);
    bool unpackArchives() const;
    void setUnpackArchives(bool on);
    bool autoQuarantine() const;
    void setAutoQuarantine(bool on);
    // Нагрузка при проверке файлов: 0 — щадящая, 1 — обычная, 2 — полная.
    int  scanIntensity() const;
    void setScanIntensity(int level);
    static int threadsFor(int intensity);   // 0 — пусть решает ядро

    QStringList excludedPaths() const;
    void setExcludedPaths(const QStringList& paths);
    QStringList allowedHashes() const;
    void addAllowedHash(const QString& sha256, const QString& label);
    void removeAllowedHash(const QString& sha256);
    QString allowedLabel(const QString& sha256) const;

    // Аргументы для помощника: режим, пути, модули, исключения.
    // overridePaths — разовая проверка конкретных путей (перетаскивание).
    QJsonObject scanArgs(int modeOverride = -1, const QStringList& overridePaths = {},
                         bool filesOnly = false) const;

    // ─── Защита ───
    bool downloadGuard() const;
    void setDownloadGuard(bool on);
    // Предлагать проверку подключённой флешки или внешнего диска.
    bool driveGuard() const;
    void setDriveGuard(bool on);
    // Не беспокоить, пока на весь экран идёт игра, фильм или презентация:
    // плановая проверка откладывается, некритичные уведомления не показываются.
    bool quietWhenFullscreen() const;
    void setQuietWhenFullscreen(bool on);

    // ─── Обновления ───
    bool checkUpdatesOnStart() const;      // по умолчанию включено
    void setCheckUpdatesOnStart(bool on);
    bool autoInstallUpdates() const;       // по умолчанию выключено
    void setAutoInstallUpdates(bool on);
    QString skippedVersion() const;
    void setSkippedVersion(const QString& v);
    QDateTime lastUpdateCheck() const;
    void setLastUpdateCheck(const QDateTime& t);

    bool autoUpdateSignatures() const;     // по умолчанию включено
    void setAutoUpdateSignatures(bool on);
    QDateTime lastSignatureUpdate() const;
    void setLastSignatureUpdate(const QDateTime& t);

    // ─── Интеграции ───
    QString virusTotalKey() const;
    void setVirusTotalKey(const QString& key);

    // ─── Окно ───
    QByteArray windowGeometry() const;
    void setWindowGeometry(const QByteArray& g);
    bool firstRunDone() const;
    void setFirstRunDone(bool done);

private:
    AppSettings() = default;
};
