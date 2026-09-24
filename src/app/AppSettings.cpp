#include "AppSettings.h"

#include "../core/ScanConfig.h"

#include <QJsonArray>
#include <QSettings>

namespace {

// Настройки второй версии лежат в своей ветке: у первой другой порядок
// модулей и режим «выборочная» записывался при каждом перетаскивании —
// унаследованные значения включали бы не то.
QVariant Read(const char* key, const QVariant& def) {
    QSettings s("ThreatScanner", "ThreatScanner");
    return s.value(QStringLiteral("v2/") + key, def);
}

void Write(const char* key, const QVariant& value) {
    QSettings s("ThreatScanner", "ThreatScanner");
    s.setValue(QStringLiteral("v2/") + key, value);
}

} // namespace

AppSettings& AppSettings::Get() {
    static AppSettings s;
    return s;
}

int  AppSettings::scanMode() const { return std::clamp(Read("scan/mode", 0).toInt(), 0, 2); }
void AppSettings::setScanMode(int mode) { Write("scan/mode", mode); }

QStringList AppSettings::customPaths() const { return Read("scan/paths", QStringList()).toStringList(); }
void AppSettings::setCustomPaths(const QStringList& p) { Write("scan/paths", p); }

bool AppSettings::moduleEnabled(int id) const {
    return Read(QString("scan/module%1").arg(id).toUtf8().constData(), true).toBool();
}
void AppSettings::setModuleEnabled(int id, bool on) {
    Write(QString("scan/module%1").arg(id).toUtf8().constData(), on);
}

bool AppSettings::extendedRules() const { return Read("scan/extendedRules", false).toBool(); }
void AppSettings::setExtendedRules(bool on) { Write("scan/extendedRules", on); }
bool AppSettings::reportPua() const { return Read("scan/reportPua", false).toBool(); }
void AppSettings::setReportPua(bool on) { Write("scan/reportPua", on); }
bool AppSettings::unpackArchives() const { return Read("scan/unpack", true).toBool(); }
void AppSettings::setUnpackArchives(bool on) { Write("scan/unpack", on); }
bool AppSettings::autoQuarantine() const { return Read("scan/autoQuarantine", false).toBool(); }
void AppSettings::setAutoQuarantine(bool on) { Write("scan/autoQuarantine", on); }

QStringList AppSettings::excludedPaths() const { return Read("scan/excluded", QStringList()).toStringList(); }
void AppSettings::setExcludedPaths(const QStringList& p) { Write("scan/excluded", p); }

QStringList AppSettings::allowedHashes() const {
    QSettings s("ThreatScanner", "ThreatScanner");
    s.beginGroup("allowed");
    return s.childKeys();
}

void AppSettings::addAllowedHash(const QString& sha, const QString& label) {
    if (sha.size() != 64) return;
    QSettings s("ThreatScanner", "ThreatScanner");
    s.setValue("allowed/" + sha.toLower(), label);
}

void AppSettings::removeAllowedHash(const QString& sha) {
    QSettings s("ThreatScanner", "ThreatScanner");
    s.remove("allowed/" + sha.toLower());
}

QString AppSettings::allowedLabel(const QString& sha) const {
    QSettings s("ThreatScanner", "ThreatScanner");
    return s.value("allowed/" + sha.toLower()).toString();
}

QJsonObject AppSettings::scanArgs(int modeOverride, const QStringList& overridePaths,
                                  bool filesOnly) const
{
    QJsonObject a;
    const int mode = modeOverride >= 0 ? modeOverride : scanMode();
    a["mode"] = mode;
    const QStringList paths = overridePaths.isEmpty() ? customPaths() : overridePaths;
    a["paths"] = QJsonArray::fromStringList(paths);

    QJsonArray modules;
    for (int i = 0; i < ScanConfig::ModuleCount; ++i) {
        // Разовая проверка выбранного файла: остальные модули к нему
        // отношения не имеют, а пользователь ждёт вердикт именно по нему.
        modules.append(filesOnly ? i == ScanConfig::Files : moduleEnabled(i));
    }
    a["modules"]        = modules;
    a["extendedRules"]  = extendedRules();
    a["reportPua"]      = reportPua();
    a["unpackArchives"] = unpackArchives();
    a["excludedPaths"]  = QJsonArray::fromStringList(excludedPaths());
    a["allowedHashes"]  = QJsonArray::fromStringList(allowedHashes());
    return a;
}

bool AppSettings::downloadGuard() const { return Read("protect/downloadGuard", true).toBool(); }
void AppSettings::setDownloadGuard(bool on) { Write("protect/downloadGuard", on); }

bool AppSettings::checkUpdatesOnStart() const { return Read("update/checkOnStart", true).toBool(); }
void AppSettings::setCheckUpdatesOnStart(bool on) { Write("update/checkOnStart", on); }
bool AppSettings::autoInstallUpdates() const { return Read("update/autoInstall", false).toBool(); }
void AppSettings::setAutoInstallUpdates(bool on) { Write("update/autoInstall", on); }
QString AppSettings::skippedVersion() const { return Read("update/skipped", QString()).toString(); }
void AppSettings::setSkippedVersion(const QString& v) { Write("update/skipped", v); }
QDateTime AppSettings::lastUpdateCheck() const { return Read("update/lastCheck", QDateTime()).toDateTime(); }
void AppSettings::setLastUpdateCheck(const QDateTime& t) { Write("update/lastCheck", t); }

bool AppSettings::autoUpdateSignatures() const { return Read("signatures/auto", true).toBool(); }
void AppSettings::setAutoUpdateSignatures(bool on) { Write("signatures/auto", on); }
QDateTime AppSettings::lastSignatureUpdate() const { return Read("signatures/lastUpdate", QDateTime()).toDateTime(); }
void AppSettings::setLastSignatureUpdate(const QDateTime& t) { Write("signatures/lastUpdate", t); }

QString AppSettings::virusTotalKey() const {
    const QString key = Read("integrations/virusTotalKey", QString()).toString();
    if (!key.isEmpty()) return key;
    // Ключ из первой версии переносим: вводить его заново незачем.
    QSettings s("ThreatScanner", "ThreatScanner");
    return s.value("integrations/virusTotalKey").toString();
}
void AppSettings::setVirusTotalKey(const QString& k) { Write("integrations/virusTotalKey", k.trimmed()); }

QByteArray AppSettings::windowGeometry() const { return Read("ui/geometry", QByteArray()).toByteArray(); }
void AppSettings::setWindowGeometry(const QByteArray& g) { Write("ui/geometry", g); }
bool AppSettings::firstRunDone() const { return Read("ui/firstRunDone", false).toBool(); }
void AppSettings::setFirstRunDone(bool done) { Write("ui/firstRunDone", done); }
