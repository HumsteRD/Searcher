#include "ScanHistory.h"
#include "Lang.h"
#include "Texts.h"

#include "../core/ServiceConfig.h"
#include "../core/ThreatJson.h"
#include "../ui/Widgets.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>

ScanHistory& ScanHistory::instance() {
    static ScanHistory* h = new ScanHistory();
    return *h;
}

ScanHistory::ScanHistory() { load(); }

QString ScanHistory::filePath() const {
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + "/scan-history-v2.json";
}

void ScanHistory::load() {
    QFile f(filePath());
    if (!f.open(QIODevice::ReadOnly)) return;
    for (const QJsonValue& v : QJsonDocument::fromJson(f.readAll()).array()) {
        const QJsonObject o = v.toObject();
        ScanRecord r;
        r.when       = QDateTime::fromString(o["when"].toString(), Qt::ISODate);
        r.mode       = o["mode"].toInt();
        r.bySchedule = o["bySchedule"].toBool();
        r.durationMs = o["durationMs"].toInt();
        r.objects    = static_cast<qint64>(o["objects"].toDouble());
        r.threats    = o["threats"].toInt();
        r.critical   = o["critical"].toInt();
        r.cancelled  = o["cancelled"].toBool();
        r.reportPath = o["reportPath"].toString();
        r.target     = o["target"].toString();
        for (const QJsonValue& fv : o["findings"].toArray())
            r.findings.push_back(ThreatJson::FromJson(fv.toObject()));
        if (r.when.isValid()) records_.push_back(r);
    }
}

void ScanHistory::setTransient(const QVector<ScanRecord>& records) {
    transient_ = true;
    records_ = records;
    emit changed();
}

void ScanHistory::save() const {
    if (transient_) return;
    QJsonArray arr;
    for (const ScanRecord& r : records_) {
        QJsonObject o;
        o["when"]       = r.when.toString(Qt::ISODate);
        o["mode"]       = r.mode;
        o["bySchedule"] = r.bySchedule;
        o["durationMs"] = r.durationMs;
        o["objects"]    = static_cast<double>(r.objects);
        o["threats"]    = r.threats;
        o["critical"]   = r.critical;
        o["cancelled"]  = r.cancelled;
        o["reportPath"] = r.reportPath;
        o["target"]     = r.target;
        QJsonArray found;
        for (const Threat& t : r.findings) found.append(ThreatJson::ToJson(t));
        o["findings"] = found;
        arr.append(o);
    }
    // Через временный файл: оборванная запись не должна стереть историю.
    QSaveFile f(filePath());
    if (!f.open(QIODevice::WriteOnly)) return;
    f.write(QJsonDocument(arr).toJson(QJsonDocument::Compact));
    f.commit();
}

void ScanHistory::add(const ScanRecord& r) {
    records_.prepend(r);
    while (records_.size() > kMaxRecords) records_.removeLast();
    save();
    emit changed();
}

void ScanHistory::clear() {
    records_.clear();
    save();
    emit changed();
}

int ScanHistory::importServiceScans() {
    const QString path = QString::fromStdWString(ServiceConfig::ResultsPath());
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return 0;
    const QJsonArray arr = QJsonDocument::fromJson(f.readAll()).array();

    // Что уже подтянуто — по времени записи. Файл службы общий, удалять
    // из него записи интерфейс не может (он в ProgramData и принадлежит SYSTEM).
    QSettings s("ThreatScanner", "ThreatScanner");
    const QDateTime seen = s.value("history/serviceSeen").toDateTime();
    QDateTime newest = seen;
    int added = 0;

    for (const QJsonValue& v : arr) {
        const QJsonObject o = v.toObject();
        const QDateTime when = QDateTime::fromString(o["when"].toString(), Qt::ISODate);
        if (!when.isValid() || (seen.isValid() && when <= seen)) continue;
        ScanRecord r;
        r.when = when;
        r.mode = o["mode"].toString() == "Full" ? 1 : 0;
        r.bySchedule = true;
        r.durationMs = o["durationMs"].toInt();
        r.objects = static_cast<qint64>(o["objects"].toDouble());
        r.threats = o["threats"].toInt();
        r.critical = o["critical"].toInt();
        r.cancelled = o["cancelled"].toBool();
        for (const QJsonValue& fv : o["findings"].toArray())
            r.findings.push_back(ThreatJson::FromJson(fv.toObject()));
        records_.push_back(r);
        if (!newest.isValid() || when > newest) newest = when;
        ++added;
    }
    if (added) {
        std::sort(records_.begin(), records_.end(),
                  [](const ScanRecord& a, const ScanRecord& b) { return a.when > b.when; });
        while (records_.size() > kMaxRecords) records_.removeLast();
        s.setValue("history/serviceSeen", newest);
        save();
        emit changed();
    }
    return added;
}

QString ScanHistory::exportText(const ScanRecord& r) const {
    const QLocale loc = Lang::instance().current() == Lang::Id::Ru ? QLocale(QLocale::Russian)
                                                                    : QLocale(QLocale::English);
    QString out;
    out += TR("Threat Scanner — scan report") + "\n";
    out += QString(40, QChar('=')) + "\n\n";
    out += TR("Date") + ": " + loc.toString(r.when, QLocale::LongFormat) + "\n";
    out += TR("Scan type") + ": " + (r.mode == 3 ? TR("Sandbox") : Texts::modeLabel(r.mode)) + "\n";
    if (!r.target.isEmpty()) out += TR("Target") + ": " + r.target + "\n";
    out += TR("Duration") + ": " + Ui::formatDuration(r.durationMs) + "\n";
    out += TR("Objects checked") + ": " + QString::number(r.objects) + "\n";
    out += TR("Threats found") + ": " + QString::number(r.threats) + "\n";
    if (r.cancelled) out += TR("The scan was stopped before it finished.") + "\n";
    out += "\n";
    if (r.findings.isEmpty()) {
        out += TR("Nothing dangerous was found.") + "\n";
        return out;
    }
    int n = 1;
    for (const Threat& t : r.findings) {
        out += QString("%1. [%2] %3\n").arg(n++).arg(Texts::severityLabel(t.severity),
                                                   QString::fromStdWString(t.name));
        out += "   " + Texts::headline(t) + "\n";
        out += "   " + TR("Location") + ": " + QString::fromStdWString(t.source) + "\n";
        out += "   " + TR("Status") + ": " + Texts::statusLabel(t.status) + "\n";
        for (const Texts::Reason& reason : Texts::reasons(t)) {
            out += "   - " + reason.text;
            if (!reason.detail.isEmpty()) out += " (" + reason.detail + ")";
            out += "\n";
        }
        if (!t.sha256.empty()) out += "   SHA-256: " + QString::fromStdString(t.sha256) + "\n";
        out += "\n";
    }
    return out;
}
