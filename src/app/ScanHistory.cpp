#include "ScanHistory.h"
#include "Lang.h"
#include "ServiceConfig.h"

#include <algorithm>

#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QLocale>

ScanHistory& ScanHistory::instance() {
    static ScanHistory h;
    return h;
}

ScanHistory::ScanHistory() {
    load();
}

QString ScanHistory::filePath() const {
    const QString dir =
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + "/scan-history.json";
}

void ScanHistory::load() {
    QFile f(filePath());
    if (!f.open(QIODevice::ReadOnly)) return;

    const QJsonArray arr = QJsonDocument::fromJson(f.readAll()).array();
    for (const QJsonValue& v : arr) {
        const QJsonObject o = v.toObject();

        ScanRecord r;
        r.when            = QDateTime::fromString(o["when"].toString(), Qt::ISODate);
        r.mode            = o["mode"].toString();
        r.durationMs      = o["durationMs"].toInt();
        r.objectsScanned  = o["objects"].toVariant().toLongLong();
        r.totalThreats    = o["threats"].toInt();
        r.criticalThreats = o["critical"].toInt();
        r.cancelled       = o["cancelled"].toBool();
        r.reportPath      = o["reportPath"].toString();

        for (const QJsonValue& fv : o["findings"].toArray()) {
            const QJsonObject fo = fv.toObject();
            r.findings.push_back({ fo["severity"].toString(),
                                   fo["name"].toString(),
                                   fo["source"].toString() });
        }
        records_.push_back(r);
    }
}

void ScanHistory::save() const {
    QJsonArray arr;
    for (const ScanRecord& r : records_) {
        QJsonArray findings;
        for (const auto& f : r.findings) {
            findings.append(QJsonObject{ { "severity", f.severity },
                                         { "name", f.name },
                                         { "source", f.source } });
        }
        arr.append(QJsonObject{
            { "when",       r.when.toString(Qt::ISODate) },
            { "mode",       r.mode },
            { "durationMs", r.durationMs },
            { "objects",    QJsonValue::fromVariant(r.objectsScanned) },
            { "threats",    r.totalThreats },
            { "critical",   r.criticalThreats },
            { "cancelled",  r.cancelled },
            { "reportPath", r.reportPath },
            { "findings",   findings },
        });
    }

    QFile f(filePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
}

void ScanHistory::add(const ScanRecord& r) {
    records_.prepend(r);
    while (records_.size() > kMaxRecords) records_.removeLast();
    save();
}

void ScanHistory::importServiceScans() {
    QFile file(QString::fromStdWString(ServiceConfig::ResultsPath()));
    if (!file.open(QIODevice::ReadOnly)) return;   // служба ещё не работала

    const QJsonArray scans = QJsonDocument::fromJson(file.readAll()).array();
    file.close();

    bool added = false;
    for (const QJsonValue& value : scans) {
        const QJsonObject o = value.toObject();
        const QDateTime when =
            QDateTime::fromString(o["when"].toString(), Qt::ISODate);
        if (!when.isValid()) continue;

        // Файл службы мы не чистим — она пишет в него сама. Поэтому
        // на каждом заходе отбрасываем то, что уже забрали.
        bool known = false;
        for (const ScanRecord& existing : records_) {
            if (existing.mode == "Service" && existing.when == when) {
                known = true;
                break;
            }
        }
        if (known) continue;

        ScanRecord record;
        record.when            = when;
        record.mode            = "Service";
        record.durationMs      = o["durationMs"].toInt();
        record.objectsScanned  = o["objects"].toVariant().toLongLong();
        record.totalThreats    = o["threats"].toInt();
        record.criticalThreats = o["critical"].toInt();
        records_.push_back(record);
        added = true;
    }

    if (!added) return;

    std::sort(records_.begin(), records_.end(),
              [](const ScanRecord& a, const ScanRecord& b) {
                  return a.when > b.when;
              });
    while (records_.size() > kMaxRecords) records_.removeLast();
    save();
}

void ScanHistory::clear() {
    records_.clear();
    save();
}

QString ScanHistory::exportText(const ScanRecord& r) const {
    QString out;
    out += "Threat Scanner — " + TR("Scan report") + "\n";
    out += QString(60, '=') + "\n\n";

    out += TR("Date") + ": " + r.when.toString("yyyy-MM-dd HH:mm:ss") + "\n";
    out += TR("Mode") + ": " + r.mode + "\n";
    out += TR("Duration") + ": " + QString::number(r.durationMs / 1000) + " "
         + TR("s") + "\n";
    out += TR("Objects checked") + ": "
         + QLocale().toString(r.objectsScanned) + "\n";
    out += TR("Threats found") + ": " + QString::number(r.totalThreats)
         + " (" + TR("critical") + ": "
         + QString::number(r.criticalThreats) + ")\n";
    if (r.cancelled) out += TR("Scan was cancelled before it finished.") + "\n";

    out += "\n" + QString(60, '-') + "\n";

    if (r.findings.isEmpty() && r.totalThreats > 0) {
        // Служба находки не сохраняет — только счётчики. Написать здесь
        // «ничего не найдено» значило бы соврать.
        out += TR("This scan ran in the background; the list of findings "
                  "was not kept.") + "\n";
    } else if (r.findings.isEmpty()) {
        out += TR("Nothing suspicious was found.") + "\n";
    } else {
        for (const auto& f : r.findings) {
            out += QString("[%1] %2\n    %3\n")
                       .arg(f.severity, -5).arg(f.name, f.source);
        }
    }
    return out;
}
