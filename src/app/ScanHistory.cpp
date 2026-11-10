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

void ScanHistory::syncStatus(const Threat& threat) {
    // Самая свежая проверка, где есть эта находка: тот же вид, то же
    // расположение и то же содержимое.
    for (ScanRecord& r : records_) {
        for (Threat& f : r.findings) {
            if (f.kind != threat.kind || f.source != threat.source || f.sha256 != threat.sha256) continue;
            if (f.status == threat.status && f.actionMessage == threat.actionMessage) return;
            f.status = threat.status;
            f.actionMessage = threat.actionMessage;
            save();
            emit changed();
            return;
        }
    }
}

namespace {

QLocale ReportLocale() {
    return Lang::instance().current() == Lang::Id::Ru ? QLocale(QLocale::Russian) : QLocale(QLocale::English);
}

QString ScanTitle(const ScanRecord& r) {
    return r.mode == 3 ? TR("Sandbox") : Texts::modeLabel(r.mode);
}

} // namespace

QByteArray ScanHistory::exportJson(const ScanRecord& r) const {
    QJsonObject o;
    o["program"]    = QStringLiteral("Threat Scanner");
    o["when"]       = r.when.toString(Qt::ISODate);
    o["scanType"]   = r.mode == 3 ? QStringLiteral("sandbox")
                    : r.mode == 1 ? QStringLiteral("full")
                    : r.mode == 2 ? QStringLiteral("custom") : QStringLiteral("quick");
    o["background"] = r.bySchedule;
    o["target"]     = r.target;
    o["durationMs"] = r.durationMs;
    o["objects"]    = static_cast<double>(r.objects);
    o["threats"]    = r.threats;
    o["critical"]   = r.critical;
    o["cancelled"]  = r.cancelled;
    QJsonArray found;
    for (const Threat& t : r.findings) {
        QJsonObject f;
        f["name"]     = QString::fromStdWString(t.name);
        f["location"] = QString::fromStdWString(t.source);
        f["file"]     = QString::fromStdWString(t.filePath);
        f["severity"] = Texts::severityCode(t.severity);
        f["status"]   = ThreatJson::StatusCode(t.status);
        f["kind"]     = static_cast<int>(t.kind);
        f["family"]   = QString::fromStdString(t.family);
        f["type"]     = Texts::classTitle(t.malwareClass);
        f["sha256"]   = QString::fromStdString(t.sha256);
        f["signer"]   = QString::fromStdWString(t.signer);
        f["command"]  = QString::fromStdWString(t.evidence);
        QJsonArray reasons;
        for (const Texts::Reason& reason : Texts::reasons(t)) {
            QJsonObject ro;
            ro["text"] = reason.text;
            if (!reason.detail.isEmpty()) ro["detail"] = reason.detail;
            if (reason.technical) ro["technical"] = true;
            reasons.append(ro);
        }
        f["reasons"] = reasons;
        found.append(f);
    }
    o["findings"] = found;
    return QJsonDocument(o).toJson(QJsonDocument::Indented);
}

QString ScanHistory::exportHtml(const ScanRecord& r) const {
    const QLocale loc = ReportLocale();
    auto esc = [](const QString& s) { return s.toHtmlEscaped(); };
    auto tone = [](Severity s) {
        switch (s) {
        case Severity::Critical: return "crit";
        case Severity::High:     return "high";
        case Severity::Medium:   return "med";
        case Severity::Low:      return "low";
        default:                 return "info";
        }
    };

    QString h;
    h += "<!doctype html>\n<html lang=\"";
    h += Lang::instance().current() == Lang::Id::Ru ? "ru" : "en";
    h += "\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
    h += "<title>" + esc(TR("Threat Scanner — scan report")) + "</title>\n<style>\n";
    h += ":root{--bg:#f3f4f6;--card:#fff;--line:#e1e4e8;--text:#15171b;--muted:#4b5260;--faint:#616875;"
         "--crit:#b91c1c;--critbg:#fcebeb;--high:#b93f0b;--highbg:#fdede3;--med:#975a06;--medbg:#fcf3e0;"
         "--low:#3a5696;--lowbg:#ecf0f9;--ok:#127336;--okbg:#e6f5eb;--info:#4b5260;--infobg:#eff1f4}\n"
         "@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--line:#272c35;--text:#e8eaee;"
         "--muted:#aab0bb;--faint:#8a919d;--crit:#ff8286;--critbg:#33171a;--high:#ff9d68;--highbg:#321e13;"
         "--med:#efbd5c;--medbg:#2c2413;--low:#a6bceb;--lowbg:#1b2336;--ok:#5ad394;--okbg:#13281e;"
         "--info:#aab0bb;--infobg:#21252c}}\n"
         "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);"
         "font:14px/1.5 'Segoe UI',system-ui,sans-serif}\n"
         "main{max-width:880px;margin:0 auto;padding:32px 20px 48px}\n"
         "h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 12px}\n"
         ".sub{color:var(--muted);margin:0 0 20px}\n"
         ".card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:0 0 12px}\n"
         ".facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px 24px}\n"
         ".facts dt{font-size:12px;font-weight:600;color:var(--faint)}.facts dd{margin:2px 0 0;font-weight:600}\n"
         ".pill{display:inline-block;padding:2px 9px;border-radius:6px;font-size:12px;font-weight:600;white-space:nowrap}\n"
         ".crit{color:var(--crit);background:var(--critbg)}.high{color:var(--high);background:var(--highbg)}"
         ".med{color:var(--med);background:var(--medbg)}.low{color:var(--low);background:var(--lowbg)}"
         ".ok{color:var(--ok);background:var(--okbg)}.info{color:var(--info);background:var(--infobg)}\n"
         ".head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.name{font-size:15px;font-weight:600;"
         "overflow-wrap:anywhere}\n"
         ".what{color:var(--muted);margin:2px 0 10px}\n"
         "ul{margin:8px 0 0;padding-left:20px}li{margin:2px 0}li small{color:var(--faint);overflow-wrap:anywhere}\n"
         ".mono{font:12px/1.5 'Cascadia Mono',Consolas,monospace;color:var(--muted);overflow-wrap:anywhere}\n"
         ".row{margin-top:8px}.row b{display:block;font-size:12px;color:var(--faint)}\n"
         "footer{margin-top:28px;color:var(--faint);font-size:12px}\n"
         "@media print{body{background:#fff}.card{break-inside:avoid}}\n";
    h += "</style>\n</head>\n<body>\n<main>\n";

    h += "<h1>" + esc(TR("Threat Scanner — scan report")) + "</h1>\n";
    h += "<p class=\"sub\">" + esc(loc.toString(r.when, QLocale::LongFormat)) + "</p>\n";

    h += "<div class=\"card\"><dl class=\"facts\">\n";
    auto fact = [&](const QString& label, const QString& value) {
        h += "<div><dt>" + esc(label) + "</dt><dd>" + esc(value) + "</dd></div>\n";
    };
    fact(TR("Scan type"), ScanTitle(r) + (r.bySchedule ? " · " + TR("background") : QString()));
    if (!r.target.isEmpty()) fact(TR("Target"), r.target);
    fact(TR("Duration"), Ui::formatDuration(r.durationMs));
    fact(TR("Objects checked"), Ui::formatCount(r.objects));
    fact(TR("Threats found"), QString::number(r.threats));
    if (r.cancelled) fact(TR("Status"), TR("Stopped"));
    h += "</dl></div>\n";

    if (r.findings.isEmpty()) {
        h += "<div class=\"card\"><span class=\"pill ok\">" + esc(TR("Clean")) + "</span> " +
             esc(TR("Nothing dangerous was found.")) + "</div>\n";
    } else {
        h += "<h2>" + esc(TR("Findings")) + "</h2>\n";
        for (const Threat& t : r.findings) {
            h += "<div class=\"card\">\n<div class=\"head\"><span class=\"pill ";
            h += tone(t.severity);
            h += "\">" + esc(Texts::severityLabel(t.severity)) + "</span><span class=\"name\">" +
                 esc(QString::fromStdWString(t.name)) + "</span><span class=\"pill info\">" +
                 esc(Texts::statusLabel(t.status)) + "</span></div>\n";
            h += "<div class=\"what\">" + esc(Texts::headline(t)) + " · " + esc(Texts::kindLabel(t.kind)) + "</div>\n";
            h += "<div>" + esc(Texts::classExplain(t.malwareClass)) + "</div>\n";

            QStringList technical;
            h += "<ul>\n";
            for (const Texts::Reason& reason : Texts::reasons(t)) {
                if (reason.technical) {
                    technical << (reason.detail.isEmpty() ? reason.text : reason.text + " — " + reason.detail);
                    continue;
                }
                h += "<li>" + esc(reason.text);
                if (!reason.detail.isEmpty()) h += "<br><small>" + esc(reason.detail) + "</small>";
                h += "</li>\n";
            }
            h += "</ul>\n";

            auto row = [&](const QString& label, const QString& value) {
                if (value.isEmpty()) return;
                h += "<div class=\"row\"><b>" + esc(label) + "</b><span class=\"mono\">" + esc(value) + "</span></div>\n";
            };
            row(TR("Location"), QString::fromStdWString(t.source));
            if (t.filePath != t.source) row(TR("File"), QString::fromStdWString(t.filePath));
            row(QStringLiteral("SHA-256"), QString::fromStdString(t.sha256));
            row(TR("Digital signature"), QString::fromStdWString(t.signer));
            row(TR("Command line"), QString::fromStdWString(t.evidence));
            row(TR("Engine details"), technical.join("; "));
            h += "</div>\n";
        }
    }

    h += "<footer>Threat Scanner · " + esc(loc.toString(QDateTime::currentDateTime(), QLocale::ShortFormat)) +
         "</footer>\n</main>\n</body>\n</html>\n";
    return h;
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
