#include "ThreatJson.h"

#include <QJsonArray>

namespace ThreatJson {
namespace {

QString W(const std::wstring& s) { return QString::fromStdWString(s); }
QString U(const std::string& s)  { return QString::fromUtf8(s.data(), static_cast<int>(s.size())); }

QString RootName(HKEY root) {
    if (root == HKEY_CURRENT_USER)  return "HKCU";
    if (root == HKEY_LOCAL_MACHINE) return "HKLM";
    return {};
}

HKEY RootFromName(const QString& n) {
    if (n == "HKCU") return HKEY_CURRENT_USER;
    if (n == "HKLM") return HKEY_LOCAL_MACHINE;
    return nullptr;
}

} // namespace

QString SeverityCode(Severity s) {
    switch (s) {
    case Severity::Critical: return "CRIT";
    case Severity::High:     return "HIGH";
    case Severity::Medium:   return "MED";
    case Severity::Low:      return "LOW";
    default:                 return "INFO";
    }
}

Severity SeverityFromCode(const QString& c) {
    if (c == "CRIT") return Severity::Critical;
    if (c == "HIGH") return Severity::High;
    if (c == "MED")  return Severity::Medium;
    if (c == "LOW")  return Severity::Low;
    return Severity::Info;
}

QString StatusCode(ThreatStatus s) {
    switch (s) {
    case ThreatStatus::Ignored:     return "ignored";
    case ThreatStatus::Quarantined: return "quarantined";
    case ThreatStatus::Deleted:     return "deleted";
    case ThreatStatus::Restored:    return "restored";
    case ThreatStatus::Failed:      return "failed";
    case ThreatStatus::Disabled:    return "disabled";
    default:                        return "pending";
    }
}

ThreatStatus StatusFromCode(const QString& c) {
    if (c == "ignored")     return ThreatStatus::Ignored;
    if (c == "quarantined") return ThreatStatus::Quarantined;
    if (c == "deleted")     return ThreatStatus::Deleted;
    if (c == "restored")    return ThreatStatus::Restored;
    if (c == "failed")      return ThreatStatus::Failed;
    if (c == "disabled")    return ThreatStatus::Disabled;
    return ThreatStatus::Pending;
}

QJsonObject ToJson(const Threat& t) {
    QJsonObject o;
    o["severity"] = SeverityCode(t.severity);
    o["kind"]     = static_cast<int>(t.kind);
    o["status"]   = StatusCode(t.status);
    o["class"]    = t.malwareClass;
    o["family"]   = U(t.family);
    o["name"]     = W(t.name);
    o["source"]   = W(t.source);
    o["summary"]  = W(t.summary);
    o["evidence"] = W(t.evidence);
    o["sha256"]   = U(t.sha256);
    o["signer"]   = W(t.signer);
    o["action"]   = W(t.actionMessage);
    o["filePath"] = W(t.filePath);
    o["pid"]      = static_cast<double>(t.pid);
    o["regRoot"]  = RootName(t.regRoot);
    o["regSubKey"] = W(t.regSubKey);
    o["regValue"] = W(t.regValueName);
    o["task"]     = W(t.taskFullPath);
    o["service"]  = W(t.serviceName);
    o["wmi"]      = W(t.wmiConsumerPath);
    o["hosts"]    = W(t.hostsLine);
    QJsonArray reasons;
    for (const std::string& r : t.reasons) reasons.append(U(r));
    o["reasons"] = reasons;
    return o;
}

Threat FromJson(const QJsonObject& o) {
    Threat t;
    t.severity      = SeverityFromCode(o["severity"].toString());
    t.kind          = static_cast<ThreatKind>(o["kind"].toInt());
    t.status        = StatusFromCode(o["status"].toString());
    t.malwareClass  = o["class"].toInt();
    t.family        = o["family"].toString().toStdString();
    t.name          = o["name"].toString().toStdWString();
    t.source        = o["source"].toString().toStdWString();
    t.summary       = o["summary"].toString().toStdWString();
    t.evidence      = o["evidence"].toString().toStdWString();
    t.sha256        = o["sha256"].toString().toStdString();
    t.signer        = o["signer"].toString().toStdWString();
    t.actionMessage = o["action"].toString().toStdWString();
    t.filePath      = o["filePath"].toString().toStdWString();
    t.pid           = static_cast<DWORD>(o["pid"].toDouble());
    t.regRoot       = RootFromName(o["regRoot"].toString());
    t.regSubKey     = o["regSubKey"].toString().toStdWString();
    t.regValueName  = o["regValue"].toString().toStdWString();
    t.taskFullPath  = o["task"].toString().toStdWString();
    t.serviceName   = o["service"].toString().toStdWString();
    t.wmiConsumerPath = o["wmi"].toString().toStdWString();
    t.hostsLine     = o["hosts"].toString().toStdWString();
    for (const auto& v : o["reasons"].toArray()) t.reasons.push_back(v.toString().toStdString());
    return t;
}

} // namespace ThreatJson
