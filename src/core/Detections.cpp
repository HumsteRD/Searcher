#include "Detections.h"
#include "../engine/Classify.h"

#include <Windows.h>

namespace Detections {

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), n,
                        nullptr, nullptr);
    return out;
}

std::wstring Wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string Reason(std::initializer_list<std::string> parts) {
    std::string out;
    for (const std::string& p : parts) {
        if (!out.empty()) out += '\t';
        std::string clean = p;
        for (char& c : clean) if (c == '\t' || c == '\n' || c == '\r') c = ' ';
        out += clean;
    }
    return out;
}

Severity ToSeverity(int level) {
    switch (level) {
    case 4:  return Severity::Critical;
    case 3:  return Severity::High;
    case 2:  return Severity::Medium;
    case 1:  return Severity::Low;
    default: return Severity::Info;
    }
}

void FillFromVerdict(Threat& t, const Verdict& v) {
    if (static_cast<int>(ToSeverity(v.severity)) > static_cast<int>(t.severity))
        t.severity = ToSeverity(v.severity);
    t.malwareClass = static_cast<int>(v.cls);
    if (!v.family.empty()) t.family = v.family;
    if (!v.sha256.empty()) t.sha256 = v.sha256;
    if (!v.signer.empty()) t.signer = v.signer;

    for (const Finding& f : v.findings) {
        if (f.source == "hash") {
            t.reasons.push_back(Reason({ "hash", f.name, f.inner }));
        } else if (f.source == "yara") {
            t.reasons.push_back(Reason({ "yara", f.name, std::to_string(f.score), f.detail, f.inner }));
        } else if (f.source == "heur" && f.name == "script") {
            size_t start = 0;
            while (start < f.detail.size()) {
                size_t comma = f.detail.find(',', start);
                if (comma == std::string::npos) comma = f.detail.size();
                t.reasons.push_back(f.detail.substr(start, comma - start));
                start = comma + 1;
            }
        } else if (f.source == "heur") {
            t.reasons.push_back(Reason({ "deceptive", f.detail }));
        } else if (f.source == "test") {
            t.reasons.push_back("eicar");
        }
    }
    if (!v.container.empty()) t.reasons.push_back(Reason({ "container", v.container }));
    if (v.signedValid && !v.signer.empty()) t.reasons.push_back(Reason({ "signed", Utf8(v.signer) }));
}

std::wstring SummaryOf(const Verdict& v) {
    std::string s = Classify::ClassCode(v.cls);
    if (!v.family.empty()) s += "/" + v.family;
    bool hash = false, yara = false;
    for (const Finding& f : v.findings) {
        hash |= f.source == "hash";
        yara |= f.source == "yara";
    }
    if (hash && yara) s += " (hash + signatures)";
    else if (hash)    s += " (hash match)";
    else if (yara)    s += " (signature match)";
    return Wide(s);
}

} // namespace Detections
