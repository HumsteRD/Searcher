#include "ScanConfig.h"

#include <algorithm>
#include <cwctype>

namespace {

std::mutex g_lock;
ScanConfig g_current;

std::wstring Lower(std::wstring s) {
    std::replace(s.begin(), s.end(), L'/', L'\\');
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    while (s.size() > 3 && s.back() == L'\\') s.pop_back();
    return s;
}

} // namespace

bool ScanConfig::IsAllowedHash(const std::string& sha) const {
    if (sha.empty()) return false;
    return std::find(allowedHashes.begin(), allowedHashes.end(), sha) != allowedHashes.end();
}

bool ScanConfig::IsExcludedPath(const std::wstring& path) const {
    const std::wstring p = Lower(path);
    for (const std::wstring& raw : excludedPaths) {
        const std::wstring e = Lower(raw);
        if (e.empty()) continue;
        if (p == e) return true;
        if (p.size() > e.size() && p.compare(0, e.size(), e) == 0 && p[e.size()] == L'\\')
            return true;
    }
    return false;
}

void ScanConfig::SetCurrent(const ScanConfig& config) {
    std::lock_guard<std::mutex> lock(g_lock);
    g_current = config;
}

ScanConfig ScanConfig::Current() {
    std::lock_guard<std::mutex> lock(g_lock);
    return g_current;
}
