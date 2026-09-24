// Проверка ядра поиска из командной строки — для замеров скорости и
// ложных срабатываний на реальной системе без интерфейса.
//
//   engine_scan <путь> [<путь>...]       проверить папки или файлы
//   engine_scan --quick | --full         области быстрой / полной проверки
//   ключи: --extended (расширенные правила), --pua, --verbose (с отброшенным)

#include "engine/FileAnalyzer.h"
#include "engine/HashDatabase.h"
#include "engine/ScanPipeline.h"
#include "engine/YaraEngine.h"
#include "engine/Classify.h"

#include <Windows.h>

#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

namespace {

std::string Utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n,
                        nullptr, nullptr);
    return s;
}

const char* LevelName(Verdict::Level l) {
    return l == Verdict::Malicious ? "MALICIOUS" : l == Verdict::Suspicious ? "SUSPICIOUS" : "clean";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    ScanPipeline::Config cfg;
    bool extended = false, verbose = false;
    std::vector<std::wstring> paths;
    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--quick")         cfg.roots = FileWalker::QuickRoots();
        else if (a == L"--full")     cfg.roots = FileWalker::FullRoots();
        else if (a == L"--extended") extended = true;
        else if (a == L"--pua")      cfg.analyzer.reportPua = true;
        else if (a == L"--verbose")  verbose = true;
        else                         paths.push_back(a);
    }
    if (!paths.empty()) {
        auto custom = FileWalker::CustomRoots(paths);
        cfg.roots.insert(cfg.roots.end(), custom.begin(), custom.end());
    }
    if (cfg.roots.empty()) {
        std::printf("usage: engine_scan <path>... | --quick | --full [--extended] [--pua] [--verbose]\n");
        return 2;
    }

    const auto t0 = std::chrono::steady_clock::now();
    std::printf("hash database: %zu entries, stamp %u\n", HashDatabase::Get().Count(),
                HashDatabase::Get().NewestStamp());
    std::string err;
    if (!YaraEngine::Get().Prepare(extended, &err)) std::printf("YARA: %s\n", err.c_str());
    const auto t1 = std::chrono::steady_clock::now();
    std::printf("YARA: %d rules, prepared in %lld ms\n", YaraEngine::Get().RuleCount(),
                static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()));

    std::mutex outLock;
    int found = 0;
    std::atomic<bool> cancel{ false };
    ScanPipeline::Progress last;

    ScanPipeline::Run(cfg, cancel,
        [&](const std::wstring& path, const Verdict& v) {
            std::lock_guard<std::mutex> lock(outLock);
            ++found;
            std::printf("\n[%s sev=%d %s%s%s] %s\n", LevelName(v.level), v.severity,
                        Classify::ClassCode(v.cls), v.family.empty() ? "" : "/",
                        v.family.c_str(), Utf8(path).c_str());
            if (!v.signer.empty()) std::printf("    signer: %s (%s)\n", Utf8(v.signer).c_str(),
                                               v.signedValid ? "valid" : "invalid");
            for (const Finding& f : v.findings)
                std::printf("    + %s %s (%d) %s%s%s\n", f.source.c_str(), f.name.c_str(), f.score,
                            f.detail.c_str(), f.inner.empty() ? "" : "  in: ", f.inner.c_str());
            if (verbose)
                for (const Finding& f : v.dismissed)
                    std::printf("    - %s %s (%d)\n", f.source.c_str(), f.name.c_str(), f.score);
        },
        [&](const ScanPipeline::Progress& p) {
            last = p;
            static int tick = 0;
            if (++tick % 50 == 0) {
                std::lock_guard<std::mutex> lock(outLock);
                std::printf("... seen %llu, candidates %llu, checked %llu, %d%%%s\n",
                            static_cast<unsigned long long>(p.filesSeen),
                            static_cast<unsigned long long>(p.candidates),
                            static_cast<unsigned long long>(p.checked), p.percent,
                            p.walkFinished ? "" : " (walking)");
            }
        });

    const auto t2 = std::chrono::steady_clock::now();
    std::printf("\nDone: files seen %llu, checked %llu (%.1f MB), findings %d, %lld s\n",
                static_cast<unsigned long long>(last.filesSeen),
                static_cast<unsigned long long>(last.checked),
                last.bytesTotal / 1048576.0, found,
                static_cast<long long>(std::chrono::duration_cast<std::chrono::seconds>(t2 - t1).count()));
    return found ? 1 : 0;
}
