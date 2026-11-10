#include "FileSystemScanner.h"
#include "Detections.h"
#include "Logger.h"

#include "../engine/FileAnalyzer.h"
#include "../engine/ScanPipeline.h"

#include <algorithm>
#include <atomic>

void FileSystemScanner::Scan(IReportSink& sink, CancelToken& cancel, const ScanConfig& config) {
    ScanPipeline::Config pc;
    switch (config.mode) {
    case ScanConfig::Mode::Quick:  pc.roots = FileWalker::QuickRoots(); break;
    case ScanConfig::Mode::Full:   pc.roots = FileWalker::FullRoots(); break;
    case ScanConfig::Mode::Custom: pc.roots = FileWalker::CustomRoots(config.paths); break;
    }
    pc.excludes = config.excludedPaths;
    pc.analyzer.reportPua = config.reportPua;
    pc.analyzer.unpack    = config.unpackArchives;
    pc.threads            = config.threads;
    pc.pause              = &cancel.paused;

    Logger::Instance().Info("[Files] " + std::to_string(pc.roots.size()) + " locations to check");

    // Находки приходят из нескольких потоков разом.
    std::atomic<long long> reported{ 0 };
    uint64_t failed = 0;
    ScanPipeline::Run(pc, cancel.requested,
        [&](const std::wstring& path, const Verdict& v) {
            if (config.IsAllowedHash(v.sha256)) {
                Logger::Instance().Info("[Files] allowed by user: " + Detections::Utf8(path));
                return;
            }
            Threat t;
            t.kind     = ThreatKind::File;
            t.name     = path.substr(path.find_last_of(L"\\/") + 1);
            t.source   = path;
            t.filePath = path;
            t.summary  = Detections::SummaryOf(v);
            Detections::FillFromVerdict(t, v);
            if (FileWalker::IsRiskyLocation(path)) t.reasons.push_back("location.risky");
            sink.Report(t);
            ++reported;
            Logger::Instance().Warn("[Files] " + Detections::Utf8(t.summary) + ": " +
                                    Detections::Utf8(path));
            for (const Finding& f : v.dismissed) {
                Logger::Instance().Debug("[Files]   dismissed " + f.source + " " + f.name);
            }
        },
        [&](const ScanPipeline::Progress& p) {
            if (!p.current.empty()) sink.Item(p.current);
            sink.Checked(static_cast<long long>(p.checked));
            sink.Progress("Files", p.walkFinished ? p.percent : -1);
            failed = p.failed;
        });

    if (failed) {
        Logger::Instance().Warn("[Files] could not analyze " + std::to_string(failed) +
                                " damaged or oversized files; they were skipped");
    }
    Logger::Instance().Info("[Files] done, findings: " + std::to_string(reported.load()));
}
