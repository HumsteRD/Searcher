#include "LocalCheck.h"
#include "AppSettings.h"

#include "../core/Detections.h"
#include "../core/Logger.h"
#include "../engine/FileAnalyzer.h"
#include "../engine/FileWalker.h"
#include "../engine/HashDatabase.h"
#include "../engine/YaraEngine.h"

#include <QFileInfo>
#include <QMetaObject>
#include <QPointer>
#include <QtConcurrent/QtConcurrentRun>

LocalCheck& LocalCheck::instance() {
    static LocalCheck* c = new LocalCheck();
    return *c;
}

LocalCheck::LocalCheck() {
    qRegisterMetaType<LocalCheck::Result>("LocalCheck::Result");
}

void LocalCheck::check(const QStringList& files, const QString& tag) {
    if (files.isEmpty()) return;
    ++running_;
    emit started(tag, files.size());

    const bool extended = AppSettings::Get().extendedRules();
    FileAnalyzer::Options opt;
    opt.reportPua = AppSettings::Get().reportPua();
    opt.unpack = AppSettings::Get().unpackArchives();
    QStringList allowed = AppSettings::Get().allowedHashes();

    QPointer<LocalCheck> self(this);
    (void)QtConcurrent::run([self, files, tag, extended, opt, allowed]() {
        // Правила компилируются один раз за запуск и дальше живут в памяти.
        std::string error;
        if (!YaraEngine::Get().Prepare(extended, &error))
            Logger::Instance().Warn("[LocalCheck] rules unavailable: " + error);
        HashDatabase::Get();

        for (const QString& path : files) {
            const Verdict v = FileAnalyzer::Analyze(path.toStdWString(), opt);
            LocalCheck::Result r;
            r.path = path;
            r.size = static_cast<qint64>(v.size);
            r.sha256 = QString::fromStdString(v.sha256);
            r.signer = QString::fromStdWString(v.signer);
            r.container = QString::fromStdString(v.container);
            r.skipped = v.skipped;
            r.skipReason = QString::fromStdString(v.skipReason);
            r.clean = v.level == Verdict::Clean || allowed.contains(r.sha256);
            if (!r.clean) {
                Threat& t = r.threat;
                t.kind = ThreatKind::File;
                t.name = QFileInfo(path).fileName().toStdWString();
                t.source = QFileInfo(path).absoluteFilePath().replace('/', '\\').toStdWString();
                t.filePath = t.source;
                t.summary = Detections::SummaryOf(v);
                Detections::FillFromVerdict(t, v);
                if (FileWalker::IsRiskyLocation(t.source)) t.reasons.push_back("location.risky");
            }
            if (!self) return;
            QMetaObject::invokeMethod(self, [self, tag, r]() {
                if (self) emit self->fileChecked(tag, r);
            }, Qt::QueuedConnection);
        }
        if (!self) return;
        QMetaObject::invokeMethod(self, [self, tag]() {
            if (!self) return;
            --self->running_;
            emit self->finished(tag);
        }, Qt::QueuedConnection);
    });
}
