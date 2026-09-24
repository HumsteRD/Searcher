#include "DownloadGuard.h"
#include "LocalCheck.h"

#include "../core/Logger.h"
#include "../engine/FileAnalyzer.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QStandardPaths>
#include <QTimer>

namespace {

// Временные файлы браузеров: пока они есть, загрузка не закончена.
bool IsPartial(const QString& name) {
    const QString n = name.toLower();
    return n.endsWith(".crdownload") || n.endsWith(".part") || n.endsWith(".partial") ||
           n.endsWith(".download") || n.endsWith(".tmp") || n.startsWith("~$");
}

} // namespace

DownloadGuard::DownloadGuard(QObject* parent) : QObject(parent) {
    watcher_ = new QFileSystemWatcher(this);
    debounce_ = new QTimer(this);
    debounce_->setSingleShot(true);
    debounce_->setInterval(800);
    settle_ = new QTimer(this);
    settle_->setInterval(1000);
    connect(watcher_, &QFileSystemWatcher::directoryChanged, this, [this]() { debounce_->start(); });
    connect(debounce_, &QTimer::timeout, this, &DownloadGuard::scanFolders);
    connect(settle_, &QTimer::timeout, this, &DownloadGuard::checkReady);
}

QStringList DownloadGuard::folders() const {
    QStringList out;
    for (auto loc : { QStandardPaths::DownloadLocation, QStandardPaths::DesktopLocation }) {
        const QString p = QStandardPaths::writableLocation(loc);
        if (!p.isEmpty() && QDir(p).exists()) out << p;
    }
    return out;
}

void DownloadGuard::setEnabled(bool on) {
    if (on == enabled_) return;
    enabled_ = on;
    if (!watcher_->directories().isEmpty()) watcher_->removePaths(watcher_->directories());
    pending_.clear();
    known_.clear();
    settle_->stop();
    if (!on) return;

    // Что уже лежит в папках — не новое: проверять это задача обычной
    // проверки, а не монитора, иначе при каждом запуске всё с начала.
    for (const QString& dir : folders()) {
        watcher_->addPath(dir);
        for (const QFileInfo& fi : QDir(dir).entryInfoList(QDir::Files | QDir::Hidden))
            known_.insert(fi.absoluteFilePath(), fi.lastModified().toMSecsSinceEpoch());
    }
    Logger::Instance().Info("[Guard] watching " + std::to_string(watcher_->directories().size()) + " folders");
}

void DownloadGuard::scanFolders() {
    for (const QString& dir : folders()) {
        for (const QFileInfo& fi : QDir(dir).entryInfoList(QDir::Files | QDir::Hidden)) {
            const QString path = fi.absoluteFilePath();
            const qint64 mtime = fi.lastModified().toMSecsSinceEpoch();
            auto it = known_.find(path);
            if (it != known_.end() && it.value() == mtime) continue;
            known_.insert(path, mtime);
            if (IsPartial(fi.fileName())) continue;
            pending_.insert(path, Pending{ -1, 0 });
        }
    }
    if (!pending_.isEmpty() && !settle_->isActive()) settle_->start();
}

void DownloadGuard::checkReady() {
    QStringList ready;
    for (auto it = pending_.begin(); it != pending_.end();) {
        const QFileInfo fi(it.key());
        if (!fi.exists()) { it = pending_.erase(it); continue; }
        // Размер не менялся две секунды подряд — файл дописан.
        if (fi.size() == it->size) ++it->stableTicks;
        else { it->size = fi.size(); it->stableTicks = 0; }
        if (it->stableTicks >= 2) {
            const std::wstring name = fi.fileName().toStdWString();
            bool candidate = FileAnalyzer::IsCandidateByName(name);
            if (!candidate) {
                QFile f(it.key());
                if (f.open(QIODevice::ReadOnly)) {
                    const QByteArray head = f.read(8);
                    candidate = FileAnalyzer::IsCandidateByMagic(
                        reinterpret_cast<const uint8_t*>(head.constData()), static_cast<size_t>(head.size()));
                }
            }
            if (candidate) ready << it.key();
            it = pending_.erase(it);
            continue;
        }
        ++it;
    }
    if (pending_.isEmpty()) settle_->stop();
    if (!ready.isEmpty()) LocalCheck::instance().check(ready, "guard");
}
