#include "Updater.h"
#include "AppSettings.h"

#include "../core/Logger.h"

#include <Windows.h>
#include <shellapi.h>

#include <QApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QStandardPaths>

namespace {

constexpr const char* kLatestApi = "https://api.github.com/repos/HumsteRD/Searcher/releases/latest";

QNetworkRequest Request(const QUrl& url) {
    QNetworkRequest r(url);
    // GitHub отвергает запросы без User-Agent.
    r.setHeader(QNetworkRequest::UserAgentHeader, "ThreatScanner/" + Updater::currentVersion());
    r.setRawHeader("Accept", "application/vnd.github+json");
    r.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    r.setTransferTimeout(30000);
    return r;
}

QList<int> Parts(const QString& v) {
    QList<int> out;
    for (const QString& p : QString(v).remove(QRegularExpression("^[vV]")).split(QRegularExpression("[.-]")))
        out << p.toInt();
    return out;
}

} // namespace

Updater& Updater::instance() {
    static Updater* u = new Updater();
    return *u;
}

Updater::Updater() : nam_(new QNetworkAccessManager(this)) {}

QString Updater::currentVersion() { return QStringLiteral(TS_VERSION); }

bool Updater::isNewer(const QString& candidate, const QString& current) {
    const QList<int> a = Parts(candidate), b = Parts(current);
    for (int i = 0; i < std::max(a.size(), b.size()); ++i) {
        const int x = i < a.size() ? a[i] : 0, y = i < b.size() ? b[i] : 0;
        if (x != y) return x > y;
    }
    return false;
}

QString Updater::cacheDir() const {
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/updates";
    QDir().mkpath(dir);
    return dir;
}

void Updater::check(bool manual) {
    if (checking_) return;
    checking_ = true;
    QNetworkReply* reply = nam_->get(Request(QUrl(kLatestApi)));
    connect(reply, &QNetworkReply::finished, this, [this, reply, manual]() {
        reply->deleteLater();
        checking_ = false;
        AppSettings::Get().setLastUpdateCheck(QDateTime::currentDateTime());

        if (reply->error() != QNetworkReply::NoError) {
            const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            // 404 — релизов ещё нет: это не ошибка, просто обновлений нет.
            if (http == 404) { available_ = false; emit checkFinished(false, manual); return; }
            Logger::Instance().Warn("[Update] check failed: " + reply->errorString().toStdString());
            emit checkFailed(reply->errorString(), manual);
            return;
        }

        const QJsonObject root = QJsonDocument::fromJson(reply->readAll()).object();
        Release r;
        r.version = root["tag_name"].toString().remove(QRegularExpression("^[vV]"));
        r.notes = root["body"].toString();
        r.pageUrl = root["html_url"].toString();
        for (const QJsonValue& v : root["assets"].toArray()) {
            const QJsonObject a = v.toObject();
            const QString name = a["name"].toString();
            if (name.endsWith(".exe", Qt::CaseInsensitive) && name.contains("setup", Qt::CaseInsensitive)) {
                r.assetName = name;
                r.assetUrl = a["browser_download_url"].toString();
                r.assetSize = static_cast<qint64>(a["size"].toDouble());
            }
        }
        // Контрольная сумма в описании: строка «SHA-256: <64 hex>».
        const QRegularExpressionMatch m =
            QRegularExpression("SHA-?256[^0-9a-fA-F]{0,20}([0-9a-fA-F]{64})").match(r.notes);
        if (m.hasMatch()) r.sha256 = m.captured(1).toLower();

        latest_ = r;
        available_ = !r.version.isEmpty() && !r.assetUrl.isEmpty() && isNewer(r.version, currentVersion());
        Logger::Instance().Info("[Update] latest " + r.version.toStdString() +
                                (available_ ? " (newer)" : " (up to date)"));
        emit checkFinished(available_, manual);
    });
}

void Updater::download() {
    if (!available_ || downloading_) return;
    const QString target = cacheDir() + "/" + latest_.assetName;

    // Уже скачан целиком и сходится по размеру (и хэшу, если он известен).
    QFileInfo done(target);
    if (done.exists() && done.size() == latest_.assetSize) {
        downloaded_ = target;
        emit downloadFinished(target);
        return;
    }

    const QString partPath = target + ".part";
    partFile_ = new QFile(partPath, this);
    if (!partFile_->open(QIODevice::ReadWrite)) {
        emit downloadFailed(partFile_->errorString());
        return;
    }
    qint64 have = partFile_->size();
    if (have > latest_.assetSize) { partFile_->resize(0); have = 0; }
    partFile_->seek(have);

    QNetworkRequest req = Request(QUrl(latest_.assetUrl));
    req.setRawHeader("Accept", "application/octet-stream");
    req.setTransferTimeout(120000);
    if (have > 0) req.setRawHeader("Range", "bytes=" + QByteArray::number(have) + "-");

    downloading_ = true;
    QNetworkReply* reply = nam_->get(req);
    connect(reply, &QNetworkReply::metaDataChanged, this, [this, reply, have]() {
        // Сервер не поддержал докачку и отдаёт файл целиком — пишем с нуля.
        const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (have > 0 && http == 200) { partFile_->resize(0); partFile_->seek(0); }
    });
    connect(reply, &QNetworkReply::readyRead, this, [this, reply]() {
        partFile_->write(reply->readAll());
        emit downloadProgress(partFile_->size(), latest_.assetSize);
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, target, partPath]() {
        reply->deleteLater();
        downloading_ = false;
        partFile_->write(reply->readAll());
        partFile_->flush();
        const qint64 size = partFile_->size();
        partFile_->close();
        partFile_->deleteLater();
        partFile_ = nullptr;

        if (reply->error() != QNetworkReply::NoError) {
            emit downloadFailed(reply->errorString());
            return;
        }
        if (size != latest_.assetSize) {
            emit downloadFailed(QStringLiteral("size mismatch"));
            return;
        }
        if (!latest_.sha256.isEmpty()) {
            QFile f(partPath);
            f.open(QIODevice::ReadOnly);
            QCryptographicHash h(QCryptographicHash::Sha256);
            h.addData(&f);
            if (h.result().toHex() != latest_.sha256.toLatin1()) {
                f.close();
                QFile::remove(partPath);
                emit downloadFailed(QStringLiteral("checksum mismatch"));
                return;
            }
        }
        QFile::remove(target);
        QFile::rename(partPath, target);
        downloaded_ = target;
        Logger::Instance().Info("[Update] downloaded " + target.toStdString());
        emit downloadFinished(target);
    });
}

bool Updater::installAndQuit(bool silent) {
    if (downloaded_.isEmpty() || !QFile::exists(downloaded_)) return false;
    const QString params = silent
        ? QStringLiteral("/SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS")
        : QStringLiteral("/CLOSEAPPLICATIONS /RESTARTAPPLICATIONS");
    const std::wstring file = QDir::toNativeSeparators(downloaded_).toStdWString();
    const std::wstring args = params.toStdWString();
    SHELLEXECUTEINFOW sei{ sizeof(sei) };
    sei.fMask = SEE_MASK_NOASYNC;
    sei.lpVerb = L"open";
    sei.lpFile = file.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) {
        Logger::Instance().Error("[Update] cannot start the installer");
        return false;
    }
    QApplication::exit(0);
    return true;
}
