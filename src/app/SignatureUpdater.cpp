#include "SignatureUpdater.h"
#include "AppSettings.h"
#include "Lang.h"
#include "Updater.h"

#include "../core/Logger.h"
#include "../engine/HashDatabase.h"
#include "../engine/SignatureStore.h"
#include "../engine/Unpack.h"
#include "../engine/YaraEngine.h"

#include <QDate>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSaveFile>
#include <QSettings>
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>

namespace {

constexpr const char* kYaraForgeApi = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest";
constexpr const char* kOwnSignaturesApi =
    "https://api.github.com/repos/HumsteRD/Searcher/releases/tags/signatures-latest";

QNetworkRequest Request(const QString& url) {
    QNetworkRequest r{ QUrl(url) };
    r.setHeader(QNetworkRequest::UserAgentHeader, "ThreatScanner/" + Updater::currentVersion());
    r.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    r.setTransferTimeout(120000);
    return r;
}

QString UpdateDir() {
    return QString::fromStdWString(SignatureStore::UpdateDir().wstring());
}

// Какой выпуск файла из релиза уже разобран: дата и размер ресурса.
// По ним видно, что качать нечего, без самой загрузки.
QString SeenAsset(const QString& name) {
    return QSettings("ThreatScanner", "ThreatScanner").value("v2/signatures/asset-" + name).toString();
}

void RememberAsset(const QString& name, const QString& stamp) {
    QSettings("ThreatScanner", "ThreatScanner").setValue("v2/signatures/asset-" + name, stamp);
}

} // namespace

SignatureUpdater& SignatureUpdater::instance() {
    static SignatureUpdater* s = new SignatureUpdater();
    return *s;
}

SignatureUpdater::SignatureUpdater() : nam_(new QNetworkAccessManager(this)) {}

void SignatureUpdater::updateAll(bool manual) {
    if (busy()) return;
    manual_ = manual;
    changed_ = false;
    notes_.clear();
    pending_ = 3;   // правила, полная база хэшей, свежие хэши
    emit started();
    updateRules(AppSettings::Get().extendedRules());
    updateHashDatabases();
}

void SignatureUpdater::doneOne(bool changed, const QString& note) {
    changed_ |= changed;
    if (!note.isEmpty()) notes_ << note;
    if (--pending_ > 0) return;
    AppSettings::Get().setLastSignatureUpdate(QDateTime::currentDateTime());
    HashDatabase::Get().Reload();
    emit finished(changed_, notes_.join("; "), manual_);
}

void SignatureUpdater::updateRules(bool extended) {
    QNetworkReply* meta = nam_->get(Request(kYaraForgeApi));
    connect(meta, &QNetworkReply::finished, this, [this, meta, extended]() {
        meta->deleteLater();
        if (meta->error() != QNetworkReply::NoError) {
            Logger::Instance().Warn("[Signatures] YARA-Forge check failed: " + meta->errorString().toStdString());
            doneOne(false, {});
            return;
        }
        const QJsonObject root = QJsonDocument::fromJson(meta->readAll()).object();
        const uint32_t remoteStamp = root["tag_name"].toString().left(8).toUInt();
        const std::filesystem::path current = SignatureStore::RulesFile(extended ? "extended" : "core");
        const uint32_t localStamp = current.empty() ? 0 : SignatureStore::RulesStamp(current);
        if (remoteStamp == 0 || remoteStamp <= localStamp) {
            doneOne(false, {});
            return;
        }
        const QString wanted = extended ? "yara-forge-rules-extended.zip" : "yara-forge-rules-core.zip";
        QString url;
        for (const QJsonValue& v : root["assets"].toArray())
            if (v.toObject()["name"].toString() == wanted) url = v.toObject()["browser_download_url"].toString();
        if (url.isEmpty()) { doneOne(false, {}); return; }

        QNetworkReply* dl = nam_->get(Request(url));
        connect(dl, &QNetworkReply::finished, this, [this, dl, extended, remoteStamp]() {
            dl->deleteLater();
            if (dl->error() != QNetworkReply::NoError) { doneOne(false, {}); return; }
            const QByteArray zip = dl->readAll();

            // Распаковка и пробная компиляция — в пуле потоков: это 1–3 секунды.
            auto* watcher = new QFutureWatcher<QString>(this);
            connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher, remoteStamp]() {
                const QString err = watcher->result();
                watcher->deleteLater();
                if (!err.isEmpty()) {
                    Logger::Instance().Warn("[Signatures] rules update rejected: " + err.toStdString());
                    doneOne(false, {});
                    return;
                }
                doneOne(true, TR("signature rules from %1").arg(QDate::fromString(QString::number(remoteStamp), "yyyyMMdd")
                                                                   .toString("dd.MM.yyyy")));
            });
            watcher->setFuture(QtConcurrent::run([zip, extended]() -> QString {
                const auto unpacked = Unpack::Extract(reinterpret_cast<const uint8_t*>(zip.constData()),
                                                      static_cast<size_t>(zip.size()),
                                                      Unpack::Limits{ 64u << 20, 96u << 20, 8 });
                for (const auto& item : unpacked.items) {
                    if (item.name.size() < 4 || item.name.substr(item.name.size() - 4) != ".yar") continue;
                    const std::string text(item.data.begin(), item.data.end());
                    std::string error;
                    int count = 0;
                    if (!YaraEngine::Validate(text, &error, &count)) return QString::fromStdString(error);
                    QSaveFile out(UpdateDir() + (extended ? "/rules-extended.yar" : "/rules-core.yar"));
                    if (!out.open(QIODevice::WriteOnly)) return out.errorString();
                    out.write(item.data.empty() ? QByteArray()
                                                : QByteArray(reinterpret_cast<const char*>(item.data.data()),
                                                             static_cast<int>(item.data.size())));
                    if (!out.commit()) return out.errorString();
                    Logger::Instance().Info("[Signatures] YARA rules updated: " + std::to_string(count) + " rules");
                    return {};
                }
                return QStringLiteral("no .yar file in the package");
            }));
        });
    });
}

void SignatureUpdater::updateHashDatabases() {
    // Обе базы хэшей лежат в релизе проекта: полная (base.tsdb) и свежие
    // записи за последние дни (recent.tsdb). Собирает их GitHub Actions.
    // Напрямую у MalwareBazaar программа больше ничего не берёт: выгрузки
    // там теперь выдаются только по личному ключу, а вшивать ключ
    // в программу, которая стоит у всех, нельзя.
    QNetworkReply* meta = nam_->get(Request(kOwnSignaturesApi));
    connect(meta, &QNetworkReply::finished, this, [this, meta]() {
        meta->deleteLater();
        if (meta->error() != QNetworkReply::NoError) {
            Logger::Instance().Warn("[Signatures] hash database check failed: " +
                                    meta->errorString().toStdString());
            doneOne(false, {});
            doneOne(false, {});
            return;
        }
        const QJsonArray assets = QJsonDocument::fromJson(meta->readAll()).object()["assets"].toArray();
        fetchDatabase(assets, "base.tsdb");
        fetchDatabase(assets, "recent.tsdb");
    });
}

void SignatureUpdater::fetchDatabase(const QJsonArray& assets, const QString& name) {
    QString url, assetStamp;
    qint64 size = 0;
    for (const QJsonValue& v : assets) {
        const QJsonObject a = v.toObject();
        if (a["name"].toString() != name) continue;
        url = a["browser_download_url"].toString();
        size = static_cast<qint64>(a["size"].toDouble());
        assetStamp = a["updated_at"].toString() + "/" + QString::number(size);
    }
    // Базы свежих записей в релизе может не быть вовсе — это не ошибка.
    if (url.isEmpty() || size <= 0) { doneOne(false, {}); return; }

    // Полная база весит около десяти мегабайт, а проверка идёт несколько
    // раз в день: тот же файл, что уже разобран, второй раз не качаем.
    const QString target = UpdateDir() + "/" + name;
    const bool haveData = name == "base.tsdb" ? HashDatabase::Get().Count() > 0 : QFile::exists(target);
    if (SeenAsset(name) == assetStamp && haveData) { doneOne(false, {}); return; }

    QNetworkReply* dl = nam_->get(Request(url));
    connect(dl, &QNetworkReply::finished, this, [this, dl, size, assetStamp, name, target]() {
        dl->deleteLater();
        if (dl->error() != QNetworkReply::NoError) { doneOne(false, {}); return; }
        const QByteArray body = dl->readAll();
        if (body.size() != size) { doneOne(false, {}); return; }   // оборванная загрузка

        const QString tmp = target + ".download";
        {
            QFile f(tmp);
            if (!f.open(QIODevice::WriteOnly) || f.write(body) != body.size()) {
                f.close();
                QFile::remove(tmp);
                doneOne(false, {});
                return;
            }
        }
        uint32_t remoteStamp = 0, count = 0;
        if (!HashDatabase::Validate(tmp.toStdWString(), &remoteStamp, &count)) {
            QFile::remove(tmp);
            Logger::Instance().Warn("[Signatures] " + name.toStdString() + " from the release is not a valid database");
            doneOne(false, {});
            return;
        }
        // Этот выпуск разобран — запоминаем, чтобы не качать его снова.
        RememberAsset(name, assetStamp);

        // Старее того, что уже есть, — не ставим (у полной базы «есть» —
        // это и копия из установки программы).
        uint32_t localStamp = 0;
        if (name == "base.tsdb") localStamp = HashDatabase::Get().NewestStamp();
        else HashDatabase::ReadHeader(target.toStdWString(), &localStamp);
        const bool newer = name == "base.tsdb" ? remoteStamp > localStamp : remoteStamp >= localStamp;
        if (!newer) {
            QFile::remove(tmp);
            doneOne(false, {});
            return;
        }
        QFile::remove(target);
        if (!QFile::rename(tmp, target)) {
            QFile::remove(tmp);
            doneOne(false, {});
            return;
        }
        Logger::Instance().Info("[Signatures] " + name.toStdString() + " updated: " + std::to_string(count) + " hashes");
        doneOne(true, name == "base.tsdb" ? TR("%1 known malicious files").arg(count)
                                          : TR("%1 new samples from the last days").arg(count));
    });
}
