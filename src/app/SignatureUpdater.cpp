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
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>

namespace {

constexpr const char* kYaraForgeApi = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest";
constexpr const char* kOwnSignaturesApi =
    "https://api.github.com/repos/HumsteRD/Searcher/releases/tags/signatures-latest";
constexpr const char* kBazaarRecent = "https://bazaar.abuse.ch/export/csv/recent/";

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

// Разбор CSV MalwareBazaar: sha256 (колонка 2), тип (7), семейство (9),
// процент VirusTotal (11). Правила отбора — как в tools/sigdb/build_sigdb.py.
std::vector<HashDatabase::Entry> ParseBazaarCsv(const QByteArray& csv) {
    static const QSet<QString> kTypes = {
        "exe", "dll", "msi", "sys", "scr", "cpl", "ocx", "js", "jse", "vbs", "vbe", "ps1", "psm1",
        "bat", "cmd", "hta", "wsf", "lnk", "py", "jar", "zip", "rar", "7z", "iso", "img", "vhd",
        "cab", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "rtf", "one",
        "pdf", "chm", "html", "htm", "xll", "reg", "msix", "appx",
    };
    std::vector<HashDatabase::Entry> out;
    for (const QByteArray& rawLine : csv.split('\n')) {
        const QByteArray line = rawLine.trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        // Поля в кавычках, разделитель «", "».
        QList<QByteArray> cols = line.split(',');
        for (QByteArray& c : cols) {
            c = c.trimmed();
            if (c.startsWith('"')) c.remove(0, 1);
            if (c.endsWith('"')) c.chop(1);
        }
        if (cols.size() < 11) continue;
        const std::string sha = cols[1].toLower().toStdString();
        const QString type = QString::fromLatin1(cols[6]).toLower();
        QString family = QString::fromUtf8(cols[8]);
        if (sha.size() != 64 || !kTypes.contains(type)) continue;
        if (family.isEmpty() || family == "n/a") {
            bool ok = false;
            const double vt = cols[10].toDouble(&ok);
            if (!ok || vt < 10.0) continue;
            family.clear();
        }
        uint64_t key = 0;
        if (!HashDatabase::KeyFromHex(sha, key)) continue;
        out.emplace_back(key, family.toStdString());
    }
    return out;
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
    pending_ = 3;
    emit started();
    updateRules(AppSettings::Get().extendedRules());
    updateBaseHashes();
    updateRecentHashes();
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

void SignatureUpdater::updateBaseHashes() {
    QNetworkReply* meta = nam_->get(Request(kOwnSignaturesApi));
    connect(meta, &QNetworkReply::finished, this, [this, meta]() {
        meta->deleteLater();
        if (meta->error() != QNetworkReply::NoError) { doneOne(false, {}); return; }
        const QJsonObject root = QJsonDocument::fromJson(meta->readAll()).object();
        QString url;
        qint64 size = 0;
        for (const QJsonValue& v : root["assets"].toArray()) {
            const QJsonObject a = v.toObject();
            if (a["name"].toString() == "base.tsdb") {
                url = a["browser_download_url"].toString();
                size = static_cast<qint64>(a["size"].toDouble());
            }
        }
        if (url.isEmpty() || size <= 0) { doneOne(false, {}); return; }

        QNetworkReply* dl = nam_->get(Request(url));
        connect(dl, &QNetworkReply::finished, this, [this, dl]() {
            dl->deleteLater();
            if (dl->error() != QNetworkReply::NoError) { doneOne(false, {}); return; }
            const QString tmp = UpdateDir() + "/base.tsdb.download";
            {
                QFile f(tmp);
                if (!f.open(QIODevice::WriteOnly)) { doneOne(false, {}); return; }
                f.write(dl->readAll());
            }
            uint32_t remoteStamp = 0, count = 0;
            if (!HashDatabase::Validate(tmp.toStdWString(), &remoteStamp, &count)) {
                QFile::remove(tmp);
                doneOne(false, {});
                return;
            }
            const uint32_t localStamp = HashDatabase::Get().NewestStamp();
            if (remoteStamp <= localStamp) {
                QFile::remove(tmp);
                doneOne(false, {});
                return;
            }
            const QString target = UpdateDir() + "/base.tsdb";
            QFile::remove(target);
            QFile::rename(tmp, target);
            Logger::Instance().Info("[Signatures] hash database updated: " + std::to_string(count));
            doneOne(true, TR("%1 known malicious files").arg(count));
        });
    });
}

void SignatureUpdater::updateRecentHashes() {
    QNetworkReply* dl = nam_->get(Request(kBazaarRecent));
    connect(dl, &QNetworkReply::finished, this, [this, dl]() {
        dl->deleteLater();
        if (dl->error() != QNetworkReply::NoError) {
            Logger::Instance().Warn("[Signatures] MalwareBazaar unavailable: " + dl->errorString().toStdString());
            doneOne(false, {});
            return;
        }
        const QByteArray csv = dl->readAll();
        auto* watcher = new QFutureWatcher<int>(this);
        connect(watcher, &QFutureWatcher<int>::finished, this, [this, watcher]() {
            const int added = watcher->result();
            watcher->deleteLater();
            doneOne(added > 0, added > 0 ? TR("%1 new samples from the last days").arg(added) : QString());
        });
        watcher->setFuture(QtConcurrent::run([csv]() -> int {
            std::vector<HashDatabase::Entry> fresh = ParseBazaarCsv(csv);
            if (fresh.empty()) return 0;
            const std::filesystem::path file = SignatureStore::UpdateDir() / L"recent.tsdb";
            std::vector<HashDatabase::Entry> all;
            HashDatabase::ReadEntries(file, all);
            const size_t before = all.size();
            all.insert(all.end(), fresh.begin(), fresh.end());
            // Свежая часть не должна расти без конца: полная база её догонит.
            if (all.size() > 300000) all.erase(all.begin(), all.begin() + (all.size() - 300000));
            const uint32_t stamp = QDate::currentDate().toString("yyyyMMdd").toUInt();
            if (!HashDatabase::WriteFile(file, stamp, all)) return 0;
            std::vector<HashDatabase::Entry> check;
            HashDatabase::ReadEntries(file, check);
            return static_cast<int>(check.size() > before ? check.size() - before : 0);
        }));
    });
}
