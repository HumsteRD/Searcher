#include "VirusTotalClient.h"
#include "AppSettings.h"
#include "../core/Logger.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTimer>
#include <QUrl>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>

namespace {

const char* kBaseUrl = "https://www.virustotal.com/api/v3/files/";

// SHA-256 пустого файла — гарантированно известен VirusTotal,
// поэтому годится как проверка валидности ключа.
const char* kEmptyFileSha256 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

QNetworkRequest MakeRequest(const QString& sha256, const QString& apiKey) {
    QNetworkRequest req(QUrl(QString(kBaseUrl) + sha256));
    req.setRawHeader("x-apikey", apiKey.toUtf8());
    req.setRawHeader("Accept", "application/json");
    return req;
}

// Разбирает last_analysis_stats -> (malicious, total)
bool ParseStats(const QByteArray& body, int& malicious, int& total) {
    QJsonParseError err{};
    QJsonDocument doc = QJsonDocument::fromJson(body, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return false;

    QJsonObject stats = doc.object()
                           .value("data").toObject()
                           .value("attributes").toObject()
                           .value("last_analysis_stats").toObject();
    if (stats.isEmpty()) return false;

    const int mal   = stats.value("malicious").toInt();
    const int susp  = stats.value("suspicious").toInt();
    const int harm  = stats.value("harmless").toInt();
    const int undet = stats.value("undetected").toInt();
    const int tout  = stats.value("timeout").toInt();

    malicious = mal + susp;
    total     = mal + susp + harm + undet + tout;
    return total > 0;
}

} // namespace

VirusTotalClient& VirusTotalClient::instance() {
    // Намеренно без деструктора: QObject, разрушаемый после QApplication,
    // роняет приложение на выходе. Живёт до конца процесса.
    static VirusTotalClient* c = new VirusTotalClient();
    return *c;
}

VirusTotalClient::VirusTotalClient(QObject* parent)
    : QObject(parent)
{
    nam_   = new QNetworkAccessManager(this);
    timer_ = new QTimer(this);
    timer_->setSingleShot(true);
    connect(timer_, &QTimer::timeout, this, &VirusTotalClient::sendNext);
}

bool VirusTotalClient::hasApiKey() const {
    return !AppSettings::Get().virusTotalKey().isEmpty();
}

int VirusTotalClient::pendingCount() const {
    return queue_.size() + (inFlight_ ? 1 : 0);
}

void VirusTotalClient::lookup(int index, const QString& sha256) {
    if (sha256.isEmpty()) {
        emit lookupFinished(index, sha256, 0, 0, false, false, "No file hash available.");
        return;
    }
    if (!hasApiKey()) {
        emit lookupFinished(index, sha256, 0, 0, false, false,
                            "VirusTotal API key is not set (Settings).");
        return;
    }
    if (queued_.contains(index)) return;   // уже в очереди

    queued_.insert(index);
    queue_.enqueue({ index, sha256 });
    emitQueueSize();
    pump();
}

void VirusTotalClient::emitQueueSize() {
    emit queueSizeChanged(pendingCount());
}

void VirusTotalClient::pump() {
    if (inFlight_ || queue_.isEmpty() || timer_->isActive()) return;
    sendNext();
}

void VirusTotalClient::sendNext() {
    if (inFlight_ || queue_.isEmpty()) return;

    const auto item   = queue_.dequeue();
    const int index   = item.first;
    const QString sha = item.second;

    const QString apiKey =
        AppSettings::Get().virusTotalKey();
    if (apiKey.isEmpty()) {
        queued_.remove(index);
        emit lookupFinished(index, sha, 0, 0, false, false,
                            "VirusTotal API key is not set (Settings).");
        emitQueueSize();
        return;
    }

    inFlight_ = true;
    QNetworkReply* reply = nam_->get(MakeRequest(sha, apiKey));

    connect(reply, &QNetworkReply::finished, this, [this, reply, index, sha]() {
        reply->deleteLater();
        inFlight_ = false;
        queued_.remove(index);

        const int http = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();

        if (http == 200) {
            int malicious = 0, total = 0;
            if (ParseStats(body, malicious, total)) {
                Logger::Instance().Info(
                    "[VT] " + sha.left(12).toStdString() + "... -> " +
                    std::to_string(malicious) + "/" + std::to_string(total));
                emit lookupFinished(index, sha, malicious, total, true, true, QString());
            } else {
                emit lookupFinished(index, sha, 0, 0, false, false,
                                    "Unexpected VirusTotal response.");
            }
        } else if (http == 404) {
            emit lookupFinished(index, sha, 0, 0, false, true, QString());
        } else if (http == 401) {
            emit lookupFinished(index, sha, 0, 0, false, false, "Invalid API key.");
        } else if (http == 429) {
            emit lookupFinished(index, sha, 0, 0, false, false,
                                "Rate limit exceeded — try again in a minute.");
        } else if (http != 0) {
            emit lookupFinished(index, sha, 0, 0, false, false,
                                QString("VirusTotal HTTP %1").arg(http));
        } else {
            emit lookupFinished(index, sha, 0, 0, false, false,
                                reply->errorString());
        }

        emitQueueSize();

        // Следующий запрос — не раньше, чем позволит лимит.
        if (!queue_.isEmpty()) timer_->start(kMinIntervalMs);
    });
}

void VirusTotalClient::testApiKey() {
    const QString apiKey =
        AppSettings::Get().virusTotalKey();
    if (apiKey.isEmpty()) {
        emit apiKeyTested(false, "Enter an API key first.");
        return;
    }

    QNetworkReply* reply = nam_->get(MakeRequest(kEmptyFileSha256, apiKey));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int http = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();

        if (http == 200 || http == 404) {
            emit apiKeyTested(true, "API key works.");
        } else if (http == 401) {
            emit apiKeyTested(false, "Invalid API key.");
        } else if (http == 429) {
            emit apiKeyTested(false, "Key is valid but rate-limited right now.");
        } else if (http != 0) {
            emit apiKeyTested(false, QString("VirusTotal HTTP %1").arg(http));
        } else {
            emit apiKeyTested(false, reply->errorString());
        }
    });
}
