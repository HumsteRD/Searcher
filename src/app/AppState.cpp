#include "AppState.h"

#include "../core/ThreatJson.h"

AppState& AppState::instance() {
    static AppState* s = new AppState();
    return *s;
}

int AppState::pendingCount() const {
    int n = 0;
    for (const Item& i : items_)
        if (i.threat.status == ThreatStatus::Pending || i.threat.status == ThreatStatus::Failed) ++n;
    return n;
}

int AppState::criticalCount() const {
    int n = 0;
    for (const Item& i : items_)
        if (i.threat.severity == Severity::Critical &&
            (i.threat.status == ThreatStatus::Pending || i.threat.status == ThreatStatus::Failed))
            ++n;
    return n;
}

void AppState::beginScan(int mode, bool singleTarget, const QString& target) {
    scan_ = Scan{};
    scan_.running = true;
    scan_.mode = mode;
    scan_.singleTarget = singleTarget;
    scan_.target = target;
    scan_.percent = -1;
    scan_.startedAt = QDateTime::currentDateTime();
    items_.clear();
    emit itemsReset();
    emit scanChanged();
}

void AppState::setProgress(int percent, const QString& stage) {
    if (!scan_.running) return;
    // Процент не откатывается назад: шкала, прыгающая влево, читается как сбой.
    if (percent >= 0 && scan_.percent >= 0 && percent < scan_.percent) percent = scan_.percent;
    scan_.percent = percent;
    if (!stage.isEmpty()) scan_.stage = stage;
    emit scanChanged();
}

void AppState::setDetail(const QString& item, qint64 objects, int elapsedMs, int etaMs) {
    if (!scan_.running) return;
    scan_.currentItem = item;
    scan_.objects = objects;
    scan_.elapsedMs = elapsedMs;
    scan_.etaMs = etaMs;
    emit scanChanged();
}

void AppState::finishScan(bool cancelled) {
    if (!scan_.running) return;
    scan_.running = false;
    scan_.finished = true;
    scan_.cancelled = cancelled;
    if (!cancelled) scan_.percent = 100;
    scan_.finishedAt = QDateTime::currentDateTime();
    scan_.elapsedMs = static_cast<int>(scan_.startedAt.msecsTo(scan_.finishedAt));
    scan_.currentItem.clear();
    emit scanChanged();
}

void AppState::addThreat(int index, const QJsonObject& payload) {
    if (rowForHelperIndex(index) >= 0) return;
    Item it;
    it.index = index;
    it.threat = ThreatJson::FromJson(payload);
    items_.push_back(it);
    emit itemAdded(items_.size() - 1);
}

void AppState::addLocalThreat(const Threat& threat) {
    Item it;
    it.index = -1;
    it.threat = threat;
    items_.push_back(it);
    emit itemAdded(items_.size() - 1);
}

void AppState::setBusy(int row, bool busy) {
    if (row < 0 || row >= items_.size()) return;
    items_[row].busy = busy;
    emit itemChanged(row);
}

void AppState::setThreat(int row, const Threat& threat) {
    if (row < 0 || row >= items_.size()) return;
    items_[row].threat = threat;
    emit itemChanged(row);
}

void AppState::applyActionResult(int helperIndex, const QString& status, const QString& message,
                                 bool ok)
{
    const int row = rowForHelperIndex(helperIndex);
    if (row < 0) return;
    Item& it = items_[row];
    it.busy = false;
    it.threat.status = ThreatJson::StatusFromCode(status);
    if (!ok && it.threat.status == ThreatStatus::Pending) it.threat.status = ThreatStatus::Failed;
    it.threat.actionMessage = message.toStdWString();
    emit itemChanged(row);
}

void AppState::setVirusTotal(int row, int state, const QString& text) {
    if (row < 0 || row >= items_.size()) return;
    items_[row].vtState = state;
    items_[row].vtText = text;
    emit itemChanged(row);
}

int AppState::rowForHelperIndex(int index) const {
    if (index < 0) return -1;
    for (int i = 0; i < items_.size(); ++i)
        if (items_[i].index == index) return i;
    return -1;
}
