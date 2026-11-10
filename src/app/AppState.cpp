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

int AppState::foundInScan() const {
    int n = 0;
    for (const Item& i : items_)
        if (!i.carried) ++n;
    return n;
}

QString AppState::stageName(int module) {
    switch (module) {
    case 0:  return QStringLiteral("Files");
    case 1:  return QStringLiteral("Processes");
    case 2:  return QStringLiteral("Autoruns");
    case 3:  return QStringLiteral("Tasks");
    case 4:  return QStringLiteral("Services");
    case 5:  return QStringLiteral("Network");
    default: return {};
    }
}

int AppState::currentStageIndex() const {
    if (scan_.stage == QLatin1String("Done")) return scan_.stages.size();
    for (int i = 0; i < scan_.stages.size(); ++i)
        if (stageName(scan_.stages[i]) == scan_.stage) return i;
    return -1;
}

void AppState::beginScan(int mode, bool singleTarget, const QString& target, const QVector<int>& stages) {
    scan_ = Scan{};
    scan_.running = true;
    scan_.mode = mode;
    scan_.singleTarget = singleTarget;
    scan_.target = target;
    scan_.stages = stages;
    scan_.percent = -1;
    scan_.startedAt = QDateTime::currentDateTime();

    // Находки прошлой проверки уходят, а найденное вне проверок и ещё не
    // решённое (опасная загрузка, перетащенный файл) остаётся: начало новой
    // проверки — не повод молча забыть про файл, который ждёт решения.
    QVector<Item> kept;
    for (const Item& it : items_) {
        const bool open = it.threat.status == ThreatStatus::Pending || it.threat.status == ThreatStatus::Failed;
        if (it.index < 0 && open && !it.busy) {
            kept.push_back(it);
            kept.back().carried = true;
        }
    }
    items_ = kept;
    emit itemsReset();
    emit scanChanged();
}

void AppState::setPaused(bool paused) {
    if (!scan_.running || scan_.paused == paused) return;
    scan_.paused = paused;
    if (paused) scan_.etaMs = -1;
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
    scan_.paused = false;
    scan_.finished = true;
    scan_.cancelled = cancelled;
    if (!cancelled) scan_.percent = 100;
    scan_.finishedAt = QDateTime::currentDateTime();
    // Длительность считает помощник — без времени на паузе. Часы окна
    // годятся, только если от помощника ничего не пришло (не поднялся).
    if (scan_.elapsedMs <= 0)
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

void AppState::clearItems() {
    items_.clear();
    emit itemsReset();
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
