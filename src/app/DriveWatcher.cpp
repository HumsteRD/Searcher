#include "DriveWatcher.h"
#include "Lang.h"

#include <Windows.h>

#include <QTimer>

namespace {

// Буквы дисков, на которых сейчас есть читаемый том. Устройство чтения
// карт без карты букву имеет, а тома — нет: такое диском не считаем.
quint32 PresentMask(QList<DriveWatcher::Drive>* out) {
    // Без этого Windows показала бы окно «Вставьте диск» на пустом приводе.
    DWORD previousMode = 0;
    SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &previousMode);

    quint32 mask = 0;
    const DWORD letters = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(letters & (1u << i))) continue;
        const wchar_t root[] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', 0 };
        const UINT type = GetDriveTypeW(root);
        if (type != DRIVE_REMOVABLE && type != DRIVE_FIXED) continue;

        wchar_t label[MAX_PATH + 1] = {};
        if (!GetVolumeInformationW(root, label, MAX_PATH, nullptr, nullptr, nullptr, nullptr, 0)) continue;
        mask |= 1u << i;
        if (!out) continue;

        DriveWatcher::Drive d;
        d.root = QString::fromWCharArray(root);
        d.label = QString::fromWCharArray(label);
        d.removable = type == DRIVE_REMOVABLE;
        ULARGE_INTEGER freeToCaller{}, total{}, freeTotal{};
        if (GetDiskFreeSpaceExW(root, &freeToCaller, &total, &freeTotal)) {
            d.totalBytes = static_cast<qint64>(total.QuadPart);
            d.freeBytes = static_cast<qint64>(freeTotal.QuadPart);
        }
        out->push_back(d);
    }

    SetThreadErrorMode(previousMode, nullptr);
    return mask;
}

} // namespace

QString DriveWatcher::Drive::title() const {
    const QString letter = root.left(2);
    const QString name = label.isEmpty() ? (removable ? TR("Removable drive") : TR("Local drive")) : label;
    return QStringLiteral("%1 (%2)").arg(name, letter);
}

DriveWatcher::DriveWatcher(QObject* parent) : QObject(parent) {
    qRegisterMetaType<DriveWatcher::Drive>("DriveWatcher::Drive");
    timer_ = new QTimer(this);
    timer_->setInterval(3000);
    connect(timer_, &QTimer::timeout, this, &DriveWatcher::poll);
}

void DriveWatcher::setEnabled(bool on) {
    if (on == enabled_) return;
    enabled_ = on;
    if (!on) {
        timer_->stop();
        return;
    }
    // Что подключено сейчас — не новость: предлагать проверку системного
    // диска при каждом запуске незачем.
    known_ = PresentMask(nullptr);
    timer_->start();
}

QList<DriveWatcher::Drive> DriveWatcher::drives() {
    QList<Drive> out;
    PresentMask(&out);
    return out;
}

void DriveWatcher::poll() {
    const quint32 now = PresentMask(nullptr);
    const quint32 arrived = now & ~known_;
    known_ = now;
    if (!arrived) return;
    for (const Drive& d : drives()) {
        const int index = d.root.at(0).unicode() - 'A';
        if (index >= 0 && index < 26 && (arrived & (1u << index))) emit driveArrived(d);
    }
}
