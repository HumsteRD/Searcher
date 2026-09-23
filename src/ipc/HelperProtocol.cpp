#include "HelperProtocol.h"

#include <QRandomGenerator>

namespace Ipc {

QString MakePipeName() {
    // 128 бит случайности: имя канала видно в системе, и предсказуемое
    // имя позволило бы чужому процессу занять его раньше помощника.
    quint64 high = QRandomGenerator::system()->generate64();
    quint64 low  = QRandomGenerator::system()->generate64();
    return QString("ThreatScanner-%1%2")
        .arg(high, 16, 16, QChar('0'))
        .arg(low,  16, 16, QChar('0'));
}

QString PipePath(const QString& name) {
    return "\\\\.\\pipe\\" + name;
}

} // namespace Ipc
