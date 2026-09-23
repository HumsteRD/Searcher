#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QProgressBar;
class QPropertyAnimation;
class QVariantAnimation;
class QFrame;
class ToggleSwitch;
class GradientButton;

class ScanPage : public QWidget {
    Q_OBJECT

public:
    explicit ScanPage(QWidget* parent = nullptr);

    void setProgress(int percent, const QString& stage);
    void setRunning(bool running);
    void setStats(int threats, int critical);

    // Живые детали хода: что проверяется, сколько проверено,
    // сколько прошло и сколько примерно осталось (мс, -1 = неизвестно).
    void setDetail(const QString& currentItem, qint64 objectsScanned,
                   int elapsedMs, int etaMs);

signals:
    void scanRequested();
    void cancelRequested();

private:
    QWidget* buildScopeCard();
    void     applyMode(int mode);
    void     updateScopeSummary();

    GradientButton* modeButtons_[3] = { nullptr, nullptr, nullptr };
    QPushButton*  browseButton_ = nullptr;
    QPushButton*  browseFileButton_ = nullptr;
    QWidget*      pathRow_ = nullptr;
    QLabel*       customPathLabel_ = nullptr;
    QLabel*       scopeSummary_ = nullptr;
    ToggleSwitch* moduleToggles_[7] = { nullptr, nullptr, nullptr, nullptr,
                                        nullptr, nullptr, nullptr };

    QPushButton*  startButton_ = nullptr;
    QPushButton*  cancelButton_ = nullptr;
    QProgressBar* progress_ = nullptr;
    QLabel*       stageLabel_ = nullptr;
    QLabel*       percentLabel_ = nullptr;
    QLabel*       itemLabel_ = nullptr;
    QLabel*       countedLabel_ = nullptr;
    QLabel*       timeLabel_ = nullptr;
    QLabel*       threatsValueLabel_ = nullptr;
    QLabel*       criticalValueLabel_ = nullptr;

    QPropertyAnimation* progressAnim_ = nullptr;
    QVariantAnimation*  percentAnim_ = nullptr;
};
