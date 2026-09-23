#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QFrame;

class HomePage : public QWidget {
    Q_OBJECT

public:
    explicit HomePage(QWidget* parent = nullptr);

    void setStats(int threats, int critical, int scanned);
    void setLastScanText(const QString& text);
    void setQuarantineCount(int count);

signals:
    void scanRequested();

private:
    // Три вердикта героя: геометрия одна, меняются плитка и слова.
    enum class Verdict { Protected, Threats, Critical };

    QWidget* buildHeroCard();
    QWidget* buildStatsRow();
    QFrame*  buildStatCard(const QString& title, QLabel** valueOut,
                           QLabel** subOut);
    void     applyVerdict(Verdict v);

    QFrame*      heroTile_;
    QLabel*      heroIcon_;
    QLabel*      heroTitle_;
    QLabel*      heroSubtitle_;
    QPushButton* scanButton_;

    QLabel*      threatsValue_;
    QLabel*      threatsSub_;
    QLabel*      filesValue_;
    QLabel*      filesSub_;
    QLabel*      quarValue_;
    QLabel*      quarSub_;

    Verdict      verdict_ = Verdict::Protected;
};
