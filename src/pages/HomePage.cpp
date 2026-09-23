#include "HomePage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"
#include "../ui/Icons.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QFrame>
#include "../ui/GradientButton.h"
#include <QLocale>

using PageHelpers::BtnStyle;

namespace {

struct VerdictStyle {
    const char* title;
    const char* tileBg;
    const char* tileBorder;
    const char* iconColor;
    const char* glyph;   // ресурс из identity-набора
};

} // namespace

HomePage::HomePage(QWidget* parent)
    : QWidget(parent)
{
    QVBoxLayout* root = PageHelpers::scrollablePageLayout(this);
    root->setSpacing(Theme::Space::L);

    root->addWidget(PageHelpers::sectionTitle(TR("SYSTEM STATUS"), this));
    root->addWidget(buildHeroCard());

    root->addSpacing(Theme::Space::XXS);
    root->addWidget(PageHelpers::sectionTitle(TR("OVERVIEW"), this));
    root->addWidget(buildStatsRow());

    root->addStretch();

    applyVerdict(Verdict::Protected);
}

QWidget* HomePage::buildHeroCard() {
    QFrame* card = PageHelpers::card(this, Theme::Radius::HERO);
    PageHelpers::applyHeroShadow(card);

    QVBoxLayout* lay = new QVBoxLayout(card);
    lay->setContentsMargins(Theme::Space::MAX, Theme::Space::HUGE,
                            Theme::Space::MAX, Theme::Space::HUGE);
    lay->setSpacing(Theme::Space::S);
    lay->setAlignment(Qt::AlignCenter);

    // Плитка с иконкой — единственный элемент, который меняет цвет по вердикту.
    heroTile_ = new QFrame(card);
    heroTile_->setFixedSize(72, 72);
    heroIcon_ = new QLabel(heroTile_);
    heroIcon_->setAlignment(Qt::AlignCenter);
    heroIcon_->setStyleSheet("background: transparent; border: none;");

    QVBoxLayout* tileLay = new QVBoxLayout(heroTile_);
    tileLay->setContentsMargins(0, 0, 0, 0);
    tileLay->addWidget(heroIcon_, 0, Qt::AlignCenter);

    QHBoxLayout* tileRow = new QHBoxLayout;
    tileRow->addStretch();
    tileRow->addWidget(heroTile_);
    tileRow->addStretch();
    lay->addLayout(tileRow);

    lay->addSpacing(Theme::Space::XXS);

    heroTitle_ = new QLabel(TR("System is protected"), card);
    heroTitle_->setAlignment(Qt::AlignCenter);
    heroTitle_->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::HERO));
    PageHelpers::setTracking(heroTitle_, -0.2);
    lay->addWidget(heroTitle_);

    heroSubtitle_ = new QLabel(TR("No scan has been performed yet"), card);
    heroSubtitle_->setAlignment(Qt::AlignCenter);
    heroSubtitle_->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::CONTROL));
    lay->addWidget(heroSubtitle_);

    lay->addSpacing(Theme::Space::L);

    auto* g = new GradientButton(TR("Start scan"), GradientButton::Style::Filled, card);
    g->setFixedHeight(Theme::Size::BTN_HERO);
    PageHelpers::applyPrimaryButtonShadow(g);
    scanButton_ = g;
    scanButton_->setMinimumWidth(200);
    connect(scanButton_, &QPushButton::clicked, this, &HomePage::scanRequested);

    QHBoxLayout* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    btnRow->addWidget(scanButton_);
    btnRow->addStretch();
    lay->addLayout(btnRow);

    card->setMinimumHeight(card->sizeHint().height());
    return card;
}

QFrame* HomePage::buildStatCard(const QString& title, QLabel** valueOut,
                                QLabel** subOut)
{
    QFrame* card = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* lay = new QVBoxLayout(card);
    lay->setContentsMargins(Theme::Space::XL, Theme::Space::L,
                            Theme::Space::XL, Theme::Space::L);
    lay->setSpacing(Theme::Space::XXS);

    QLabel* t = new QLabel(title, card);
    t->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_MUTED).arg(Theme::Font::OVERLINE));
    PageHelpers::setTracking(t, Theme::Font::TRACK_OVERLINE);
    lay->addWidget(t);

    QLabel* v = new QLabel("0", card);
    v->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::METRIC));
    lay->addWidget(v);
    *valueOut = v;

    QLabel* s = new QLabel(QString(), card);
    s->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::CONTROL));
    lay->addWidget(s);
    *subOut = s;

    return card;
}

QWidget* HomePage::buildStatsRow() {
    QWidget* row = new QWidget(this);
    row->setStyleSheet("background: transparent;");

    QHBoxLayout* lay = new QHBoxLayout(row);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(Theme::Space::M);

    lay->addWidget(buildStatCard(TR("THREATS FOUND"), &threatsValue_, &threatsSub_));
    lay->addWidget(buildStatCard(TR("FILES SCANNED"), &filesValue_,   &filesSub_));
    lay->addWidget(buildStatCard(TR("IN QUARANTINE"), &quarValue_,    &quarSub_));

    threatsSub_->setText(TR("No scan yet"));
    filesSub_->setText(TR("Objects inspected"));
    quarSub_->setText(TR("Isolated files"));

    return row;
}

void HomePage::applyVerdict(Verdict v) {
    static const VerdictStyle kStyles[] = {
        { "System is protected",        Theme::OK_BG,       Theme::OK_BORDER,
          Theme::OK,       "glyph-clean" },
        { "Threats detected",           Theme::SEV_HIGH_BG, Theme::SEV_HIGH_BORDER,
          Theme::SEV_HIGH, "glyph-threat" },
        { "Critical threats detected!", Theme::SEV_CRIT_BG, Theme::SEV_CRIT_BORDER,
          Theme::SEV_CRIT, "glyph-critical" },
    };

    const VerdictStyle& s = kStyles[static_cast<int>(v)];
    verdict_ = v;

    heroTile_->setStyleSheet(QString(
        "background-color: %1; border: 1px solid %2; border-radius: %3px;"
    ).arg(s.tileBg, s.tileBorder).arg(Theme::Radius::TILE));

    heroIcon_->setPixmap(Icons::fromResource(s.glyph, 34, QColor(s.iconColor)));
    heroTitle_->setText(TR(s.title));
}

void HomePage::setStats(int threats, int critical, int scanned) {
    threatsValue_->setText(QString::number(threats));
    threatsValue_->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(threats == 0 ? Theme::TEXT_PRIMARY
                       : (critical > 0 ? Theme::SEV_CRIT : Theme::SEV_HIGH))
     .arg(Theme::Font::METRIC));

    if (threats == 0) {
        threatsSub_->setText(TR("No action required"));
    } else if (critical > 0) {
        threatsSub_->setText(QString("%1 critical").arg(critical));
    } else {
        threatsSub_->setText(TR("None critical"));
    }

    // Разделитель разрядов: числа тут крупные и читаются плохо без него.
    filesValue_->setText(QLocale().toString(scanned));

    if (threats == 0)      applyVerdict(Verdict::Protected);
    else if (critical > 0) applyVerdict(Verdict::Critical);
    else                   applyVerdict(Verdict::Threats);
}

void HomePage::setLastScanText(const QString& text) {
    heroSubtitle_->setText(text);
}

void HomePage::setQuarantineCount(int count) {
    quarValue_->setText(QString::number(count));
}
