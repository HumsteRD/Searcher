#include "ScanPage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"
#include "../core/AppSettings.h"
#include "../ui/ToggleSwitch.h"
#include <QFileDialog>
#include <QGridLayout>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QFrame>
#include "../ui/GradientButton.h"
#include <QPropertyAnimation>
#include <QVariantAnimation>
#include <QFontMetrics>
#include <QLocale>

using PageHelpers::BtnStyle;

ScanPage::ScanPage(QWidget* parent)
    : QWidget(parent)
{
    QVBoxLayout* root = PageHelpers::scrollablePageLayout(this);

    root->addWidget(PageHelpers::pageTitle(TR("Scan"), this));
    root->addWidget(PageHelpers::pageSubtitle(
        TR("Run a full system scan to detect threats across registry, files, "
           "processes, scheduled tasks and network connections."), this));

    root->addSpacing(Theme::Space::S);
    root->addWidget(buildScopeCard());

    // ─── Карточка процесса ───
    QFrame* card = PageHelpers::card(this, Theme::Radius::HERO);
    QVBoxLayout* cardLay = new QVBoxLayout(card);
    cardLay->setContentsMargins(Theme::Space::HUGE, Theme::Space::XXL,
                                Theme::Space::HUGE, Theme::Space::XXL);
    cardLay->setSpacing(Theme::Space::L);

    QWidget* topRow = new QWidget(card);
    topRow->setStyleSheet("background: transparent;");
    QHBoxLayout* topLay = new QHBoxLayout(topRow);
    topLay->setContentsMargins(0, 0, 0, 0);

    QWidget* leftCol = new QWidget(topRow);
    leftCol->setStyleSheet("background: transparent;");
    QVBoxLayout* leftLay = new QVBoxLayout(leftCol);
    leftLay->setContentsMargins(0, 0, 0, 0);
    leftLay->setSpacing(Theme::Space::XXS);

    leftLay->addWidget(PageHelpers::sectionTitle(TR("STATUS"), leftCol));

    stageLabel_ = new QLabel(TR("Ready to scan"), leftCol);
    stageLabel_->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::TITLE));
    leftLay->addWidget(stageLabel_);

    topLay->addWidget(leftCol);
    topLay->addStretch();

    percentLabel_ = new QLabel("0%", topRow);
    percentLabel_->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::ACCENT_TEXT).arg(Theme::Font::METRIC));
    percentLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    topLay->addWidget(percentLabel_);

    cardLay->addWidget(topRow);

    // ─── Прогресс ───
    progress_ = new QProgressBar(card);
    progress_->setRange(0, 100);
    progress_->setValue(0);
    progress_->setTextVisible(false);
    progress_->setFixedHeight(8);
    progress_->setStyleSheet(QString(
        "QProgressBar {"
        "  background-color: %1;"
        "  border: none;"
        "  border-radius: %2px;"
        "}"
        "QProgressBar::chunk {"
        "  border-radius: %2px;"
        "  background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
        "                                    stop:0 %3, stop:1 %4);"
        "}"
    ).arg(Theme::SUNKEN).arg(Theme::Radius::PROGRESS)
     .arg(Theme::ACCENT, Theme::ACCENT_GRAD_END));
    cardLay->addWidget(progress_);

    // Под прогрессом — что именно проверяется сейчас. Без этой строки
    // сканирование выглядело как зависшие 0%, и было непонятно, идёт ли работа.
    itemLabel_ = new QLabel("—", card);
    itemLabel_->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "font-family: 'Cascadia Mono', 'Consolas', monospace;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_MONO_DIM).arg(Theme::Font::OVERLINE));
    itemLabel_->setTextFormat(Qt::PlainText);
    cardLay->addWidget(itemLabel_);

    QWidget* metaRow = new QWidget(card);
    metaRow->setStyleSheet("background: transparent;");
    QHBoxLayout* metaLay = new QHBoxLayout(metaRow);
    metaLay->setContentsMargins(0, 0, 0, 0);
    metaLay->setSpacing(Theme::Space::M);

    auto metaLabel = [&](QLabel** out, const QString& initial) {
        QLabel* l = new QLabel(initial, metaRow);
        l->setStyleSheet(QString(
            "color: %1; font-size: %2px;"
            "background: transparent; border: none;"
        ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::CONTROL));
        *out = l;
        return l;
    };

    metaLay->addWidget(metaLabel(&countedLabel_, "0 objects checked"));
    metaLay->addStretch();
    metaLay->addWidget(metaLabel(&timeLabel_, QString()));

    cardLay->addWidget(metaRow);

    // Заполнение и число процентов едут вместе, 240 мс.
    progressAnim_ = new QPropertyAnimation(progress_, "value", this);
    progressAnim_->setDuration(240);
    progressAnim_->setEasingCurve(QEasingCurve::OutCubic);

    percentAnim_ = new QVariantAnimation(this);
    percentAnim_->setDuration(240);
    percentAnim_->setEasingCurve(QEasingCurve::Linear);
    connect(percentAnim_, &QVariantAnimation::valueChanged,
            this, [this](const QVariant& v) {
        percentLabel_->setText(QString("%1%").arg(v.toInt()));
    });

    // ─── Кнопки ───
    QWidget* btnRow = new QWidget(card);
    btnRow->setStyleSheet("background: transparent;");
    QHBoxLayout* btnLay = new QHBoxLayout(btnRow);
    btnLay->setContentsMargins(0, 0, 0, 0);
    btnLay->setSpacing(Theme::Space::S);

    auto* g = new GradientButton(TR("Start scan"), GradientButton::Style::Filled, btnRow);
    g->setFixedHeight(Theme::Size::BTN_HERO);
    PageHelpers::applyPrimaryButtonShadow(g);
    startButton_ = g;
    startButton_->setMinimumWidth(180);
    connect(startButton_, &QPushButton::clicked, this, &ScanPage::scanRequested);

    auto* cancel = new GradientButton(TR("Cancel"),
                                      GradientButton::Style::Outline, btnRow);
    cancel->setFixedHeight(Theme::Size::BTN_HERO);
    cancel->setMinimumWidth(140);
    cancel->setGradient(QColor(Theme::SEV_HIGH), QColor(Theme::SEV_CRIT));
    cancelButton_ = cancel;
    cancelButton_->setVisible(false);
    connect(cancelButton_, &QPushButton::clicked, this, &ScanPage::cancelRequested);

    btnLay->addWidget(startButton_);
    btnLay->addWidget(cancelButton_);
    btnLay->addStretch();

    cardLay->addWidget(btnRow);
    // Иначе при нехватке высоты текст статуса и кнопка срезаются.
    card->setMinimumHeight(card->sizeHint().height());
    root->addWidget(card);

    // ─── Счётчики ───
    QWidget* statsRow = new QWidget(this);
    statsRow->setStyleSheet("background: transparent;");
    QHBoxLayout* statsLay = new QHBoxLayout(statsRow);
    statsLay->setContentsMargins(0, 0, 0, 0);
    statsLay->setSpacing(Theme::Space::M);

    auto makeStat = [this](const QString& title, QLabel** out) {
        QFrame* c = PageHelpers::card(this, Theme::Radius::CARD);
        QVBoxLayout* l = new QVBoxLayout(c);
        l->setContentsMargins(Theme::Space::XL, Theme::Space::L,
                              Theme::Space::XL, Theme::Space::L);
        l->setSpacing(Theme::Space::XXS);

        l->addWidget(PageHelpers::sectionTitle(title, c));

        QLabel* v = new QLabel("0", c);
        v->setStyleSheet(QString(
            "color: %1; font-size: %2px; font-weight: 600;"
            "background: transparent; border: none;"
        ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::METRIC));
        l->addWidget(v);

        *out = v;
        return c;
    };

    statsLay->addWidget(makeStat(TR("THREATS FOUND"), &threatsValueLabel_));
    statsLay->addWidget(makeStat(TR("CRITICAL"),      &criticalValueLabel_));

    root->addWidget(statsRow);
    root->addStretch();
}

QWidget* ScanPage::buildScopeCard() {
    QFrame* card = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* lay = new QVBoxLayout(card);
    lay->setContentsMargins(Theme::Space::XL, Theme::Space::L,
                            Theme::Space::XL, Theme::Space::L);
    lay->setSpacing(Theme::Space::S);

    lay->addWidget(PageHelpers::sectionTitle(TR("SCAN SCOPE"), card));

    // ─── Режим ───
    QWidget* modeRow = new QWidget(card);
    modeRow->setStyleSheet("background: transparent;");
    QHBoxLayout* modeLay = new QHBoxLayout(modeRow);
    modeLay->setContentsMargins(0, 0, 0, 0);
    modeLay->setSpacing(Theme::Space::XS);

    const char* kModeNames[3] = { "Quick", "Full", "Folder" };
    for (int i = 0; i < 3; ++i) {
        auto* b = new GradientButton(TR(kModeNames[i]),
                                     GradientButton::Style::Outline, modeRow);
        b->setFixedHeight(Theme::Size::BTN_HEADER);
        b->setMinimumWidth(120);
        b->setCheckable(true);
        modeButtons_[i] = b;
        connect(b, &QPushButton::clicked, this, [this, i]() { applyMode(i); });
        modeLay->addWidget(b);
    }

    browseButton_ = PageHelpers::button(TR("Folder…"),
                                        PageHelpers::BtnStyle::Secondary, card);
    browseButton_->setFixedHeight(Theme::Size::BTN_ROW);
    connect(browseButton_, &QPushButton::clicked, this, [this]() {
        const QString dir = QFileDialog::getExistingDirectory(
            this, TR("Choose folder to scan"), customPathLabel_->text());
        if (dir.isEmpty()) return;
        AppSettings::Get().SetCustomPath(dir.toStdWString());
        applyMode(2);
    });

    // Отдельная кнопка: диалог выбора папки файлы не показывает в принципе.
    browseFileButton_ = PageHelpers::button(TR("File…"),
                                            PageHelpers::BtnStyle::Secondary, card);
    browseFileButton_->setFixedHeight(Theme::Size::BTN_ROW);
    connect(browseFileButton_, &QPushButton::clicked, this, [this]() {
        const QString file = QFileDialog::getOpenFileName(
            this, TR("Choose file to scan"), customPathLabel_->text(),
            TR("All files (*)"));
        if (file.isEmpty()) return;
        AppSettings::Get().SetCustomPath(file.toStdWString());
        applyMode(2);
    });
    modeLay->addStretch();
    lay->addWidget(modeRow);

    pathRow_ = new QWidget(card);
    pathRow_->setStyleSheet("background: transparent;");
    QHBoxLayout* pathLay = new QHBoxLayout(pathRow_);
    pathLay->setContentsMargins(0, 0, 0, 0);
    pathLay->setSpacing(Theme::Space::XS);

    customPathLabel_ = new QLabel(pathRow_);
    customPathLabel_->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "font-family: 'Cascadia Mono', 'Consolas', monospace;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_MONO_DIM).arg(Theme::Font::OVERLINE));
    customPathLabel_->setTextFormat(Qt::PlainText);
    pathLay->addWidget(customPathLabel_, 1);
    pathLay->addWidget(browseButton_);
    pathLay->addWidget(browseFileButton_);

    lay->addWidget(pathRow_);

    // ─── Модули ───
    lay->addSpacing(Theme::Space::XXS);
    lay->addWidget(PageHelpers::sectionTitle(TR("MODULES"), card));

    QGridLayout* grid = new QGridLayout;
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setHorizontalSpacing(Theme::Space::XL);
    grid->setVerticalSpacing(Theme::Space::XS);

    const char* kModuleNames[7] = {
        "Registry", "Files", "Processes", "Network", "Scheduled tasks",
        "Scripts", "System persistence"
    };
    for (int i = 0; i < 7; ++i) {
        auto* sw = new ToggleSwitch(card);
        sw->setChecked(AppSettings::Get().ModuleEnabled(i));
        moduleToggles_[i] = sw;
        connect(sw, &ToggleSwitch::toggled, this, [this, i](bool on) {
            AppSettings::Get().SetModuleEnabled(i, on);
            updateScopeSummary();
        });

        QLabel* lbl = new QLabel(TR(kModuleNames[i]), card);
        lbl->setStyleSheet(QString(
            "color: %1; font-size: %2px;"
            "background: transparent; border: none;"
        ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::CONTROL));

        QWidget* cell = new QWidget(card);
        cell->setStyleSheet("background: transparent;");
        QHBoxLayout* cellLay = new QHBoxLayout(cell);
        cellLay->setContentsMargins(0, 0, 0, 0);
        cellLay->setSpacing(Theme::Space::S);
        cellLay->addWidget(sw);
        cellLay->addWidget(lbl);
        cellLay->addStretch();

        grid->addWidget(cell, i / 3, i % 3);
    }
    lay->addLayout(grid);

    scopeSummary_ = new QLabel(card);
    scopeSummary_->setWordWrap(true);
    scopeSummary_->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::CONTROL));
    lay->addWidget(scopeSummary_);

    QLabel* dropHint = new QLabel(
        TR("Drag a file or folder onto the window to check just that."), card);
    dropHint->setWordWrap(true);
    dropHint->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_MUTED).arg(Theme::Font::OVERLINE));
    lay->addWidget(dropHint);

    card->setMinimumHeight(card->sizeHint().height());

    applyMode(static_cast<int>(AppSettings::Get().Mode()));
    return card;
}

void ScanPage::applyMode(int mode) {
    AppSettings::Get().SetMode(static_cast<AppSettings::ScanMode>(mode));

    for (int i = 0; i < 3; ++i) {
        const bool on = (i == mode);
        modeButtons_[i]->setChecked(on);
        // Активный режим заливаем градиентом, остальные оставляем обводкой.
        modeButtons_[i]->setGradient(
            on ? QColor(Theme::ACCENT) : QColor(Theme::BORDER_CONTROL),
            on ? QColor(Theme::ACCENT_GRAD_END) : QColor(Theme::BORDER_CONTROL_HOVER));
    }

    const QString path =
        QString::fromStdWString(AppSettings::Get().CustomPath());
    pathRow_->setVisible(mode == 2);
    customPathLabel_->setText(path.isEmpty() ? TR("Nothing chosen yet") : path);

    updateScopeSummary();
}

void ScanPage::updateScopeSummary() {
    int enabled = 0;
    for (int i = 0; i < 7; ++i) {
        if (moduleToggles_[i] && moduleToggles_[i]->isChecked()) ++enabled;
    }

    QString text;
    switch (AppSettings::Get().Mode()) {
    case AppSettings::ScanMode::Quick:
        text = TR("Quick: the three riskiest folders, shallow depth. "
                  "Takes seconds.");
        break;
    case AppSettings::ScanMode::Custom:
        text = TR("Folder: only the folder you picked, scanned deeply.");
        break;
    default:
        text = TR("Full: every risky folder in the list. Takes the longest.");
        break;
    }

    if (enabled == 0) {
        text = TR("All modules are off — there is nothing to scan.");
    } else if (enabled < 5) {
        text += " " + TR("Modules enabled: %1 of 7.").arg(enabled);
    }

    scopeSummary_->setText(text);
    if (startButton_) startButton_->setEnabled(enabled > 0);
}

void ScanPage::setProgress(int percent, const QString& stage) {
    if (percent != progress_->value()) {
        progressAnim_->stop();
        progressAnim_->setStartValue(progress_->value());
        progressAnim_->setEndValue(percent);
        progressAnim_->start();

        QString cur = percentLabel_->text();
        cur.remove('%');

        percentAnim_->stop();
        percentAnim_->setStartValue(cur.toInt());
        percentAnim_->setEndValue(percent);
        percentAnim_->start();
    }

    if (!stage.isEmpty()) stageLabel_->setText(stage);
}

void ScanPage::setRunning(bool running) {
    startButton_->setVisible(!running);
    cancelButton_->setVisible(running);

    if (running) {
        stageLabel_->setText(TR("Scanning…"));
        countedLabel_->setText("0 " + TR("objects checked"));
        timeLabel_->clear();
        itemLabel_->setText("—");
    } else if (progress_->value() >= 99) {
        stageLabel_->setText(TR("Scan complete"));
    }
}

namespace {

QString formatDuration(int ms) {
    const int total = ms / 1000;
    const int m = total / 60;
    const int sec = total % 60;
    if (m > 0) return QString("%1 %2 %3 %4").arg(m).arg(TR("min"))
                                .arg(sec, 2, 10, QChar('0')).arg(TR("s"));
    return QString("%1 %2").arg(sec).arg(TR("s"));
}

} // namespace

void ScanPage::setDetail(const QString& currentItem, qint64 objectsScanned,
                         int elapsedMs, int etaMs)
{
    // Путь обрезаем по ширине виджета: длинные пути иначе растягивают карточку.
    const QFontMetrics fm(itemLabel_->font());
    itemLabel_->setText(currentItem.isEmpty()
        ? "—"
        : fm.elidedText(currentItem, Qt::ElideMiddle,
                        qMax(120, itemLabel_->width())));
    itemLabel_->setToolTip(currentItem);

    countedLabel_->setText(
        QLocale().toString(objectsScanned) + " " + TR("objects checked"));

    QString t = formatDuration(elapsedMs) + " " + TR("elapsed");
    if (etaMs >= 0) t += " · " + TR("about") + " " + formatDuration(etaMs)
                     + " " + TR("left");
    timeLabel_->setText(t);
}

void ScanPage::setStats(int threats, int critical) {
    threatsValueLabel_->setText(QString::number(threats));
    criticalValueLabel_->setText(QString::number(critical));

    auto paint = [](QLabel* l, const char* color) {
        l->setStyleSheet(QString(
            "color: %1; font-size: %2px; font-weight: 600;"
            "background: transparent; border: none;"
        ).arg(color).arg(Theme::Font::METRIC));
    };

    paint(threatsValueLabel_, threats  > 0 ? Theme::SEV_HIGH : Theme::TEXT_PRIMARY);
    paint(criticalValueLabel_, critical > 0 ? Theme::SEV_CRIT : Theme::TEXT_PRIMARY);
}
