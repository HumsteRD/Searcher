#include "LogsPage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QFrame>
#include <QLabel>
#include <QDateTime>
#include "../ui/GradientButton.h"

LogsPage::LogsPage(QWidget* parent) : QWidget(parent) {
    setStyleSheet("background: transparent;");

    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                             Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    root->setSpacing(12);

    // Заголовок + кнопка Clear (сразу справа, заметная)
    QWidget* titleRow = new QWidget(this);
    titleRow->setStyleSheet("background: transparent;");
    QHBoxLayout* titleLay = new QHBoxLayout(titleRow);
    titleLay->setContentsMargins(0, 0, 0, 0);
    titleLay->setSpacing(12);
    titleLay->setAlignment(Qt::AlignVCenter);

    titleLay->addWidget(PageHelpers::pageTitle(TR("Logs"), this));
    titleLay->addStretch();

    auto* clearBtn = new GradientButton(TR("Clear log"),
        GradientButton::Style::Outline, titleRow);
    clearBtn->setFixedHeight(Theme::Size::BTN_HEADER);
    clearBtn->setMinimumWidth(130);
    clearBtn->setGradient(QColor(Theme::SEV_HIGH), QColor(Theme::SEV_CRIT));
    connect(clearBtn, &QPushButton::clicked, this, &LogsPage::clear);
    titleLay->addWidget(clearBtn);

    root->addWidget(titleRow);

    root->addWidget(PageHelpers::pageSubtitle(
        TR("Detailed information about scans, modules and detected events."), this));

    root->addSpacing(12);

    // Сам лог
    QFrame* card = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* cardLay = new QVBoxLayout(card);
    cardLay->setContentsMargins(2, 2, 2, 2);

    logArea_ = new QPlainTextEdit(card);
    logArea_->setReadOnly(true);
    logArea_->setLineWrapMode(QPlainTextEdit::NoWrap);
    logArea_->setStyleSheet(QString(
        "QPlainTextEdit {"
        "  background-color: %2;"
        "  color: %1;"
        "  border: none;"
        "  font-family: 'Cascadia Mono', 'Consolas', monospace;"
        "  font-size: 13px;"
        "  padding: 16px;"
        "  selection-background-color: rgba(124,131,245,80);"
        "}"
    ).arg(Theme::TEXT_MONO, Theme::CONSOLE));
    cardLay->addWidget(logArea_);

    root->addWidget(card, 1);

    appendLine("Application started", "INF");
    appendLine("UI initialized", "INF");
    appendLine("Waiting for scan to begin...", "INF");
}

void LogsPage::appendLine(const QString& line, const QString& level) {
    // Цветной бейдж уровня + время
    QString badgeBg, badgeColor;
    if      (level == "ERR") { badgeBg = Theme::SEV_CRIT_BG; badgeColor = Theme::SEV_CRIT; }
    else if (level == "WRN") { badgeBg = Theme::SEV_MED_BG; badgeColor = Theme::SEV_MED; }
    else if (level == "DBG") { badgeBg = Theme::SEV_INFO_BG; badgeColor = Theme::SEV_INFO; }
    else                     { badgeBg = Theme::SEV_LOW_BG; badgeColor = Theme::SEV_LOW; }

    QString time = QDateTime::currentDateTime().toString("HH:mm:ss");

    // HTML с цветным бейджем
    QString html = QString(
        "<span style='color:%1;'>%2</span>  "
        "<span style='background-color:%3; color:%4; padding:0px 6px; "
        "border-radius:4px; font-weight:700;'>%5</span>  "
        "<span style='color:%6;'>%7</span>"
    ).arg(
        Theme::TEXT_MONO_DIM,
        time,
        badgeBg,
        badgeColor,
        level,
        Theme::TEXT_MONO,
        line.toHtmlEscaped()
    );

    logArea_->appendHtml(html);
}

void LogsPage::clear() {
    logArea_->clear();
}
