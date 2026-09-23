#include "PageHelpers.h"
#include "../theme.h"

#include <QLabel>
#include <QFrame>
#include <QPushButton>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QGraphicsDropShadowEffect>
#include <QFont>
#include <QFontMetrics>

namespace PageHelpers {

namespace {

QString labelQss(const char* color, int size, int weight) {
    return QString(
        "color: %1; font-size: %2px; font-weight: %3;"
        "background: transparent; border: none;"
    ).arg(color).arg(size).arg(weight);
}

} // namespace

void setTracking(QWidget* w, qreal px) {
    QFont f = w->font();
    f.setLetterSpacing(QFont::AbsoluteSpacing, px);
    w->setFont(f);
}

QLabel* sectionTitle(const QString& text, QWidget* parent) {
    QLabel* l = new QLabel(text, parent);
    l->setStyleSheet(labelQss(Theme::TEXT_MUTED, Theme::Font::OVERLINE, 600));
    setTracking(l, Theme::Font::TRACK_OVERLINE);
    return l;
}

QLabel* pageTitle(const QString& text, QWidget* parent) {
    QLabel* l = new QLabel(text, parent);
    l->setStyleSheet(labelQss(Theme::TEXT_PRIMARY, Theme::Font::TITLE, 600));
    setTracking(l, -0.1);
    return l;
}

QLabel* pageSubtitle(const QString& text, QWidget* parent) {
    QLabel* l = new QLabel(text, parent);
    l->setStyleSheet(labelQss(Theme::TEXT_SECONDARY, Theme::Font::CONTROL, 400));
    l->setWordWrap(true);
    return l;
}

QFrame* card(QWidget* parent, int radius) {
    QFrame* f = new QFrame(parent);
    f->setStyleSheet(QString(
        "QFrame {"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: %3px;"
        "}"
    ).arg(Theme::CARD, Theme::BORDER_CARD).arg(radius));
    return f;
}

QVBoxLayout* pageLayout(QWidget* page) {
    page->setStyleSheet("background: transparent;");
    QVBoxLayout* root = new QVBoxLayout(page);
    root->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                             Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    root->setSpacing(Theme::Space::M);
    return root;
}

QVBoxLayout* scrollablePageLayout(QWidget* page) {
    page->setStyleSheet("background: transparent;");

    QVBoxLayout* outer = new QVBoxLayout(page);
    outer->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                              Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    outer->setSpacing(0);

    QScrollArea* scroll = new QScrollArea(page);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background: transparent;");
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    QWidget* content = new QWidget(scroll);
    content->setStyleSheet("background: transparent;");
    scroll->setWidget(content);
    outer->addWidget(scroll, 1);

    QVBoxLayout* inner = new QVBoxLayout(content);
    inner->setContentsMargins(0, 0, Theme::Space::S, 0);
    inner->setSpacing(Theme::Space::M);
    return inner;
}

QPushButton* button(const QString& text, BtnStyle style, QWidget* parent) {
    QPushButton* b = new QPushButton(text, parent);
    b->setCursor(Qt::PointingHandCursor);

    QString qss;

    switch (style) {
    case BtnStyle::Primary:
        b->setFixedHeight(Theme::Size::BTN_HERO);
        // Прозрачная граница в 1px: при фокусе она лишь перекрашивается,
        // поэтому вёрстка не сдвигается ни на пиксель.
        qss = QString(
            "QPushButton {"
            "  background-color: %1; color: #FFFFFF;"
            "  border: 1px solid transparent; border-radius: %4px;"
            "  padding: 0 20px; font-size: %5px; font-weight: 600;"
            "}"
            "QPushButton:hover   { background-color: %2; }"
            "QPushButton:pressed { background-color: %3; }"
            "QPushButton:disabled { background-color: #1A2140; border-color: %6; color: %7; }"
            "QPushButton:focus   { border-color: %8; }"
        ).arg(Theme::ACCENT, Theme::ACCENT_HOVER, Theme::ACCENT_PRESSED)
         .arg(Theme::Radius::CONTROL)
         .arg(Theme::Font::CONTROL)
         .arg(Theme::BORDER_DISABLED, Theme::TEXT_DISABLED, Theme::FOCUS);
        applyPrimaryButtonShadow(b);
        break;

    case BtnStyle::Secondary:
        b->setFixedHeight(Theme::Size::BTN_HEADER);
        qss = QString(
            "QPushButton {"
            "  background-color: transparent; color: %1;"
            "  border: 1px solid %2; border-radius: %3px;"
            "  padding: 0 16px; font-size: %4px; font-weight: 600;"
            "}"
            "QPushButton:hover   { border-color: %5; color: %6; }"
            "QPushButton:pressed { background-color: %7; }"
            "QPushButton:disabled { border-color: %8; color: %9; background-color: %10; }"
            "QPushButton:focus   { border-color: %11; }"
        ).arg(Theme::TEXT_SECONDARY, Theme::BORDER_CONTROL)
         .arg(Theme::Radius::CONTROL)
         .arg(Theme::Font::CONTROL)
         .arg(Theme::BORDER_CONTROL_HOVER, Theme::TEXT_PRIMARY, Theme::ROW_HOVER,
              Theme::BORDER_DISABLED, Theme::TEXT_DISABLED, Theme::FILL_DISABLED,
              Theme::FOCUS);
        break;

    case BtnStyle::Danger:
        b->setFixedHeight(Theme::Size::BTN_HEADER);
        qss = QString(
            "QPushButton {"
            "  background-color: transparent; color: %1;"
            "  border: 1px solid %2; border-radius: %3px;"
            "  padding: 0 16px; font-size: %4px; font-weight: 600;"
            "}"
            "QPushButton:hover   { background-color: %5; }"
            "QPushButton:pressed { background-color: %2; color: #FFFFFF; }"
            "QPushButton:disabled { border-color: %6; color: %7; }"
            "QPushButton:focus   { border-color: %8; }"
        ).arg(Theme::SEV_CRIT, Theme::SEV_CRIT_BORDER)
         .arg(Theme::Radius::CONTROL)
         .arg(Theme::Font::CONTROL)
         .arg(Theme::SEV_CRIT_BG, Theme::BORDER_DISABLED, Theme::TEXT_DISABLED,
              Theme::FOCUS);
        break;

    case BtnStyle::Row:
        b->setFixedHeight(Theme::Size::BTN_ROW);
        qss = QString(
            "QPushButton {"
            "  background-color: transparent; color: %1;"
            "  border: 1px solid %2; border-radius: %3px;"
            "  padding: 0 10px; font-size: %4px; font-weight: 600;"
            "}"
            "QPushButton:hover   { border-color: %5; color: %6; }"
            "QPushButton:pressed { background-color: %7; }"
            "QPushButton:disabled { border-color: %8; color: %9; }"
            "QPushButton:focus   { border-color: %10; }"
        ).arg(Theme::TEXT_SECONDARY, Theme::BORDER_CONTROL)
         .arg(Theme::Radius::PILL)
         .arg(Theme::Font::OVERLINE)
         .arg(Theme::BORDER_CONTROL_HOVER, Theme::TEXT_PRIMARY, Theme::ROW_HOVER,
              Theme::BORDER_DISABLED, Theme::TEXT_DISABLED, Theme::FOCUS);
        break;
    }

    b->setStyleSheet(qss);
    return b;
}

SeverityColors severityColors(const QString& severity) {
    if (severity == "CRIT")
        return { Theme::SEV_CRIT, Theme::SEV_CRIT_BG, Theme::SEV_CRIT_BORDER };
    if (severity == "HIGH")
        return { Theme::SEV_HIGH, Theme::SEV_HIGH_BG, Theme::SEV_HIGH_BORDER };
    if (severity == "MED")
        return { Theme::SEV_MED,  Theme::SEV_MED_BG,  Theme::SEV_MED_BORDER };
    if (severity == "LOW")
        return { Theme::SEV_LOW,  Theme::SEV_LOW_BG,  Theme::SEV_LOW_BORDER };
    return { Theme::SEV_INFO, Theme::SEV_INFO_BG, Theme::SEV_INFO_BORDER };
}

QLabel* severityPill(const QString& severity, QWidget* parent) {
    const SeverityColors c = severityColors(severity);

    QLabel* pill = new QLabel(severity, parent);
    pill->setAlignment(Qt::AlignCenter);
    pill->setFixedHeight(Theme::Size::PILL);
    pill->setStyleSheet(QString(
        "background-color: %1; color: %2;"
        "border: 1px solid %3; border-radius: %4px;"
        "padding: 0 8px; font-size: %5px; font-weight: 600;"
    ).arg(c.bg, c.fg, c.border)
     .arg(Theme::Radius::PILL)
     .arg(Theme::Font::OVERLINE));
    setTracking(pill, Theme::Font::TRACK_PILL);

    // Ширину задаём сами. Своей подсказке размера здесь верить нельзя:
    // она считается до применения стиля и трекинга, и «HIGH» обрезалось
    // с обеих сторон, превращаясь на экране в «IGI».
    QFont measured = pill->font();
    measured.setWeight(QFont::DemiBold);
    measured.setPixelSize(Theme::Font::OVERLINE);
    pill->setMinimumWidth(
        QFontMetrics(measured).horizontalAdvance(severity) + 24);
    return pill;
}

// ─── Тени: в приложении их ровно три ────────────────────────────────────

void applyHeroShadow(QWidget* w) {
    auto* e = new QGraphicsDropShadowEffect(w);
    e->setColor(QColor(5, 7, 15, 140));
    e->setBlurRadius(32);
    e->setOffset(0, 8);
    w->setGraphicsEffect(e);
}

void applyPrimaryButtonShadow(QWidget* w) {
    auto* e = new QGraphicsDropShadowEffect(w);
    e->setColor(QColor(11, 27, 71, 120));
    e->setBlurRadius(14);
    e->setOffset(0, 3);
    w->setGraphicsEffect(e);
}

void applyModalShadow(QWidget* w) {
    auto* e = new QGraphicsDropShadowEffect(w);
    e->setColor(QColor(4, 6, 13, 190));
    e->setBlurRadius(48);
    e->setOffset(0, 16);
    w->setGraphicsEffect(e);
}

} // namespace PageHelpers
