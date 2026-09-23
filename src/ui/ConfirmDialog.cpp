#include "ConfirmDialog.h"
#include "GradientButton.h"
#include "../theme.h"
#include "../core/Lang.h"
#include "../pages/PageHelpers.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFrame>
#include <QPainter>
#include <QPropertyAnimation>
#include <QShowEvent>

namespace {
constexpr int kCardWidth = 440;
}

ConfirmDialog::ConfirmDialog(QWidget* parent, const QString& title,
                             const QString& text, const QString& confirmLabel,
                             bool irreversible)
    : QDialog(parent)
{
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setModal(true);

    // Подложка на всё окно-родитель, поверх неё — карточка по центру.
    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setAlignment(Qt::AlignCenter);

    card_ = PageHelpers::card(this, Theme::Radius::HERO);
    card_->setFixedWidth(kCardWidth);
    PageHelpers::applyModalShadow(card_);
    outer->addWidget(card_);

    QVBoxLayout* lay = new QVBoxLayout(card_);
    lay->setContentsMargins(Theme::Space::XXL, Theme::Space::XL,
                            Theme::Space::XXL, Theme::Space::XL);
    lay->setSpacing(Theme::Space::S);

    QLabel* t = new QLabel(title, card_);
    t->setWordWrap(true);
    t->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::CARD));
    lay->addWidget(t);

    QLabel* b = new QLabel(text, card_);
    b->setWordWrap(true);
    b->setTextFormat(Qt::PlainText);
    b->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::BODY));
    lay->addWidget(b);

    if (irreversible) {
        QLabel* warn = new QLabel(TR("This cannot be undone"), card_);
        warn->setStyleSheet(QString(
            "background-color: %1; color: %2;"
            "border: 1px solid %3; border-radius: %4px;"
            "padding: 8px 12px; font-size: %5px; font-weight: 600;"
        ).arg(Theme::SEV_CRIT_BG, Theme::SEV_CRIT, Theme::SEV_CRIT_BORDER)
         .arg(Theme::Radius::CONTROL)
         .arg(Theme::Font::CONTROL));
        lay->addWidget(warn);
    }

    lay->addSpacing(Theme::Space::XS);

    QWidget* buttons = new QWidget(card_);
    buttons->setStyleSheet("background: transparent;");
    QHBoxLayout* btnLay = new QHBoxLayout(buttons);
    btnLay->setContentsMargins(0, 0, 0, 0);
    btnLay->setSpacing(Theme::Space::S);
    btnLay->addStretch();

    auto* cancel = new GradientButton(TR("Cancel"),
                                      GradientButton::Style::Outline, buttons);
    cancel->setFixedHeight(Theme::Size::BTN_HERO);
    cancel->setMinimumWidth(120);
    cancel->setGradient(QColor(Theme::BORDER_CONTROL),
                        QColor(Theme::BORDER_CONTROL_HOVER));
    connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
    btnLay->addWidget(cancel);

    auto* confirm = new GradientButton(confirmLabel,
                                       GradientButton::Style::Filled, buttons);
    confirm->setFixedHeight(Theme::Size::BTN_HERO);
    confirm->setMinimumWidth(160);
    confirm->setGradient(
        irreversible ? QColor(Theme::SEV_HIGH) : QColor(Theme::ACCENT),
        irreversible ? QColor(Theme::SEV_CRIT) : QColor(Theme::ACCENT_GRAD_END));
    connect(confirm, &QPushButton::clicked, this, &QDialog::accept);
    btnLay->addWidget(confirm);

    lay->addWidget(buttons);

    // Enter не должен разрушать файл: фокус остаётся на отмене.
    cancel->setDefault(true);
    cancel->setFocus();
}

void ConfirmDialog::showEvent(QShowEvent* event) {
    QDialog::showEvent(event);

    // Карточка появляется от 92% к 100% — единственная анимация окна.
    const QRect target = card_->geometry();
    QRect from = target;
    from.setSize(target.size() * 0.92);
    from.moveCenter(target.center());

    auto* anim = new QPropertyAnimation(card_, "geometry", this);
    anim->setDuration(180);
    anim->setEasingCurve(QEasingCurve::OutBack);
    anim->setStartValue(from);
    anim->setEndValue(target);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void ConfirmDialog::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.fillRect(rect(), QColor(6, 8, 15, 184));   // затемнение фона
}

bool ConfirmDialog::ask(QWidget* parent, const QString& title,
                        const QString& text, const QString& confirmLabel,
                        bool irreversible)
{
    ConfirmDialog dlg(parent, title, text, confirmLabel, irreversible);

    // Растягиваем на всё окно приложения, чтобы затемнение накрыло его целиком.
    if (QWidget* top = parent ? parent->window() : nullptr) {
        dlg.setGeometry(QRect(top->mapToGlobal(QPoint(0, 0)), top->size()));
    }
    return dlg.exec() == QDialog::Accepted;
}
