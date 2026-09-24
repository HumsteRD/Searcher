#include "Theme.h"

#include <QApplication>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QPalette>
#include <QSettings>
#include <QStyleHints>

#include <map>

namespace Ui {
namespace {

struct ColorEntry { const char* name; const char* hex; };

// palette:Light
const ColorEntry kLight[] = {
    { "window", "#F3F4F6" }, { "sidebar", "#F9FAFB" }, { "surface", "#FFFFFF" },
    { "surfaceAlt", "#F7F8FA" }, { "raised", "#FFFFFF" }, { "hover", "#EDEFF2" },
    { "pressed", "#E3E6EA" }, { "input", "#FFFFFF" }, { "border", "#E1E4E8" },
    { "borderStrong", "#C3C8D0" }, { "focus", "#2563EB" },
    { "text", "#15171B" }, { "text2", "#4B5260" }, { "text3", "#616875" },
    { "textDisabled", "#A2A8B1" }, { "textOnAccent", "#FFFFFF" },
    { "accent", "#2563EB" }, { "accentHover", "#1E55D6" }, { "accentPressed", "#1A48BA" },
    { "accentText", "#1D4ED8" }, { "accentSoft", "#EAF1FE" },
    { "ok", "#16A34A" }, { "okText", "#127336" }, { "okSoft", "#E6F5EB" },
    { "warn", "#D97706" }, { "warnText", "#975A06" }, { "warnSoft", "#FCF3E0" },
    { "high", "#EA580C" }, { "highText", "#B93F0B" }, { "highSoft", "#FDEDE3" },
    { "danger", "#DC2626" }, { "dangerText", "#B91C1C" }, { "dangerSoft", "#FCEBEB" },
    { "dangerHover", "#C21F1F" },
    { "low", "#4B6BB5" }, { "lowText", "#3A5696" }, { "lowSoft", "#ECF0F9" },
    { "infoSoft", "#EFF1F4" },
    { "scrollThumb", "#C9CED5" }, { "scrollThumbHover", "#A9B0BA" },
    { "rowHover", "#F4F6F9" }, { "rowSelected", "#E8F0FE" },
};
// end

// palette:Dark
const ColorEntry kDark[] = {
    { "window", "#0F1115" }, { "sidebar", "#13161B" }, { "surface", "#181B21" },
    { "surfaceAlt", "#1C2027" }, { "raised", "#21252D" }, { "hover", "#242931" },
    { "pressed", "#2B3039" }, { "input", "#13161B" }, { "border", "#272C35" },
    { "borderStrong", "#3A414C" }, { "focus", "#6EA1FF" },
    { "text", "#E8EAEE" }, { "text2", "#AAB0BB" }, { "text3", "#8A919D" },
    { "textDisabled", "#545B67" }, { "textOnAccent", "#FFFFFF" },
    { "accent", "#2F6FEB" }, { "accentHover", "#3D7BF2" }, { "accentPressed", "#2860D2" },
    { "accentText", "#80AAFF" }, { "accentSoft", "#1A2640" },
    { "ok", "#2FB872" }, { "okText", "#5AD394" }, { "okSoft", "#13281E" },
    { "warn", "#E3A02A" }, { "warnText", "#EFBD5C" }, { "warnSoft", "#2C2413" },
    { "high", "#F07A3A" }, { "highText", "#FF9D68" }, { "highSoft", "#321E13" },
    { "danger", "#D93A40" }, { "dangerText", "#FF8286" }, { "dangerSoft", "#33171A" },
    { "dangerHover", "#E54A50" },
    { "low", "#7F9CDB" }, { "lowText", "#A6BCEB" }, { "lowSoft", "#1B2336" },
    { "infoSoft", "#21252C" },
    { "scrollThumb", "#363C46" }, { "scrollThumbHover", "#4A515D" },
    { "rowHover", "#1D2128" }, { "rowSelected", "#1C2A44" },
};
// end

// palette:Graphite
const ColorEntry kGraphite[] = {
    { "window", "#2A2C30" }, { "sidebar", "#25272A" }, { "surface", "#323438" },
    { "surfaceAlt", "#36383D" }, { "raised", "#3B3E43" }, { "hover", "#3D4045" },
    { "pressed", "#45484E" }, { "input", "#2A2C30" }, { "border", "#44474D" },
    { "borderStrong", "#5A5E66" }, { "focus", "#8AB4FF" },
    { "text", "#F1F2F4" }, { "text2", "#C5C9CF" }, { "text3", "#A7ABB3" },
    { "textDisabled", "#6B6F76" }, { "textOnAccent", "#FFFFFF" },
    { "accent", "#2F6CE0" }, { "accentHover", "#3B78EA" }, { "accentPressed", "#285FC8" },
    { "accentText", "#9DBEFF" }, { "accentSoft", "#303B51" },
    { "ok", "#34B874" }, { "okText", "#72D9A2" }, { "okSoft", "#2C3A33" },
    { "warn", "#E0A43A" }, { "warnText", "#F2C872" }, { "warnSoft", "#3D3728" },
    { "high", "#EE8446" }, { "highText", "#FFB083" }, { "highSoft", "#433429" },
    { "danger", "#D63C42" }, { "dangerText", "#FF9699" }, { "dangerSoft", "#482A2D" },
    { "dangerHover", "#E24C52" },
    { "low", "#8EA7DE" }, { "lowText", "#B5C7EE" }, { "lowSoft", "#33394A" },
    { "infoSoft", "#3A3D42" },
    { "scrollThumb", "#575B62" }, { "scrollThumbHover", "#6C7078" },
    { "rowHover", "#393C41" }, { "rowSelected", "#344262" },
};
// end

template <size_t N>
Palette Build(const ColorEntry (&entries)[N], bool dark) {
    std::map<std::string, QColor> m;
    for (const auto& e : entries) m[e.name] = QColor(e.hex);
    Palette p;
    p.dark = dark;
#define SET(field) p.field = m[#field]
    SET(window); SET(sidebar); SET(surface); SET(surfaceAlt); SET(raised); SET(hover);
    SET(pressed); SET(input); SET(border); SET(borderStrong); SET(focus);
    SET(text); SET(text2); SET(text3); SET(textDisabled); SET(textOnAccent);
    SET(accent); SET(accentHover); SET(accentPressed); SET(accentText); SET(accentSoft);
    SET(ok); SET(okText); SET(okSoft); SET(warn); SET(warnText); SET(warnSoft);
    SET(high); SET(highText); SET(highSoft); SET(danger); SET(dangerText); SET(dangerSoft);
    SET(dangerHover); SET(low); SET(lowText); SET(lowSoft); SET(infoSoft);
    SET(scrollThumb); SET(scrollThumbHover); SET(rowHover); SET(rowSelected);
#undef SET
    return p;
}

bool SystemIsDark() {
    return QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark;
}

QString Hex(const QColor& c) { return c.name(QColor::HexRgb); }

QString Rgba(const QColor& c, double alpha) {
    return QString("rgba(%1,%2,%3,%4)").arg(c.red()).arg(c.green()).arg(c.blue()).arg(alpha, 0, 'f', 3);
}

} // namespace

namespace Font {

QString family() {
    static const QString f = [] {
        const QStringList all = QFontDatabase::families();
        // Segoe UI Variable Text создан для 12–16 px; Display для таких
        // размеров слишком тонкий и именно он давал «мыльный» текст.
        for (const char* name : { "Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI" })
            if (all.contains(name)) return QString(name);
        return QString("Segoe UI");
    }();
    return f;
}

QString monoFamily() {
    static const QString f = [] {
        const QStringList all = QFontDatabase::families();
        for (const char* name : { "Cascadia Mono", "Consolas" })
            if (all.contains(name)) return QString(name);
        return QString("Consolas");
    }();
    return f;
}

QFont make(int pixelSize, int weight) {
    QFont f(family());
    f.setPixelSize(pixelSize);
    f.setWeight(static_cast<QFont::Weight>(weight));
    f.setHintingPreference(QFont::PreferDefaultHinting);
    return f;
}

QFont mono(int pixelSize) {
    QFont f(monoFamily());
    f.setPixelSize(pixelSize);
    f.setStyleHint(QFont::Monospace);
    f.setHintingPreference(QFont::PreferDefaultHinting);
    return f;
}

} // namespace Font

Theme& Theme::instance() {
    static Theme* t = new Theme();
    return *t;
}

Theme::Theme() {
    QSettings s("ThreatScanner", "ThreatScanner");
    const int stored = s.value("ui/theme", static_cast<int>(Id::System)).toInt();
    id_ = static_cast<Id>(std::clamp(stored, 0, 3));
    apply();
    connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, this,
            [this]() { onSystemThemeChanged(); });
}

Theme::Id Theme::effective() const {
    if (id_ != Id::System) return id_;
    return SystemIsDark() ? Id::Dark : Id::Light;
}

void Theme::setId(Id id) {
    if (id == id_) return;
    id_ = id;
    QSettings s("ThreatScanner", "ThreatScanner");
    s.setValue("ui/theme", static_cast<int>(id));
    apply();
}

void Theme::onSystemThemeChanged() {
    if (id_ == Id::System) apply();
}

Palette Theme::paletteFor(Id id) {
    if (id == Id::System) id = SystemIsDark() ? Id::Dark : Id::Light;
    switch (id) {
    case Id::Dark:     return Build(kDark, true);
    case Id::Graphite: return Build(kGraphite, true);
    default:           return Build(kLight, false);
    }
}

void Theme::apply() {
    palette_ = paletteFor(effective());

    if (qApp) {
        // Палитра Qt — для того, что таблица стилей не покрывает:
        // системные диалоги, подсказки, выделение текста.
        QPalette qp;
        const Palette& p = palette_;
        qp.setColor(QPalette::Window, p.window);
        qp.setColor(QPalette::WindowText, p.text);
        qp.setColor(QPalette::Base, p.input);
        qp.setColor(QPalette::AlternateBase, p.surfaceAlt);
        qp.setColor(QPalette::Text, p.text);
        qp.setColor(QPalette::PlaceholderText, p.text3);
        qp.setColor(QPalette::Button, p.surface);
        qp.setColor(QPalette::ButtonText, p.text);
        qp.setColor(QPalette::BrightText, p.textOnAccent);
        qp.setColor(QPalette::Highlight, p.accent);
        qp.setColor(QPalette::HighlightedText, p.textOnAccent);
        qp.setColor(QPalette::ToolTipBase, p.raised);
        qp.setColor(QPalette::ToolTipText, p.text);
        qp.setColor(QPalette::Link, p.accentText);
        qp.setColor(QPalette::LinkVisited, p.accentText);
        qp.setColor(QPalette::Mid, p.border);
        qp.setColor(QPalette::Dark, p.borderStrong);
        qp.setColor(QPalette::Disabled, QPalette::Text, p.textDisabled);
        qp.setColor(QPalette::Disabled, QPalette::WindowText, p.textDisabled);
        qp.setColor(QPalette::Disabled, QPalette::ButtonText, p.textDisabled);
        QApplication::setPalette(qp);
        qApp->setStyleSheet(styleSheet());
    }
    emit changed();
}

Tone Theme::tone(const QString& code) const {
    const Palette& p = palette_;
    if (code == "CRIT") return { p.dangerText, p.dangerSoft, p.danger };
    if (code == "HIGH") return { p.highText, p.highSoft, p.high };
    if (code == "MED")  return { p.warnText, p.warnSoft, p.warn };
    if (code == "LOW")  return { p.lowText, p.lowSoft, p.low };
    if (code == "OK")   return { p.okText, p.okSoft, p.ok };
    if (code == "ACCENT") return { p.accentText, p.accentSoft, p.accent };
    return { p.text2, p.infoSoft, p.text3 };
}

QString Theme::styleSheet() const {
    const Palette& p = palette_;
    QString s = QStringLiteral(R"QSS(
* { outline: none; }
QWidget {
    font-family: "@font@";
    font-size: 14px;
    color: @text@;
}
QMainWindow, #root { background: @window@; }
QWidget#page, QWidget#pageBody, QScrollArea#pageScroll, QScrollArea#pageScroll > QWidget > QWidget {
    background: transparent;
}
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget#qt_scrollarea_viewport { background: transparent; }

/* ─── Боковая панель и заголовок окна ─── */
#titleBar { background: @sidebar@; border-bottom: 1px solid @border@; }
#sidebar { background: @sidebar@; border-right: 1px solid @border@; }
#titleBar QLabel#appName { font-size: 13px; font-weight: 600; color: @text@; }

/* ─── Карточки ─── */
QFrame#card, QFrame[card="true"] {
    background: @surface@;
    border: 1px solid @border@;
    border-radius: 12px;
}
QFrame#card[card="hover"] { border-color: @borderStrong@; background: @surfaceAlt@; }
QFrame[card="alt"] {
    background: @surfaceAlt@;
    border: 1px solid @border@;
    border-radius: 10px;
}
QFrame#choice { background: @surface@; border: 1px solid @border@; border-radius: 12px; }
QFrame#choice[hover="true"] { border-color: @borderStrong@; }
QFrame#choice[selected="true"] { border: 1px solid @accent@; background: @accentSoft@; }
QFrame[divider="true"] { background: @border@; border: none; min-height: 1px; max-height: 1px; }

/* ─── Текст ─── */
QLabel { background: transparent; }
QLabel[role="title"]   { font-size: 22px; font-weight: 600; color: @text@; }
QLabel[role="hero"]    { font-size: 20px; font-weight: 600; color: @text@; }
QLabel[role="heading"] { font-size: 16px; font-weight: 600; color: @text@; }
QLabel[role="subheading"] { font-size: 14px; font-weight: 600; color: @text@; }
QLabel[role="body"]    { font-size: 14px; color: @text@; }
QLabel[role="muted"]   { font-size: 13px; color: @text2@; }
QLabel[role="caption"] { font-size: 12px; color: @text3@; }
QLabel[role="label"]   { font-size: 12px; font-weight: 600; color: @text3@; }
QLabel[role="metric"]  { font-size: 28px; font-weight: 600; color: @text@; }
QLabel[role="mono"]    { font-family: "@mono@"; font-size: 12px; color: @text2@; }
QLabel[role="link"]    { color: @accentText@; }
QLabel[tone="danger"]  { color: @dangerText@; }
QLabel[tone="ok"]      { color: @okText@; }
QLabel[tone="warn"]    { color: @warnText@; }
QLabel[tone="accent"]  { color: @accentText@; }

/* ─── Кнопки ─── */
QPushButton {
    min-height: 34px;
    padding: 0 14px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    border: 1px solid @borderStrong@;
    background: @surface@;
    color: @text@;
}
QPushButton:hover   { background: @hover@; }
QPushButton:pressed { background: @pressed@; }
QPushButton:disabled { color: @textDisabled@; border-color: @border@; background: @surface@; }
QPushButton:focus { border-color: @focus@; }
QPushButton[variant="primary"] {
    background: @accent@; border: 1px solid @accent@; color: @textOnAccent@;
}
QPushButton[variant="primary"]:hover   { background: @accentHover@; border-color: @accentHover@; }
QPushButton[variant="primary"]:pressed { background: @accentPressed@; border-color: @accentPressed@; }
QPushButton[variant="primary"]:disabled { background: @hover@; border-color: @border@; color: @textDisabled@; }
QPushButton[variant="danger"] {
    background: @danger@; border: 1px solid @danger@; color: @textOnAccent@;
}
QPushButton[variant="danger"]:hover { background: @dangerHover@; border-color: @dangerHover@; }
QPushButton[variant="danger"]:disabled { background: @hover@; border-color: @border@; color: @textDisabled@; }
QPushButton[variant="ghost"] { background: transparent; border: 1px solid transparent; color: @text2@; }
QPushButton[variant="ghost"]:hover { background: @hover@; color: @text@; }
QPushButton[variant="ghost"]:pressed { background: @pressed@; }
QPushButton[variant="link"] {
    background: transparent; border: none; color: @accentText@; padding: 0; min-height: 0;
    font-weight: 600;
}
QPushButton[variant="link"]:hover { text-decoration: underline; }
QPushButton[size="small"] { min-height: 28px; padding: 0 10px; font-size: 12px; border-radius: 6px; }
QPushButton[size="large"] { min-height: 40px; padding: 0 20px; font-size: 14px; }

QToolButton {
    background: transparent; border: none; border-radius: 6px; padding: 4px; color: @text2@;
}
QToolButton:hover { background: @hover@; color: @text@; }
QToolButton:pressed { background: @pressed@; }

/* ─── Поля ввода ─── */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QComboBox, QTimeEdit {
    background: @input@;
    border: 1px solid @borderStrong@;
    border-radius: 8px;
    padding: 6px 10px;
    min-height: 20px;
    color: @text@;
    selection-background-color: @accent@;
    selection-color: @textOnAccent@;
}
QPlainTextEdit, QTextEdit { padding: 8px; }
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus, QTimeEdit:focus {
    border-color: @focus@;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled { color: @textDisabled@; border-color: @border@; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox::down-arrow { image: none; width: 0; height: 0; }
QComboBox QAbstractItemView {
    background: @raised@; border: 1px solid @border@; border-radius: 8px; padding: 4px;
    selection-background-color: @rowSelected@; selection-color: @text@; outline: none;
}
QSpinBox::up-button, QSpinBox::down-button, QTimeEdit::up-button, QTimeEdit::down-button { width: 0; border: none; }

QTextBrowser { background: transparent; border: none; color: @text@; }

/* ─── Флажки ─── */
QCheckBox { spacing: 10px; color: @text@; font-size: 14px; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 5px;
    border: 1px solid @borderStrong@; background: @input@;
}
QCheckBox::indicator:hover { border-color: @accent@; }
QCheckBox::indicator:checked { background: @accent@; border-color: @accent@; image: url(:/ui/check.svg); }
QCheckBox:disabled { color: @textDisabled@; }

/* ─── Списки и таблицы ─── */
QTableView, QTreeView, QListView {
    background: @surface@;
    border: none;
    gridline-color: transparent;
    selection-background-color: @rowSelected@;
    selection-color: @text@;
    alternate-background-color: @surfaceAlt@;
    font-size: 13px;
}
QTableView::item, QTreeView::item { padding: 0 8px; border-bottom: 1px solid @border@; }
QTableView::item:hover, QTreeView::item:hover { background: @rowHover@; }
QTableView::item:selected, QTreeView::item:selected { background: @rowSelected@; color: @text@; }
QHeaderView { background: @surface@; border: none; }
QHeaderView::section {
    background: @surface@; color: @text3@; border: none; border-bottom: 1px solid @border@;
    padding: 0 8px; height: 36px; font-size: 12px; font-weight: 600;
}
/* Списки в карточках — с рамкой. После общего правила QListView: при
   равной специфичности побеждает то, что ниже. */
QListWidget {
    background: @input@; border: 1px solid @border@; border-radius: 8px; padding: 4px;
}
QListWidget::item { padding: 6px 8px; border-radius: 6px; border: none; color: @text@; }
QListWidget::item:hover { background: @rowHover@; }
QListWidget::item:selected { background: @rowSelected@; color: @text@; }
QListWidget::item:disabled { color: @text3@; }

/* ─── Прокрутка ─── */
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px; }
QScrollBar::handle:vertical { background: @scrollThumb@; border-radius: 4px; min-height: 32px; margin: 0 2px; }
QScrollBar::handle:vertical:hover { background: @scrollThumbHover@; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px; }
QScrollBar::handle:horizontal { background: @scrollThumb@; border-radius: 4px; min-width: 32px; margin: 2px 0; }
QScrollBar::handle:horizontal:hover { background: @scrollThumbHover@; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ─── Меню и подсказки ─── */
QMenu {
    background: @raised@; border: 1px solid @border@; border-radius: 10px; padding: 6px;
}
QMenu::item { padding: 8px 24px 8px 12px; border-radius: 6px; color: @text@; font-size: 13px; }
QMenu::item:selected { background: @hover@; }
QMenu::item:disabled { color: @textDisabled@; }
QMenu::separator { height: 1px; background: @border@; margin: 4px 8px; }
QToolTip {
    background: @raised@; color: @text@; border: 1px solid @border@;
    padding: 6px 10px; border-radius: 6px; font-size: 12px;
}

/* ─── Модальные окна ─── */
QFrame#modal {
    background: @raised@; border: 1px solid @borderStrong@; border-radius: 12px;
}
QMessageBox, QDialog { background: @window@; }
)QSS");

    const std::pair<const char*, QString> vars[] = {
        { "@font@", Font::family() }, { "@mono@", Font::monoFamily() },
        { "@window@", Hex(p.window) }, { "@sidebar@", Hex(p.sidebar) },
        { "@surface@", Hex(p.surface) }, { "@surfaceAlt@", Hex(p.surfaceAlt) },
        { "@raised@", Hex(p.raised) }, { "@hover@", Hex(p.hover) }, { "@pressed@", Hex(p.pressed) },
        { "@input@", Hex(p.input) }, { "@border@", Hex(p.border) },
        { "@borderStrong@", Hex(p.borderStrong) }, { "@focus@", Hex(p.focus) },
        { "@text@", Hex(p.text) }, { "@text2@", Hex(p.text2) }, { "@text3@", Hex(p.text3) },
        { "@textDisabled@", Hex(p.textDisabled) }, { "@textOnAccent@", Hex(p.textOnAccent) },
        { "@accent@", Hex(p.accent) }, { "@accentHover@", Hex(p.accentHover) },
        { "@accentPressed@", Hex(p.accentPressed) }, { "@accentText@", Hex(p.accentText) },
        { "@accentSoft@", Hex(p.accentSoft) },
        { "@danger@", Hex(p.danger) }, { "@dangerHover@", Hex(p.dangerHover) },
        { "@dangerText@", Hex(p.dangerText) }, { "@okText@", Hex(p.okText) },
        { "@warnText@", Hex(p.warnText) },
        { "@scrollThumb@", Hex(p.scrollThumb) }, { "@scrollThumbHover@", Hex(p.scrollThumbHover) },
        { "@rowHover@", Hex(p.rowHover) }, { "@rowSelected@", Hex(p.rowSelected) },
    };
    for (const auto& [key, value] : vars) s.replace(key, value);
    Q_UNUSED(Rgba);
    return s;
}

} // namespace Ui
