#pragma once

#include <QString>

// Дизайн-система Threat Scanner v1.0.
// Значения взяты из макета один в один — не подбирать «на глаз»:
// контраст каждой пары посчитан, шкалы замкнутые.
//
// Типографика: одна шкала из 7 размеров, ничего кроме.
// Отступы: только кратные 4. Границы: всегда 1px.
namespace Theme {

// ─── Поверхности и текст ────────────────────────────────────────────────
inline constexpr const char* WINDOW_BASE   = "#0A0D18";  // база под градиентами
inline constexpr const char* SIDEBAR       = "rgba(9,12,24,0.62)";
inline constexpr const char* CARD          = "#151A2E";  // карточки, тело таблиц, модалки
inline constexpr const char* CARD_HOVER    = "#1A2038";  // только у кликабельных карточек
inline constexpr const char* SUNKEN        = "#101426";  // шапка таблицы, поле ввода, трек
inline constexpr const char* CONSOLE       = "#0D1120";
inline constexpr const char* ROW_HOVER     = "#171D33";
inline constexpr const char* ROW_SELECTED  = "#1B2340";

inline constexpr const char* TEXT_PRIMARY   = "#E8EBF5";
inline constexpr const char* TEXT_SECONDARY = "#A2AAC4";
inline constexpr const char* TEXT_MUTED     = "#808AA8";  // надзаголовки, шапки таблиц
inline constexpr const char* TEXT_DISABLED  = "#5A6280";
inline constexpr const char* TEXT_MONO      = "#C7D0E6";
inline constexpr const char* TEXT_MONO_DIM  = "#6E7794";

// ─── Акцент ─────────────────────────────────────────────────────────────
inline constexpr const char* ACCENT          = "#3E6FD9";
inline constexpr const char* ACCENT_HOVER    = "#4C7DEA";
inline constexpr const char* ACCENT_PRESSED  = "#3260C0";
inline constexpr const char* ACCENT_GRAD_END = "#8B5CF6";  // фиолетовый конец  // правый стоп прогресса
inline constexpr const char* ACCENT_TEXT     = "#7FA6FF";  // активная иконка, индикатор
inline constexpr const char* ACCENT_WASH     = "#1B2440";  // фон активного пункта меню
inline constexpr const char* FOCUS           = "#9DBBFF";

inline constexpr const char* OK        = "#58D6A6";
inline constexpr const char* OK_BG     = "#122A22";
inline constexpr const char* OK_BORDER = "#2C6B52";

// ─── Уровни опасности: цвет + фон + граница ─────────────────────────────
// Красный/оранжевый/жёлтый живут только здесь. LOW и INFO намеренно уходят
// из тёплого ряда в нейтральный сине-серый: «неопасно» не должно выглядеть
// как «слегка опасно».
inline constexpr const char* SEV_CRIT        = "#FF6A78";
inline constexpr const char* SEV_CRIT_BG     = "#3A1420";
inline constexpr const char* SEV_CRIT_BORDER = "#7A2434";

inline constexpr const char* SEV_HIGH        = "#FF9A52";
inline constexpr const char* SEV_HIGH_BG     = "#3A2413";
inline constexpr const char* SEV_HIGH_BORDER = "#7A4A22";

inline constexpr const char* SEV_MED         = "#FFCB57";
inline constexpr const char* SEV_MED_BG      = "#362C10";
inline constexpr const char* SEV_MED_BORDER  = "#6E5A22";

inline constexpr const char* SEV_LOW         = "#9FB0D6";
inline constexpr const char* SEV_LOW_BG      = "#1B2136";
inline constexpr const char* SEV_LOW_BORDER  = "#333C5C";

inline constexpr const char* SEV_INFO        = "#7C86A6";
inline constexpr const char* SEV_INFO_BG     = "#161A29";
inline constexpr const char* SEV_INFO_BORDER = "#2A3148";

// ─── Границы ────────────────────────────────────────────────────────────
inline constexpr const char* BORDER_CARD          = "#262C44";  // декоративный волосок
inline constexpr const char* BORDER_DIVIDER       = "#1D2338";  // разделитель строк
inline constexpr const char* BORDER_CONTROL       = "#626C92";  // 3.35:1 — контролы
inline constexpr const char* BORDER_CONTROL_HOVER = "#7D89B4";
inline constexpr const char* BORDER_DISABLED      = "#2A3150";
inline constexpr const char* FILL_DISABLED        = "#141828";

inline constexpr const char* SCROLL_TRACK   = "#0E1224";
inline constexpr const char* SCROLL_THUMB   = "#2E3654";
inline constexpr const char* SCROLL_HOVER   = "#3C4670";
inline constexpr const char* SCROLL_PRESSED = "#4A557F";

// ─── Шрифты ─────────────────────────────────────────────────────────────
inline constexpr const char* FONT_UI   = "Segoe UI Variable Display";
inline constexpr const char* FONT_MONO = "Cascadia Mono";

// Типографическая шкала — 7 размеров, больше никаких.
// Трекинг задаётся кодом через QFont::setLetterSpacing: в QSS его нет.
namespace Font {
    inline constexpr int METRIC   = 44;  // 600 — крупные числа, процент скана
    inline constexpr int HERO     = 30;  // 600 — вердикт, не чаще раза на экран
    inline constexpr int TITLE    = 20;  // 600 — заголовок страницы, стадия скана
    inline constexpr int CARD     = 16;  // 600 — заголовок карточки, модалки
    inline constexpr int BODY     = 14;  // 400 — текст, ячейки таблиц, ввод
    inline constexpr int CONTROL  = 13;  // 500/600 — кнопки, пункты меню, статусы
    inline constexpr int OVERLINE = 12;  // 600 — надзаголовки, шапки, пилюли

    inline constexpr qreal TRACK_OVERLINE = 1.1;
    inline constexpr qreal TRACK_HEADER   = 0.8;
    inline constexpr qreal TRACK_PILL     = 0.4;
}

// ─── Отступы, радиусы, размеры ──────────────────────────────────────────
namespace Space {
    inline constexpr int XXS = 4,  XS = 8,  S  = 12, M  = 16;
    inline constexpr int L   = 20, XL = 24, XXL = 28, HUGE = 32, MAX = 36;
}

namespace Radius {
    inline constexpr int INDICATOR = 2;   // индикатор активного пункта
    inline constexpr int PROGRESS   = 4;   // прогресс, бейдж уровня лога
    inline constexpr int PILL       = 6;   // пилюли, компактные кнопки
    inline constexpr int CONTROL    = 8;   // кнопки, поля ввода, окно
    inline constexpr int CARD       = 12;  // карточки, таблицы, трек тумблера
    inline constexpr int HERO       = 16;  // карточка-герой, модалка
    inline constexpr int TILE       = 20;  // плитка иконки в герое
}

namespace Size {
    inline constexpr int SIDEBAR      = 216;
    inline constexpr int TITLEBAR     = 56;
    inline constexpr int PAGE_PAD_X   = 28;
    inline constexpr int PAGE_PAD_TOP = 24;

    inline constexpr int BTN_HERO   = 40;
    inline constexpr int BTN_INPUT  = 36;
    inline constexpr int BTN_HEADER = 32;
    inline constexpr int BTN_ROW    = 28;
    inline constexpr int TOGGLE     = 24;
    inline constexpr int PILL       = 20;

    inline constexpr int TABLE_HEADER = 40;
    inline constexpr int TABLE_ROW    = 40;
    inline constexpr int TABLE_PAD_X  = 16;

    inline constexpr int WINDOW_MIN_W = 1100;
    inline constexpr int WINDOW_MIN_H = 720;
    inline constexpr int WINDOW_W     = 1280;
    inline constexpr int WINDOW_H     = 800;
}

// ─── Глобальный QSS ─────────────────────────────────────────────────────
// Только то, что действительно глобально: базовый шрифт, скроллбары,
// подсказки, модальные окна. Всё остальное — на своих виджетах.
inline QString GlobalStyleSheet() {
    return QString(R"(
        QWidget {
            font-family: "%1", "Segoe UI", sans-serif;
            font-size: %2px;
            color: %3;
        }

        QScrollBar:vertical {
            background: %4;
            width: 10px;
            margin: 0;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical {
            background: %5;
            border-radius: 5px;
            min-height: 32px;
        }
        QScrollBar::handle:vertical:hover   { background: %6; }
        QScrollBar::handle:vertical:pressed { background: %7; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }

        QScrollBar:horizontal {
            background: %4;
            height: 10px;
            margin: 0;
            border-radius: 5px;
        }
        QScrollBar::handle:horizontal {
            background: %5;
            border-radius: 5px;
            min-width: 32px;
        }
        QScrollBar::handle:horizontal:hover   { background: %6; }
        QScrollBar::handle:horizontal:pressed { background: %7; }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }

        QMenu {
            background-color: %12;
            border: 1px solid %13;
            border-radius: %10px;
            padding: 6px;
        }
        QMenu::item {
            background-color: transparent;
            color: %3;
            padding: 8px 28px 8px 12px;
            border-radius: %14px;
            margin: 1px 0;
            font-size: %11px;
        }
        QMenu::item:selected {
            background-color: %15;
            color: %3;
        }
        QMenu::item:disabled { color: %16; }
        QMenu::separator {
            height: 1px;
            background: %13;
            margin: 6px 8px;
        }
        QMenu::icon { padding-left: 8px; }

        QToolTip {
            background-color: %8;
            color: %3;
            border: 1px solid %9;
            padding: 8px 12px;
            border-radius: %10px;
            font-size: %11px;
        }
    )")
        .arg(FONT_UI)
        .arg(Font::BODY)
        .arg(TEXT_PRIMARY)
        .arg(SCROLL_TRACK, SCROLL_THUMB, SCROLL_HOVER, SCROLL_PRESSED,
             CARD, BORDER_CARD)
        .arg(Radius::CONTROL)
        .arg(Font::OVERLINE)
        .arg(CARD, BORDER_CARD)
        .arg(Radius::PILL)
        .arg(ROW_SELECTED, TEXT_DISABLED);
}

} // namespace Theme
