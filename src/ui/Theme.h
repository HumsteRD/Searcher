#pragma once

#include <QColor>
#include <QFont>
#include <QObject>
#include <QString>

// Дизайн-система.
//
// Цвета — только отсюда, ни одного литерала цвета в страницах. Смена темы
// перестраивает глобальную таблицу стилей, а свои виджеты перерисовываются
// по сигналу changed(). Контраст пар «текст на фоне» проверяет
// tools/design/contrast.py — после правки палитры запускать обязательно.
//
// Шкалы замкнутые: отступы кратны 4, радиусы 6/8/12, шрифт — 7 размеров.
namespace Ui {

struct Palette {
    bool   dark = false;
    QColor window, sidebar, surface, surfaceAlt, raised, hover, pressed, input;
    QColor border, borderStrong, focus;
    QColor text, text2, text3, textDisabled, textOnAccent;
    QColor accent, accentHover, accentPressed, accentText, accentSoft;
    QColor ok, okText, okSoft;
    QColor warn, warnText, warnSoft;
    QColor high, highText, highSoft;
    QColor danger, dangerText, dangerSoft, dangerHover;
    QColor low, lowText, lowSoft;
    QColor infoSoft;
    QColor scrollThumb, scrollThumbHover;
    QColor rowHover, rowSelected;
};

// Уровень находки → цвета пилюли. Код — "CRIT", "HIGH", "MED", "LOW", "INFO",
// а также "OK" для чистого результата.
struct Tone {
    QColor text, background, solid;
};

class Theme : public QObject {
    Q_OBJECT

public:
    enum class Id { System = 0, Light = 1, Dark = 2, Graphite = 3 };

    static Theme& instance();

    Id  id() const { return id_; }
    Id  effective() const;            // System разворачивается в Light/Dark
    void setId(Id id);                // применяет и сохраняет выбор

    const Palette& palette() const { return palette_; }
    // Палитра любой темы — для превью в настройках.
    static Palette paletteFor(Id id);
    Tone tone(const QString& severityCode) const;

    // Глобальная таблица стилей для текущей палитры.
    QString styleSheet() const;

    // Системная тема Windows изменилась (для режима «Как в системе»).
    void onSystemThemeChanged();

signals:
    void changed();

private:
    Theme();
    void apply();

    Id      id_ = Id::System;
    Palette palette_;
};

inline const Palette& pal() { return Theme::instance().palette(); }

// Типографика: семь размеров.
namespace Font {
    inline constexpr int Display  = 28;   // крупное число, вердикт
    inline constexpr int Title    = 22;   // заголовок страницы
    inline constexpr int Heading  = 16;   // заголовок карточки
    inline constexpr int Body     = 14;   // основной текст
    inline constexpr int Control  = 13;   // кнопки, таблицы, подписи полей
    inline constexpr int Caption  = 12;   // вторичные пометки
    inline constexpr int Micro    = 11;   // пилюли, счётчики

    QFont make(int pixelSize, int weight = QFont::Normal);
    QFont mono(int pixelSize);
    QString family();
    QString monoFamily();
}

namespace Space {
    inline constexpr int XS = 4, S = 8, M = 12, L = 16, XL = 24, XXL = 32;
}

namespace Radius {
    inline constexpr int Small = 6, Control = 8, Card = 12;
}

} // namespace Ui
