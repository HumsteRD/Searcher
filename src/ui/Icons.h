#pragma once

#include <QIcon>
#include <QPixmap>
#include <QString>
#include <QColor>

// Иконки из макета: viewBox 24×24, только обводка 1.75, круглые концы,
// currentColor. Хранятся как path-данные и рендерятся в нужном цвете
// на лету — иначе пришлось бы держать по SVG-файлу на каждое состояние.
namespace Icons {

enum class Id {
    Shield,        // сайдбар: Home, логотип
    ShieldCheck,   // герой: система защищена
    Magnifier,     // Scan
    Warning,       // Threats, герой: угрозы найдены
    Box,           // Quarantine
    List,          // Logs
    Gear,          // Settings
    Check,
    Cross,
    Refresh,
    Folder,
    Flask,         // Behavior: наблюдение за образцом в изоляции
    Trash,
    RestoreArrow,
    // Кнопки окна — из макета тайтлбара, viewBox 16×16
    WinMinimize,
    WinMaximize,
    WinClose
};

// Пиксмап нужного размера и цвета. Рендерится с учётом devicePixelRatio,
// поэтому остаётся чётким при дробном масштабировании Windows.
QPixmap pixmap(Id id, int size, const QColor& color);

QIcon icon(Id id, int size, const QColor& color);

// Иконка с разными цветами для обычного и выключенного состояния.
QIcon icon(Id id, int size, const QColor& normal, const QColor& disabled);

// Маскот и статусные глифы из identity-набора лежат в ресурсах как SVG
// с заливкой (в отличие от интерфейсных иконок, они не обводка).
// name — имя ресурса без пути и расширения, например "mascot" или
// "glyph-clean". Заливка подменяется на переданный цвет.
QPixmap fromResource(const QString& name, int size, const QColor& color);

} // namespace Icons
