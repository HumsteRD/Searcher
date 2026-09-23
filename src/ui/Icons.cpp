#include "Icons.h"

#include <QSvgRenderer>
#include <QPainter>
#include <QByteArray>
#include <QHash>
#include <QGuiApplication>
#include <QScreen>
#include <QFile>

namespace Icons {
namespace {

struct IconDef {
    const char* paths;    // содержимое <svg>, уже с нужными элементами
    int         viewBox;  // 24 или 16
};

// Path-данные ровно из спеки макета.
IconDef defOf(Id id) {
    switch (id) {
    case Id::Shield:
        return { R"(<path d="M12 3.2 19.2 6v6.1c0 4.1-2.9 7.2-7.2 8.7-4.3-1.5-7.2-4.6-7.2-8.7V6L12 3.2Z"/>)", 24 };
    case Id::ShieldCheck:
        return { R"(<path d="M12 3.2 19.2 6v6.1c0 4.1-2.9 7.2-7.2 8.7-4.3-1.5-7.2-4.6-7.2-8.7V6L12 3.2Z"/>)"
                 R"(<path d="m8.9 11.9 2.3 2.3 4.1-4.4"/>)", 24 };
    case Id::Magnifier:
        return { R"(<circle cx="11" cy="11" r="6.2"/><path d="m15.6 15.6 4.4 4.4"/>)", 24 };
    case Id::Warning:
        return { R"(<path d="M12 4.4 21 19.6H3L12 4.4Z"/><path d="M12 9.8v4.4"/><path d="M12 17h.01"/>)", 24 };
    case Id::Box:
        return { R"(<path d="M4 8.4 12 4.4l8 4v7.2L12 19.6 4 15.6V8.4Z"/>)"
                 R"(<path d="M4 8.4 12 12.4l8-4"/><path d="M12 12.4v7.2"/>)", 24 };
    case Id::List:
        return { R"(<path d="M8 7h12M8 12h12M8 17h12"/><path d="M4 7h.01M4 12h.01M4 17h.01"/>)", 24 };
    case Id::Gear:
        return { R"(<circle cx="12" cy="12" r="3.2"/><circle cx="12" cy="12" r="8.4"/>)"
                 R"(<path d="M12 3.6v2.4M12 18v2.4M4.9 7.9l2.1 1.2M17 14.9l2.1 1.2M4.9 16.1l2.1-1.2M17 9.1l2.1-1.2"/>)", 24 };
    case Id::Check:
        return { R"(<path d="M5 12.8 9.6 17.4 19 8"/>)", 24 };
    case Id::Cross:
        return { R"(<path d="M6.4 6.4 17.6 17.6M17.6 6.4 6.4 17.6"/>)", 24 };
    case Id::Refresh:
        return { R"(<path d="M20 4.6v4.4h-4.4"/><path d="M19.5 12A7.5 7.5 0 1 1 17.3 6.7"/>)", 24 };
    case Id::Folder:
        return { R"(<path d="M3.8 7.2c0-1 .8-1.8 1.8-1.8h3.1l2 2.4h7.7c1 0 1.8.8 1.8 1.8v7.4c0 1-.8 1.8-1.8 1.8H5.6c-1 0-1.8-.8-1.8-1.8V7.2Z"/>)", 24 };
    case Id::Flask:
        return { R"(<path d="M9.6 3.6h4.8"/>)"
                 R"(<path d="M10.4 3.6v5.4l-5 8.4c-.8 1.3.1 3 1.7 3h9.8c1.6 0 2.5-1.7 1.7-3l-5-8.4V3.6"/>)"
                 R"(<path d="M7.8 15.2h8.4"/>)", 24 };
    case Id::Trash:
        return { R"(<path d="M4.8 7.4h14.4"/><path d="M9.4 7.4V5.2h5.2v2.2"/>)"
                 R"(<path d="M6.8 7.4l.8 12c0 .8.7 1.4 1.5 1.4h5.8c.8 0 1.5-.6 1.5-1.4l.8-12"/>)"
                 R"(<path d="M10.4 11v6M13.6 11v6"/>)", 24 };
    case Id::RestoreArrow:
        return { R"(<path d="M4 4.6v4.4h4.4"/><path d="M4.5 12A7.5 7.5 0 1 0 6.7 6.7"/>)", 24 };

    case Id::WinMinimize: return { R"(<path d="M4 8h8"/>)", 16 };
    case Id::WinMaximize: return { R"(<rect x="4.6" y="4.6" width="6.8" height="6.8" rx="1"/>)", 16 };
    case Id::WinClose:    return { R"(<path d="M4.6 4.6 11.4 11.4M11.4 4.6 4.6 11.4"/>)", 16 };
    }
    return { "", 24 };
}

QByteArray buildSvg(Id id, const QColor& color) {
    const IconDef d = defOf(id);
    // Кнопки окна нарисованы тоньше — так в макете тайтлбара.
    const char* width = (d.viewBox == 16) ? "1.2" : "1.75";

    return QByteArray(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 ")
        + QByteArray::number(d.viewBox) + " " + QByteArray::number(d.viewBox)
        + "\" fill=\"none\" stroke=\"" + color.name(QColor::HexRgb).toUtf8()
        + "\" stroke-width=\"" + width
        + "\" stroke-linecap=\"round\" stroke-linejoin=\"round\">"
        + d.paths + "</svg>";
}

} // namespace

QPixmap pixmap(Id id, int size, const QColor& color) {
    // Кэш: иконки перерисовываются на каждой перерисовке строки таблицы,
    // а разбор SVG заметно дороже, чем поиск по ключу.
    static QHash<QString, QPixmap> cache;
    const QString key = QString("%1|%2|%3")
        .arg(static_cast<int>(id)).arg(size).arg(color.name());

    auto it = cache.constFind(key);
    if (it != cache.constEnd()) return it.value();

    QScreen* screen = QGuiApplication::primaryScreen();
    const qreal dpr = screen ? screen->devicePixelRatio() : 1.0;

    QSvgRenderer renderer(buildSvg(id, color));
    QPixmap pm(QSize(size, size) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    renderer.render(&p, QRectF(0, 0, size, size));
    p.end();

    cache.insert(key, pm);
    return pm;
}

QIcon icon(Id id, int size, const QColor& color) {
    return QIcon(pixmap(id, size, color));
}

QPixmap fromResource(const QString& name, int size, const QColor& color) {
    static QHash<QString, QPixmap> cache;
    const QString key = QString("res|%1|%2|%3").arg(name).arg(size).arg(color.name());

    auto it = cache.constFind(key);
    if (it != cache.constEnd()) return it.value();

    QFile f(":/" + name + ".svg");
    if (!f.open(QIODevice::ReadOnly)) return {};

    // У этих фигур единственная заливка — подменяем её на нужный цвет.
    QByteArray svg = f.readAll();
    svg.replace("#FFFFFF", color.name(QColor::HexRgb).toUtf8());

    QScreen* screen = QGuiApplication::primaryScreen();
    const qreal dpr = screen ? screen->devicePixelRatio() : 1.0;

    QSvgRenderer renderer(svg);
    QPixmap pm(QSize(size, size) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    renderer.render(&p, QRectF(0, 0, size, size));
    p.end();

    cache.insert(key, pm);
    return pm;
}

QIcon icon(Id id, int size, const QColor& normal, const QColor& disabled) {
    QIcon ic(pixmap(id, size, normal));
    ic.addPixmap(pixmap(id, size, disabled), QIcon::Disabled);
    return ic;
}

} // namespace Icons
