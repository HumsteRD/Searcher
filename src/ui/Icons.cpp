#include "Icons.h"

#include <QGuiApplication>
#include <QHash>
#include <QPainter>
#include <QScreen>
#include <QSvgRenderer>

namespace Icons {
namespace {

// Только содержимое <svg>: обводка задаётся общим шаблоном ниже.
const char* Body(Id id) {
    switch (id) {
    case Id::Home:
        return R"(<path d="M3.5 10.5 12 3.5l8.5 7"/><path d="M5.5 9v11h13V9"/><path d="M10 20v-5.5h4V20"/>)";
    case Id::Shield:
        return R"(<path d="M12 3 4.5 6v5.8c0 4.4 3.1 7.8 7.5 9.2 4.4-1.4 7.5-4.8 7.5-9.2V6z"/>)";
    case Id::ShieldCheck:
        return R"(<path d="M12 3 4.5 6v5.8c0 4.4 3.1 7.8 7.5 9.2 4.4-1.4 7.5-4.8 7.5-9.2V6z"/><path d="m8.8 12 2.3 2.3 4.2-4.6"/>)";
    case Id::ShieldAlert:
        return R"(<path d="M12 3 4.5 6v5.8c0 4.4 3.1 7.8 7.5 9.2 4.4-1.4 7.5-4.8 7.5-9.2V6z"/><path d="M12 8v4.5"/><path d="M12 15.8h.01"/>)";
    case Id::Scan:
        return R"(<path d="M4 8V5.5A1.5 1.5 0 0 1 5.5 4H8"/><path d="M16 4h2.5A1.5 1.5 0 0 1 20 5.5V8"/><path d="M20 16v2.5a1.5 1.5 0 0 1-1.5 1.5H16"/><path d="M8 20H5.5A1.5 1.5 0 0 1 4 18.5V16"/><path d="M7.5 12h9"/>)";
    case Id::Alert:
        return R"(<path d="M10.3 4.3 3 17.2A2 2 0 0 0 4.7 20.2h14.6a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4"/><path d="M12 16.8h.01"/>)";
    case Id::Quarantine:
        return R"(<rect x="3.5" y="4" width="17" height="5" rx="1.5"/><path d="M5 9v9.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V9"/><path d="M10 13h4"/>)";
    case Id::Activity:
        return R"(<path d="M3 12h3.5l2.5-7 4.5 14 2.5-7H21"/>)";
    case Id::History:
        return R"(<path d="M3.8 12a8.2 8.2 0 1 0 2.4-5.8"/><path d="M3.8 4v4.2H8"/><path d="M12 7.5V12l3 2"/>)";
    case Id::Log:
        return R"(<rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="m7.5 9.5 3 2.5-3 2.5"/><path d="M12.5 15h4"/>)";
    case Id::Settings:
        return R"(<path d="M4 7h9"/><path d="M19 7h1"/><circle cx="16" cy="7" r="2.5"/><path d="M4 17h3"/><path d="M13 17h7"/><circle cx="10" cy="17" r="2.5"/>)";
    case Id::Help:
        return R"(<circle cx="12" cy="12" r="8.5"/><path d="M9.6 9.6a2.5 2.5 0 0 1 4.8.9c0 1.7-2.4 2.1-2.4 3.6"/><path d="M12 16.8h.01"/>)";
    case Id::File:
        return R"(<path d="M14 3.5H7A1.5 1.5 0 0 0 5.5 5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8z"/><path d="M14 3.5V8h4.5"/>)";
    case Id::Folder:
        return R"(<path d="M3.5 7A1.5 1.5 0 0 1 5 5.5h4l2 2h8A1.5 1.5 0 0 1 20.5 9v8.5A1.5 1.5 0 0 1 19 19H5a1.5 1.5 0 0 1-1.5-1.5z"/>)";
    case Id::Play:
        return R"(<path d="M8 5.5v13l10-6.5z"/>)";
    case Id::Stop:
        return R"(<rect x="6.5" y="6.5" width="11" height="11" rx="1.5"/>)";
    case Id::Trash:
        return R"(<path d="M4 7h16"/><path d="M9.5 7V4.5h5V7"/><path d="M6 7l1 12.5A1.5 1.5 0 0 0 8.5 21h7a1.5 1.5 0 0 0 1.5-1.5L18 7"/><path d="M10 11v6"/><path d="M14 11v6"/>)";
    case Id::Restore:
        return R"(<path d="M4 12a8 8 0 1 0 2.3-5.6"/><path d="M4 4.5v4h4"/>)";
    case Id::External:
        return R"(<path d="M14 4h6v6"/><path d="M20 4l-8.5 8.5"/><path d="M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/>)";
    case Id::Copy:
        return R"(<rect x="8.5" y="8.5" width="11" height="11" rx="1.5"/><path d="M15.5 8.5V6A1.5 1.5 0 0 0 14 4.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5"/>)";
    case Id::Check:
        return R"(<path d="m5 12.5 4.5 4.5L19 7.5"/>)";
    case Id::Close:
        return R"(<path d="M6.5 6.5l11 11"/><path d="M17.5 6.5l-11 11"/>)";
    case Id::Info:
        return R"(<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5"/><path d="M12 7.8h.01"/>)";
    case Id::Download:
        return R"(<path d="M12 4v11"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M5 19.5h14"/>)";
    case Id::Refresh:
        return R"(<path d="M20 12a8 8 0 1 1-2.3-5.6"/><path d="M20 4.5v4h-4"/>)";
    case Id::Globe:
        return R"(<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.3 2.4 3.5 5.2 3.5 8.5s-1.2 6.1-3.5 8.5c-2.3-2.4-3.5-5.2-3.5-8.5S9.7 5.9 12 3.5z"/>)";
    case Id::Cpu:
        return R"(<rect x="6.5" y="6.5" width="11" height="11" rx="1.5"/><path d="M9.5 3.5v3M14.5 3.5v3M9.5 17.5v3M14.5 17.5v3M3.5 9.5h3M3.5 14.5h3M17.5 9.5h3M17.5 14.5h3"/>)";
    case Id::Power:
        return R"(<path d="M12 3.5v8"/><path d="M7.2 6.3a7.5 7.5 0 1 0 9.6 0"/>)";
    case Id::Calendar:
        return R"(<rect x="4" y="5.5" width="16" height="14.5" rx="1.5"/><path d="M4 10h16"/><path d="M8.5 3.5v4"/><path d="M15.5 3.5v4"/>)";
    case Id::Layers:
        return R"(<path d="m12 3.5 8.5 4.5L12 12.5 3.5 8z"/><path d="m3.5 12 8.5 4.5 8.5-4.5"/><path d="m3.5 16 8.5 4.5 8.5-4.5"/>)";
    case Id::Network:
        return R"(<path d="M5.6 18.4a9 9 0 0 1 0-12.8"/><path d="M18.4 5.6a9 9 0 0 1 0 12.8"/><path d="M8.5 15.5a5 5 0 0 1 0-7"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/><circle cx="12" cy="12" r="1.6"/>)";
    case Id::ChevronRight:
        return R"(<path d="m9.5 6 6 6-6 6"/>)";
    case Id::ChevronDown:
        return R"(<path d="m6 9.5 6 6 6-6"/>)";
    case Id::Plus:
        return R"(<path d="M12 5v14"/><path d="M5 12h14"/>)";
    case Id::Minus:
        return R"(<path d="M5 12h14"/>)";
    case Id::Sun:
        return R"(<circle cx="12" cy="12" r="4"/><path d="M12 2.8v1.9M12 19.3v1.9M4.9 4.9l1.3 1.3M17.8 17.8l1.3 1.3M2.8 12h1.9M19.3 12h1.9M4.9 19.1l1.3-1.3M17.8 6.2l1.3-1.3"/>)";
    case Id::Moon:
        return R"(<path d="M19.5 14.5A7.8 7.8 0 1 1 9.5 4.5a6.2 6.2 0 0 0 10 10z"/>)";
    case Id::Monitor:
        return R"(<rect x="3.5" y="4.5" width="17" height="12" rx="1.5"/><path d="M9 20h6"/><path d="M12 16.5V20"/>)";
    case Id::Lock:
        return R"(<rect x="5" y="10.5" width="14" height="10" rx="1.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>)";
    case Id::Bolt:
        return R"(<path d="M13 3 5.5 13.5H11L10 21l8-10.5h-5.5z"/>)";
    case Id::Drive:
        return R"(<rect x="3.5" y="13" width="17" height="7" rx="1.5"/><path d="M5.5 13 8 5.5h8l2.5 7.5"/><path d="M16.5 16.5h.01"/>)";
    case Id::Target:
        return R"(<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12h.01"/>)";
    case Id::ArrowUp:
        return R"(<circle cx="12" cy="12" r="8.5"/><path d="M12 16V8"/><path d="m8.5 11.5 3.5-3.5 3.5 3.5"/>)";
    case Id::Menu:
        return R"(<path d="M4 7h16"/><path d="M4 12h16"/><path d="M4 17h16"/>)";
    case Id::Cube:
        return R"(<path d="M12 3.5 20 8v8l-8 4.5L4 16V8z"/><path d="m4 8 8 4.5L20 8"/><path d="M12 12.5v8"/>)";
    case Id::Database:
        return R"(<ellipse cx="12" cy="6" rx="7.5" ry="2.5"/><path d="M4.5 6v12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5V6"/><path d="M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5"/>)";
    case Id::Search:
        return R"(<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.4-4.4"/>)";
    case Id::WinMinimize:
        return R"(<path d="M7 12h10"/>)";
    case Id::WinMaximize:
        return R"(<rect x="7" y="7" width="10" height="10" rx="1"/>)";
    case Id::WinRestore:
        return R"(<rect x="7" y="9" width="8" height="8" rx="1"/><path d="M9.5 9V7.5a.5.5 0 0 1 .5-.5h6.5a.5.5 0 0 1 .5.5V14a.5.5 0 0 1-.5.5H15"/>)";
    case Id::WinClose:
        return R"(<path d="M7.5 7.5l9 9"/><path d="M16.5 7.5l-9 9"/>)";
    case Id::Pause:
        return R"(<path d="M8.5 5.5v13"/><path d="M15.5 5.5v13"/>)";
    case Id::Logo:
        return "";
    }
    return "";
}

QString Svg(Id id, const QColor& color, double stroke) {
    return QString(R"(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" )"
                   R"(stroke="%1" stroke-width="%2" stroke-linecap="round" stroke-linejoin="round">%3</svg>)")
        .arg(color.name(QColor::HexRgb))
        .arg(stroke)
        .arg(QString::fromLatin1(Body(id)));
}

qreal DevicePixelRatio() {
    qreal best = 1.0;
    for (QScreen* s : QGuiApplication::screens()) best = std::max(best, s->devicePixelRatio());
    return best;
}

QPixmap Render(const QString& svg, int size, qreal opacity) {
    const qreal dpr = DevicePixelRatio();
    QPixmap pm(static_cast<int>(size * dpr), static_cast<int>(size * dpr));
    pm.fill(Qt::transparent);
    QSvgRenderer renderer(svg.toUtf8());
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setOpacity(opacity);
    renderer.render(&p, QRectF(0, 0, pm.width(), pm.height()));
    p.end();
    pm.setDevicePixelRatio(dpr);
    return pm;
}

// Логотип: скруглённый квадрат цвета акцента и щит с галочкой.
const char* kLogoSvg =
    R"(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">)"
    R"(<rect width="256" height="256" rx="60" fill="#2563EB"/>)"
    R"(<path d="M128 46 194 71v52c0 44-28 76-66 90-38-14-66-46-66-90V71z" fill="none" stroke="#FFFFFF" stroke-width="17" stroke-linejoin="round"/>)"
    R"(<path d="M99 128l20 20 40-43" fill="none" stroke="#FFFFFF" stroke-width="17" stroke-linecap="round" stroke-linejoin="round"/>)"
    R"(</svg>)";

} // namespace

QPixmap pixmap(Id id, int size, const QColor& color) {
    if (id == Id::Logo) return logo(size);
    // Кэш: одни и те же иконки перерисовываются при каждой смене темы.
    static QHash<QString, QPixmap> cache;
    const QString key = QString("%1|%2|%3").arg(static_cast<int>(id)).arg(size).arg(color.rgba());
    auto it = cache.find(key);
    if (it != cache.end()) return *it;
    // Мелкие иконки чуть толще: иначе линия 1.75 на 16 px становится серой.
    const double stroke = size <= 16 ? 2.0 : 1.75;
    QPixmap pm = Render(Svg(id, color, stroke), size, color.alphaF());
    if (cache.size() > 800) cache.clear();
    cache.insert(key, pm);
    return pm;
}

QIcon icon(Id id, int size, const QColor& color) {
    QIcon ic;
    ic.addPixmap(pixmap(id, size, color), QIcon::Normal);
    return ic;
}

QIcon icon(Id id, int size, const QColor& normal, const QColor& disabled) {
    QIcon ic;
    ic.addPixmap(pixmap(id, size, normal), QIcon::Normal);
    ic.addPixmap(pixmap(id, size, disabled), QIcon::Disabled);
    return ic;
}

QPixmap logo(int size) {
    return Render(QString::fromLatin1(kLogoSvg), size, 1.0);
}

QIcon appIcon() {
    QIcon ic;
    for (int s : { 16, 20, 24, 32, 40, 48, 64, 128, 256 }) {
        QPixmap pm(s, s);
        pm.fill(Qt::transparent);
        QSvgRenderer r{ QByteArray(kLogoSvg) };
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing);
        r.render(&p, QRectF(0, 0, s, s));
        p.end();
        ic.addPixmap(pm);
    }
    return ic;
}

} // namespace Icons
