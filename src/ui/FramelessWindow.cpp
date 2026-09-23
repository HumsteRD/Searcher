#include "FramelessWindow.h"

#include <QWidget>
#include <QCursor>
#include <QScreen>
#include <QWindow>

#include <Windows.h>
#include <windowsx.h>
#include <dwmapi.h>

namespace {

// Ширина невидимой полосы у краёв, за которую окно тянется.
constexpr int kResizeBorder = 8;

// Имя намеренно не isMaximized: внутри методов окна его перекрыл бы
// унаследованный QWidget::isMaximized().
bool isZoomedWindow(HWND hwnd) {
    WINDOWPLACEMENT wp{};
    wp.length = sizeof(wp);
    if (!GetWindowPlacement(hwnd, &wp)) return false;
    return wp.showCmd == SW_SHOWMAXIMIZED;
}

} // namespace

FramelessWindow::FramelessWindow(QWidget* parent)
    : QMainWindow(parent)
{
    // Только флаги. Создавать нативное окно здесь нельзя: виджет ещё не
    // достроен, и CreateWindowEx падает с ERROR_INVALID_PARAMETER,
    // после чего Qt зацикливается на попытках его создать.
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
}

void FramelessWindow::showEvent(QShowEvent* event) {
    QMainWindow::showEvent(event);

    if (!nativeFrameReady_) {
        nativeFrameReady_ = true;
        installNativeFrame();
    }
}

void FramelessWindow::installNativeFrame() {
    HWND hwnd = reinterpret_cast<HWND>(winId());
    if (!hwnd) return;

    // Возвращаем окну системные стили. Рамку мы всё равно убираем в
    // WM_NCCALCSIZE, но без этих стилей Windows не даёт ни снапа,
    // ни сворачивания, ни анимаций — окно перестаёт быть «настоящим».
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    style |= WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
    SetWindowLongPtr(hwnd, GWL_STYLE, style);

    // Тень и скругление углов рисует DWM.
    const MARGINS shadow{ 1, 1, 1, 1 };
    DwmExtendFrameIntoClientArea(hwnd, &shadow);

    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    allowDragAndDropFromLowerPrivilege(hwnd);
}

void FramelessWindow::allowDragAndDropFromLowerPrivilege(HWND hwnd) {
    // Приложение запускается от администратора, а проводник — нет.
    // Изоляция привилегий интерфейса (UIPI) молча отбрасывает сообщения
    // из менее привилегированного процесса, поэтому перетаскивание
    // не доходит до окна. Разрешаем ровно те сообщения, что для него нужны.
    constexpr UINT WM_COPYGLOBALDATA = 0x0049;   // не описано в заголовках

    for (UINT msg : { static_cast<UINT>(WM_DROPFILES),
                      static_cast<UINT>(WM_COPYDATA),
                      WM_COPYGLOBALDATA }) {
        ChangeWindowMessageFilterEx(hwnd, msg, MSGFLT_ALLOW, nullptr);
    }
}

void FramelessWindow::setCaptionWidget(QWidget* caption) {
    caption_ = caption;
}

void FramelessWindow::addCaptionExclusion(QWidget* w) {
    if (w) exclusions_.append(QPointer<QWidget>(w));
}

void FramelessWindow::setMaximizeButton(QWidget* button) {
    maxButton_ = button;
    addCaptionExclusion(button);
}

void FramelessWindow::onMaximizeButtonHover(bool) {}

bool FramelessWindow::hitTest(const QPoint& globalPos, qintptr* result) const {
    // Тоже без winId() — см. комментарий в handleNativeEvent().
    HWND hwnd = reinterpret_cast<HWND>(internalWinId());
    if (!hwnd) { *result = HTCLIENT; return true; }

    const QPoint local = mapFromGlobal(globalPos);
    const bool maximized = isZoomedWindow(hwnd);

    // Растягивание — только когда окно в нормальном состоянии.
    if (!maximized) {
        const bool left   = local.x() < kResizeBorder;
        const bool right  = local.x() >= width()  - kResizeBorder;
        const bool top    = local.y() < kResizeBorder;
        const bool bottom = local.y() >= height() - kResizeBorder;

        if (top && left)     { *result = HTTOPLEFT;     return true; }
        if (top && right)    { *result = HTTOPRIGHT;    return true; }
        if (bottom && left)  { *result = HTBOTTOMLEFT;  return true; }
        if (bottom && right) { *result = HTBOTTOMRIGHT; return true; }
        if (left)            { *result = HTLEFT;        return true; }
        if (right)           { *result = HTRIGHT;       return true; }
        if (top)             { *result = HTTOP;         return true; }
        if (bottom)          { *result = HTBOTTOM;      return true; }
    }

    // Прямоугольники считаем в экранных координатах: mapTo() требует, чтобы
    // виджет был потомком окна, и падает, если это не так.
    auto screenRect = [](const QWidget* w) {
        return QRect(w->mapToGlobal(QPoint(0, 0)), w->size());
    };

    // Кнопка «развернуть» отдаётся системе — иначе не будет Snap Layouts.
    if (maxButton_ && maxButton_->isVisible()
        && screenRect(maxButton_).contains(globalPos)) {
        *result = HTMAXBUTTON;
        return true;
    }

    if (caption_ && caption_->isVisible()
        && screenRect(caption_).contains(globalPos)) {
        // Кнопки внутри полосы должны получать обычные события Qt.
        for (const auto& ex : exclusions_) {
            if (!ex || !ex->isVisible()) continue;
            if (screenRect(ex).contains(globalPos)) {
                *result = HTCLIENT;
                return true;
            }
        }
        *result = HTCAPTION;
        return true;
    }

    *result = HTCLIENT;
    return true;
}

bool FramelessWindow::nativeEvent(const QByteArray& eventType, void* message,
                                  qintptr* result)
{
    // Исключение, выпущенное наружу из оконной процедуры, убивает процесс
    // с кодом 0xC000041D и без внятной диагностики. Ловим здесь.
    try {
        return handleNativeEvent(eventType, message, result);
    } catch (...) {
        return QMainWindow::nativeEvent(eventType, message, result);
    }
}

bool FramelessWindow::handleNativeEvent(const QByteArray& eventType,
                                        void* message, qintptr* result)
{
    if (eventType != "windows_generic_MSG" || !message) {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    MSG* msg = static_cast<MSG*>(message);

    // Только internalWinId(): winId() СОЗДАЁТ окно, если его ещё нет.
    // Windows шлёт WM_NCCALCSIZE в процессе создания окна, и вызов winId()
    // отсюда запускал рекурсивное создание — CreateWindowEx падал с
    // ERROR_INVALID_PARAMETER, а Qt зацикливался на повторных попытках.
    HWND hwnd = reinterpret_cast<HWND>(internalWinId());
    if (!hwnd || msg->hwnd != hwnd) {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    switch (msg->message) {

    case WM_NCCALCSIZE: {
        if (msg->wParam == TRUE) {
            // Развёрнутое окно Windows выводит чуть за границы экрана —
            // без этой поправки контент срезало бы по краям.
            if (isZoomedWindow(hwnd)) {
                auto* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(msg->lParam);
                const int padded = GetSystemMetrics(SM_CXPADDEDBORDER);
                const int fx = GetSystemMetrics(SM_CXSIZEFRAME) + padded;
                const int fy = GetSystemMetrics(SM_CYSIZEFRAME) + padded;

                params->rgrc[0].left   += fx;
                params->rgrc[0].right  -= fx;
                params->rgrc[0].top    += fy;
                params->rgrc[0].bottom -= fy;
            }
            *result = 0;
            return true;
        }
        break;
    }

    case WM_NCHITTEST: {
        const QPoint globalPos(GET_X_LPARAM(msg->lParam),
                               GET_Y_LPARAM(msg->lParam));
        return hitTest(globalPos, result);
    }

    // Курсор над кнопкой «развернуть»: Qt мыши не видит, подсветка на нас.
    case WM_NCMOUSEMOVE: {
        const bool onMax = (msg->wParam == HTMAXBUTTON);
        if (onMax != maxHovered_) {
            maxHovered_ = onMax;
            onMaximizeButtonHover(onMax);
        }
        break;
    }
    case WM_NCMOUSELEAVE: {
        if (maxHovered_) {
            maxHovered_ = false;
            onMaximizeButtonHover(false);
        }
        break;
    }

    // Нажатие на HTMAXBUTTON приходит как неклиентское — обрабатываем сами.
    case WM_NCLBUTTONDOWN: {
        if (msg->wParam == HTMAXBUTTON) {
            *result = 0;
            return true;
        }
        break;
    }
    case WM_NCLBUTTONUP: {
        if (msg->wParam == HTMAXBUTTON) {
            if (isZoomedWindow(hwnd)) showNormal();
            else                   showMaximized();
            *result = 0;
            return true;
        }
        break;
    }

    default:
        break;
    }

    return QMainWindow::nativeEvent(eventType, message, result);
}
