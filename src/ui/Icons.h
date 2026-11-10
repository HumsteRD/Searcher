#pragma once

#include <QColor>
#include <QIcon>
#include <QPixmap>

// Иконки интерфейса: сетка 24×24, обводка 1.75, скруглённые концы.
// Хранятся путями SVG и рендерятся в нужном цвете с учётом масштаба
// экрана — остаются чёткими при 125–200%.
namespace Icons {

enum class Id {
    Home, Shield, ShieldCheck, ShieldAlert, Scan, Alert, Quarantine, Activity, History,
    Log, Settings, Help, File, Folder, Play, Stop, Trash, Restore, External, Copy,
    Check, Close, Info, Download, Refresh, Globe, Cpu, Power, Calendar, Layers, Network,
    ChevronRight, ChevronDown, Plus, Minus, Sun, Moon, Monitor, Lock, Bolt, Drive, Target,
    ArrowUp, Menu, Cube, Database, Search, WinMinimize, WinMaximize, WinRestore, WinClose,
    Pause, Logo,
};

QPixmap pixmap(Id id, int size, const QColor& color);
QIcon   icon(Id id, int size, const QColor& color);

// Иконка с цветом для обычного и выключенного состояния.
QIcon   icon(Id id, int size, const QColor& normal, const QColor& disabled);

// Логотип приложения (с фоном), для окна, трея и установщика.
QPixmap logo(int size);
QIcon   appIcon();

} // namespace Icons
