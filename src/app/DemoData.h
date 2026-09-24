#pragma once

#include <QString>

class MainWindow;

// Снимки экрана для самопроверки интерфейса: все страницы, три размера
// окна, все темы, оба языка. Данные — выдуманные, в настоящую историю
// и настройки ничего не пишется (кроме временной смены темы и языка,
// которые возвращаются в конце).
namespace DemoData {

int RunScreenshotTour(const QString& outDir);

} // namespace DemoData
