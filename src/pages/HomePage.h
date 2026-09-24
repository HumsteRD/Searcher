#pragma once

#include "Page.h"

namespace Ui { class StatTile; class IconLabel; class Button; class Banner; class ProgressBar; }

// «Обзор»: состояние защиты одной фразой и главное действие.
class HomePage : public Page {
    Q_OBJECT
public:
    explicit HomePage(MainWindow* window);
    void onShown() override;
    void refresh();

private:
    Ui::IconLabel*   heroIcon_;
    QLabel*          heroTitle_;
    QLabel*          heroText_;
    Ui::ProgressBar* heroProgress_;
    Ui::Button*      primary_;
    Ui::Button*      secondary_;
    Ui::StatTile*    lastScan_;
    Ui::StatTile*    pending_;
    Ui::StatTile*    quarantine_;
    Ui::StatTile*    databases_;
    QLabel*          guardState_;
    QLabel*          scheduleState_;
    QLabel*          signaturesState_;
    QLabel*          updateState_;
    QMetaObject::Connection primaryConn_, secondaryConn_;
};
