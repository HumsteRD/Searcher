#pragma once

#include "Page.h"

#include "../core/BehaviorReport.h"

class QLineEdit;
class QTableWidget;
class QVBoxLayout;
namespace Ui { class Banner; class Button; class Segmented; class Toggle; class Spinner; }

// «Поведение»: запуск файла в Windows Sandbox и разбор того, что он делал.
class BehaviorPage : public Page {
    Q_OBJECT
public:
    explicit BehaviorPage(MainWindow* window);
    void onShown() override;
    // Открыть сохранённый отчёт (из истории).
    void loadReportFile(const QString& path);

private:
    void refreshAvailability();
    void start();
    void onStage(const QString& stage);
    void onFinished(int result, const QString& message, const QString& howToFix, const QString& reportPath);
    void showReport(const BehaviorReport& report, bool fromFile);
    void publish(const BehaviorReport& report, const QString& reportPath);

    Ui::Banner*     availability_;
    QWidget*        sampleCard_;
    QLineEdit*      samplePath_;
    Ui::Segmented*  duration_;
    Ui::Toggle*     network_;
    Ui::Button*     start_;
    QWidget*        progressCard_;
    QLabel*         stage_;
    Ui::Spinner*    spinner_;
    QWidget*        reportCard_;
    QVBoxLayout*    reportLayout_;
    bool            running_ = false;
    QString         runningSample_;
};
