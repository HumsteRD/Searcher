#pragma once

#include "Page.h"

class QVBoxLayout;
namespace Ui { class EmptyState; class Button; }
struct ScanRecord;

// «История»: прошлые проверки, отчёты по ним.
class HistoryPage : public Page {
    Q_OBJECT
public:
    explicit HistoryPage(MainWindow* window);
    void onShown() override;
    void refresh();

signals:
    void behaviorReportRequested(QString path);

private:
    QWidget* makeRow(int index);

    QVBoxLayout* list_;
    QWidget*     listCard_;
    QWidget*     emptyCard_;
    Ui::Button*  clear_;
    QSet<qint64> expanded_;   // время проверки в миллисекундах
};
