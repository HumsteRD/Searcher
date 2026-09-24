#pragma once

#include "Page.h"

#include "../core/Quarantine.h"

class QVBoxLayout;
namespace Ui { class EmptyState; class Button; }

// «Карантин»: изолированные файлы, возврат и окончательное удаление.
class QuarantinePage : public Page {
    Q_OBJECT
public:
    explicit QuarantinePage(MainWindow* window);
    void onShown() override;
    void refresh();

private:
    QWidget* makeRow(const QuarantineItem& item);

    QVBoxLayout*    list_;
    QWidget*        listCard_;
    Ui::EmptyState* empty_;
    QWidget*        emptyCard_;
    Ui::Button*     clearAll_;
    std::vector<QuarantineItem> items_;
};
