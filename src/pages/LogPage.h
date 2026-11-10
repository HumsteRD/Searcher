#pragma once

#include "Page.h"

class QLineEdit;
class QPlainTextEdit;
namespace Ui { class Segmented; }

// «Журнал»: что делали программа и помощник — для разбора проблем.
class LogPage : public Page {
    Q_OBJECT
public:
    explicit LogPage(MainWindow* window);
    void onShown() override;

private:
    void rebuild();
    void append(const QString& line, const QString& level);
    bool passes(const QString& line, const QString& level) const;

    QPlainTextEdit* view_;
    QLineEdit*      search_;
    Ui::Segmented*  filter_;
};
