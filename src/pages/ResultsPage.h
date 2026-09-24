#pragma once

#include "Page.h"

class QBoxLayout;
class QScrollArea;
class QVBoxLayout;
class ThreatRow;
class ThreatDetail;
namespace Ui { class Segmented; class EmptyState; class Button; }

// «Результаты»: что найдено и что с этим делать.
class ResultsPage : public Page {
    Q_OBJECT
public:
    explicit ResultsPage(MainWindow* window);
    void onShown() override;

protected:
    void resizeEvent(QResizeEvent* e) override;

private:
    void rebuild();
    void updateRow(int row);
    void select(int row);
    void applyFilter();
    void updateHeader();
    void relayout();

    Ui::Segmented*  filter_;
    Ui::Button*     neutralize_;
    QWidget*        split_;
    QBoxLayout*     splitLayout_;
    QWidget*        listCard_;
    QVBoxLayout*    list_;
    ThreatDetail*   detail_;
    Ui::EmptyState* empty_;
    QList<ThreatRow*> rows_;
    int selected_ = -1;
    bool wide_ = true;
};

// Строка находки: уровень, имя, тип, расположение, статус.
class ThreatRow : public QWidget {
    Q_OBJECT
public:
    explicit ThreatRow(int row, QWidget* parent = nullptr);
    void refresh();
    void setSelected(bool on);
    int row() const { return row_; }
    QSize sizeHint() const override { return { 400, 72 }; }
    QSize minimumSizeHint() const override { return { 240, 72 }; }

signals:
    void clicked(int row);

protected:
    void paintEvent(QPaintEvent*) override;
    void mouseReleaseEvent(QMouseEvent*) override;
    void enterEvent(QEnterEvent*) override { hover_ = true; update(); }
    void leaveEvent(QEvent*) override { hover_ = false; update(); }

private:
    int  row_;
    bool selected_ = false;
    bool hover_ = false;
};

// Подробности выбранной находки.
class ThreatDetail : public QWidget {
    Q_OBJECT
public:
    ThreatDetail(MainWindow* window, QWidget* parent = nullptr);
    void show(int row);
    int row() const { return row_; }

private:
    MainWindow*  window_;
    int          row_ = -1;
    QVBoxLayout* layout_;
};
