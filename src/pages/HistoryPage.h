#pragma once

#include <QWidget>

class QTableWidget;
class QFrame;
class QLabel;

// История проверок: таблица прошлых запусков, просмотр находок
// и выгрузка отчёта в файл.
class HistoryPage : public QWidget {
    Q_OBJECT

public:
    explicit HistoryPage(QWidget* parent = nullptr);

    void refresh();

signals:
    // Запись сеанса песочницы хранит полный отчёт наблюдения; показать
    // его умеет страница поведения, а не эта.
    void behaviourReportRequested(QString path);

protected:
    void showEvent(QShowEvent* event) override;

private:
    enum Column { ColDate, ColMode, ColDuration, ColObjects,
                  ColThreats, ColActions, ColumnCount };

    void exportRecord(int index);

    // Раздать ширину: каждой колонке минимум по её заголовку, остаток
    // пропорционально. Иначе либо подписи обрезаются, либо таблица
    // не помещается и колонки болтаются в пустоте.
    void fitColumns();

    QTableWidget* table_ = nullptr;
    QFrame*       tableCard_ = nullptr;
    QWidget*      emptyBox_ = nullptr;
};
