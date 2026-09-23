#pragma once

#include <QWidget>
#include <QHash>

class QTableWidget;
class QLabel;
class QPushButton;

class ThreatsPage : public QWidget {
    Q_OBJECT

public:
    explicit ThreatsPage(QWidget* parent = nullptr);

    void clearThreats();

    // index — позиция угрозы в Scanner::Snapshot(); по нему выполняются действия.
    // kind — значение ThreatKind (int, чтобы не тащить Windows.h в заголовок).
    // evidence содержит SHA-256 у файловых угроз, у остальных — прочие данные.
    void addThreat(int index, int kind, const QString& severity,
                   const QString& name, const QString& source,
                   const QString& why, const QString& evidence);

    void setThreatStatus(int index, const QString& status,
                         const QString& message, bool success);
    void setVirusTotalResult(int index, const QString& text, bool malicious,
                         const QString& explanation = QString());
    void setVirusTotalPending(int index);

signals:
    // action: 0 = Quarantine, 1 = Delete, 2 = Ignore
    void actionRequested(int index, int action);
    void vtCheckRequested(int index, QString sha256);
    // Кнопка в пустом состоянии таблицы.
    void scanRequested();

protected:
    void showEvent(QShowEvent* event) override;

private:
    enum Column { ColSeverity, ColName, ColSource, ColVirusTotal,
                  ColStatus, ColActions, ColumnCount };

    // Отдать «Расположению» всё, что осталось от ширины. Колонка при
    // этом остаётся тянущейся мышью — в отличие от режима Stretch,
    // который двигать нельзя.
    void fitSourceColumn();

    void updateEmptyState();
    void quarantineAllCritical();
    void checkAllOnVirusTotal();
    QWidget* buildActionCell(int index, int kind);

    QTableWidget* table_;
    QWidget*      emptyBox_ = nullptr;
    QLabel*       countBadge_;
    QPushButton*  quarantineAllBtn_;
    QPushButton*  vtAllBtn_;

    QHash<int, int>     indexToRow_;   // index угрозы -> строка таблицы
    QHash<int, QString> indexToHash_;
    QHash<int, QString> indexDetails_;   // причина находки для окна подробностей  // index угрозы -> SHA-256 (может быть пуст)
};
