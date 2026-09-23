#pragma once

#include <QWidget>

class QTableWidget;
class QLabel;
class QFrame;

class QuarantinePage : public QWidget {
    Q_OBJECT

public:
    explicit QuarantinePage(QWidget* parent = nullptr);

    // Перечитывает содержимое папки карантина.
    void refresh();

signals:
    // Состав карантина изменился (restore/delete) — чтобы обновить счётчики.
    void changed();

    // Обе операции пишут туда, куда интерфейсу писать нечем: восстановление
    // возвращает файл на исходное место, удаление чистит хранилище
    // в %ProgramData%. Выполняет их помощник, подтверждение уже получено.
    void restoreRequested(QString id);
    void deleteRequested(QString id);

protected:
    void showEvent(QShowEvent* event) override;

private:
    enum Column { ColName, ColThreat, ColSeverity, ColOrigin,
                  ColDate, ColSize, ColActions, ColumnCount };

    void restoreItem(const QString& id, const QString& originalPath);
    void deleteItem(const QString& id, const QString& name);

    QTableWidget* table_;
    QFrame*       tableCard_;
    QFrame*       emptyCard_;
    QLabel*       countLabel_;
};
