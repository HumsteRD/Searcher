#pragma once

#include <QDialog>
#include <QString>

class QLabel;

// Своё окно подтверждения вместо QMessageBox: системное не подчиняется
// теме и выглядит инородно в тёмном интерфейсе.
//
// Для необратимых действий цвет опасности живёт в предупреждающей полосе,
// а не в кнопке: красный в этом приложении закреплён за уровнем угрозы.
// Фокус по умолчанию всегда на «Отмена», поэтому Enter никогда
// не уничтожает файл случайно.
class ConfirmDialog : public QDialog {
    Q_OBJECT

public:
    // Возвращает true, если пользователь подтвердил действие.
    static bool ask(QWidget* parent,
                    const QString& title,
                    const QString& text,
                    const QString& confirmLabel,
                    bool irreversible = false);

protected:
    void paintEvent(QPaintEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    ConfirmDialog(QWidget* parent, const QString& title, const QString& text,
                  const QString& confirmLabel, bool irreversible);

    QWidget* card_ = nullptr;
};
