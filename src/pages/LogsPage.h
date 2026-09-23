#pragma once

#include <QWidget>

class QPlainTextEdit;

class LogsPage : public QWidget {
    Q_OBJECT
public:
    explicit LogsPage(QWidget* parent = nullptr);

    void appendLine(const QString& line, const QString& level);
    void clear();

private:
    QPlainTextEdit* logArea_;
};
