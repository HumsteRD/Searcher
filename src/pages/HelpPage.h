#pragma once

#include <QWidget>

class QVBoxLayout;

// Справка для тех, кто впервые видит подобный инструмент:
// что делает каждая проверка, что значат уровни опасности,
// чем карантин отличается от удаления и как читать ответ VirusTotal.
class HelpPage : public QWidget {
    Q_OBJECT

public:
    explicit HelpPage(QWidget* parent = nullptr);

private:
    void addSection(QVBoxLayout* root, const QString& title,
                    const QString& body);
};
