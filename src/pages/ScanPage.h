#pragma once

#include "Page.h"

class QListWidget;
class QStackedWidget;
class QCheckBox;
namespace Ui { class ProgressBar; class ElidedLabel; class Button; class IconLabel; class Pill; }

class ChoiceCard;

// «Проверка»: выбор области, ход проверки, итог.
class ScanPage : public Page {
    Q_OBJECT
public:
    explicit ScanPage(MainWindow* window);
    void onShown() override;

private:
    void refresh();
    void selectMode(int mode);
    void savePaths();

    QStackedWidget* views_;
    // Настройка
    QList<ChoiceCard*> modes_;
    QWidget*        customBox_;
    QListWidget*    paths_;
    QList<QCheckBox*> modules_;
    Ui::Button*     start_;
    // Ход
    QLabel*          modeLabel_;
    QLabel*          stage_;
    QLabel*          percent_;
    Ui::ProgressBar* progress_;
    QLabel*          checked_;
    QLabel*          elapsed_;
    QLabel*          eta_;
    Ui::ElidedLabel* current_;
    QLabel*          found_;
    Ui::Button*      showFound_;
    Ui::Button*      cancel_;
    // Итог
    Ui::IconLabel*   resultIcon_;
    QLabel*          resultTitle_;
    QLabel*          resultText_;
    Ui::Button*      resultPrimary_;
    bool             showResult_ = false;
};

// Карточка выбора: иконка, название, пояснение; выбранная подсвечена.
class ChoiceCard : public QFrame {
    Q_OBJECT
public:
    ChoiceCard(Icons::Id icon, const QString& title, const QString& text, const QString& note);
    void setSelected(bool on);
    bool selected() const { return selected_; }

signals:
    void clicked();

protected:
    void mouseReleaseEvent(QMouseEvent* e) override;
    void enterEvent(QEnterEvent*) override;
    void leaveEvent(QEvent*) override;

private:
    Ui::IconLabel* icon_;
    Icons::Id iconId_;
    bool selected_ = false;
};
