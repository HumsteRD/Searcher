#pragma once

#include "Page.h"

#include "../ui/Theme.h"

class QListWidget;
class QLineEdit;
class QSpinBox;
namespace Ui { class Toggle; class Segmented; class Button; }

// Карточка выбора темы с маленьким превью окна в её цветах.
class ThemeOption : public QAbstractButton {
    Q_OBJECT
public:
    ThemeOption(Ui::Theme::Id id, const QString& title, QWidget* parent = nullptr);
    QSize sizeHint() const override { return { 150, 118 }; }
    QSize minimumSizeHint() const override { return { 120, 118 }; }

protected:
    void paintEvent(QPaintEvent*) override;
    void enterEvent(QEnterEvent*) override { update(); }
    void leaveEvent(QEvent*) override { update(); }

private:
    Ui::Theme::Id id_;
    QString title_;
};

class SettingsPage : public Page {
    Q_OBJECT
public:
    explicit SettingsPage(MainWindow* window);
    void onShown() override;

private:
    QWidget* section(const QString& title, const QString& subtitle, QWidget* content);
    QWidget* buildAppearance();
    QWidget* buildScanning();
    QWidget* buildProtection();
    QWidget* buildUpdates();
    QWidget* buildIntegrations();
    QWidget* buildApplication();
    QWidget* buildAbout();
    void refreshExclusions();
    void refreshTrusted();
    void refreshSignatureInfo();
    void refreshService();

    QList<ThemeOption*> themes_;
    QListWidget* exclusions_ = nullptr;
    QListWidget* trusted_ = nullptr;
    QLabel*      updateStatus_ = nullptr;
    QLabel*      signatureInfo_ = nullptr;
    Ui::Button*  checkUpdates_ = nullptr;
    Ui::Button*  updateSignatures_ = nullptr;
    Ui::Toggle*  service_ = nullptr;
    QLabel*      serviceStatus_ = nullptr;
    QLineEdit*   vtKey_ = nullptr;
    QLabel*      vtStatus_ = nullptr;
};
