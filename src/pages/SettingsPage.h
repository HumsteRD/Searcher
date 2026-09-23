#pragma once

#include <QWidget>
#include <QHash>

class QLineEdit;
class ToggleSwitch;
class QComboBox;
class QLabel;
class QPushButton;

class ScannerBridge;

class SettingsPage : public QWidget {
    Q_OBJECT
public:
    explicit SettingsPage(QWidget* parent = nullptr);

    // Ставит и снимает службу помощник — диспетчер служб с процессом
    // без прав не разговаривает.
    void setBridge(ScannerBridge* bridge);

private:
    void loadSettings();
    void updateSignatureStatus();
    void refreshServiceStatus();
    void onServiceToggled(bool on);

    QComboBox*   langBox_ = nullptr;
    QComboBox*   scheduleBox_ = nullptr;
    QComboBox*   hourBox_ = nullptr;
    ToggleSwitch* autostart_ = nullptr;
    ToggleSwitch* trayToggle_ = nullptr;
    QLineEdit*   vtKey_;
    QPushButton* vtTestBtn_;
    QLabel*      vtStatus_ = nullptr;
    QLabel*      sigStatus_ = nullptr;
    ToggleSwitch* deepScan_;
    ToggleSwitch* autoQuar_;
    ToggleSwitch* serviceToggle_ = nullptr;
    QLabel*       serviceStatus_ = nullptr;
    ScannerBridge* bridge_ = nullptr;
    // Пока команда в работе, переключатель не должен реагировать на
    // собственное же обратное переключение.
    bool          serviceBusy_ = false;
    QHash<ToggleSwitch*, QWidget*> toggleRows_;
};
