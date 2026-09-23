#pragma once

#include "../core/SandboxSession.h"
#include "../core/BehaviorVerdict.h"

#include <QWidget>
#include <QString>

class QLabel;
class QFrame;
class QComboBox;
class QTableWidget;
class QTreeWidget;
class QVBoxLayout;
class GradientButton;
class ToggleSwitch;
class ScannerBridge;

// Динамический анализ: запуск образца в Windows Sandbox и разбор того,
// что он там натворил.
//
// Страница обязана быть честной в двух местах. Первое — когда песочницы
// на системе нет: тогда вместо неработающей кнопки показывается причина,
// и если её нельзя исправить, об этом говорится прямо. Второе — список
// ограничений наблюдения: он показывается вместе с отчётом, а не прячется
// под ссылку, иначе отчёт читается как полная картина происходившего.
class SandboxPage : public QWidget {
    Q_OBJECT

public:
    explicit SandboxPage(QWidget* parent = nullptr);
    ~SandboxPage() override;

    // Показать сохранённый отчёт. Зовётся кнопкой на самой странице и
    // строкой сеанса в истории проверок.
    void loadReportFile(const QString& path);

    // Сеанс держит привилегированный помощник — страница только просит
    // его начать и показывает, что пришло обратно.
    void setBridge(ScannerBridge* bridge);

signals:
    // Поведение потянуло на угрозу. Дальше её судьбу решает MainWindow:
    // она попадает в общий список, и к ней применимы карантин и удаление,
    // как к находке обычной проверки.
    void behaviourThreatFound(const Threat& threat);

private:
    void buildAvailabilityCard(QVBoxLayout* root);
    void buildSampleCard(QVBoxLayout* root);
    void buildStatusCard(QVBoxLayout* root);
    void buildReportCards(QVBoxLayout* root);

    void chooseSample();
    void openReport();
    void startSession();
    void cancelSession();
    void onSessionFinished(int result, const QString& message,
                           const QString& howToFix, const QString& reportPath);

    void showReport(const BehaviorReport& report);
    void fillVerdict(const BehaviorReport& report);

    // Разнести результат сеанса по остальному приложению: угроза,
    // запись в истории, строка в журнале. Только для настоящего сеанса —
    // отчёт, открытый из файла, сюда не попадает.
    void publishSession(const BehaviorReport& report, const QString& reportPath);
    void fillProcessTree(const BehaviorReport& report);
    void fillEvents(const BehaviorReport& report);
    void fillLimitations(const BehaviorReport& report);

    void setRunning(bool running);
    void setStatus(const QString& text, const QString& hint = {},
                   const QString& color = {});
    void showReportCards(bool visible);

    // ─── Ввод ───
    QLabel*         sampleField_ = nullptr;
    GradientButton* chooseButton_ = nullptr;
    GradientButton* runButton_ = nullptr;
    GradientButton* cancelButton_ = nullptr;
    ToggleSwitch*   networkToggle_ = nullptr;
    QComboBox*      durationBox_ = nullptr;

    // ─── Состояние и отчёт ───
    QFrame* availabilityCard_ = nullptr;
    QFrame* statusCard_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* statusHint_ = nullptr;

    // Надзаголовки секций прячутся вместе со своими карточками —
    // иначе на пустой странице висят заголовки без содержимого.
    QLabel* processesTitle_ = nullptr;
    QLabel* eventsTitle_ = nullptr;
    QLabel* limitationsTitle_ = nullptr;

    QFrame*       verdictCard_ = nullptr;
    QVBoxLayout*  verdictLayout_ = nullptr;
    QFrame*       summaryCard_ = nullptr;
    QLabel*       summaryLabel_ = nullptr;
    QFrame*       treeCard_ = nullptr;
    QTreeWidget*  processTree_ = nullptr;
    QFrame*       eventsCard_ = nullptr;
    QTableWidget* eventsTable_ = nullptr;
    QFrame*       limitationsCard_ = nullptr;
    QVBoxLayout*  limitationsLayout_ = nullptr;

    // Показывается, пока сеансов ещё не было. Если песочницы нет,
    // не показывается вовсе: обещать пустому месту нечего.
    QFrame* emptyCard_ = nullptr;

    QString        samplePath_;
    bool           sandboxAvailable_ = false;
    bool           running_ = false;
    ScannerBridge* bridge_ = nullptr;
};
