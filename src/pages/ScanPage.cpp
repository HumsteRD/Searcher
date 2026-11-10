#include "ScanPage.h"

#include "../app/AppSettings.h"
#include "../app/AppState.h"
#include "../app/DriveWatcher.h"
#include "../app/Lang.h"
#include "../app/MainWindow.h"
#include "../app/Texts.h"
#include "../core/ScanConfig.h"

#include <QCheckBox>
#include <QDir>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QListWidget>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QStackedWidget>
#include <QVBoxLayout>

using namespace Ui;

// ─── ChoiceCard ───

ChoiceCard::ChoiceCard(Icons::Id icon, const QString& title, const QString& text, const QString& note)
    : iconId_(icon)
{
    setObjectName("choice");
    setCursor(Qt::PointingHandCursor);
    auto* col = new QVBoxLayout(this);
    col->setContentsMargins(18, 18, 18, 18);
    col->setSpacing(8);
    auto* head = new QHBoxLayout();
    head->setSpacing(10);
    icon_ = new IconLabel(icon, 20, ColorRole::Text2);
    icon_->setTile(true, 36);
    head->addWidget(icon_);
    auto* t = makeLabel(title, "subheading");
    t->setWordWrap(true);
    head->addWidget(t, 1);
    col->addLayout(head);
    col->addWidget(makeLabel(text, "muted"));
    col->addStretch(1);
    auto* n = makeLabel(note, "caption");
    col->addWidget(n);
    setSelected(false);
}

void ChoiceCard::setSelected(bool on) {
    selected_ = on;
    setStyleProp(this, "selected", on);
    icon_->set(iconId_, on ? ColorRole::AccentText : ColorRole::Text2);
}

void ChoiceCard::mouseReleaseEvent(QMouseEvent* e) {
    if (e->button() == Qt::LeftButton && rect().contains(e->position().toPoint())) emit clicked();
    QFrame::mouseReleaseEvent(e);
}

void ChoiceCard::enterEvent(QEnterEvent*) { setStyleProp(this, "hover", true); }
void ChoiceCard::leaveEvent(QEvent*) { setStyleProp(this, "hover", false); }

// ─── StageList ───

StageList::StageList(QWidget* parent) : QWidget(parent) {
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void StageList::set(const QStringList& labels, int current, bool paused) {
    if (labels == labels_ && current == current_ && paused == paused_) return;
    const bool resized = labels.size() != labels_.size();
    labels_ = labels;
    current_ = current;
    paused_ = paused;
    if (resized) updateGeometry();
    update();
}

QSize StageList::sizeHint() const {
    return { 320, static_cast<int>(labels_.size()) * 34 };
}

void StageList::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    const int rowH = 34;
    const QFont normal = Font::make(Font::Body);
    const QFont strong = Font::make(Font::Body, QFont::DemiBold);
    const QFont small = Font::make(Font::Caption);

    for (int i = 0; i < labels_.size(); ++i) {
        const int y = i * rowH;
        const QRectF dot(3, y + (rowH - 18) / 2.0, 18, 18);
        const bool done = i < current_;
        const bool active = i == current_;

        // Линия, соединяющая отметки: этапы идут один за другим.
        if (i + 1 < labels_.size()) {
            p.setPen(QPen(done ? c.ok : c.border, 1.5));
            p.drawLine(QPointF(dot.center().x(), dot.bottom() + 2), QPointF(dot.center().x(), y + rowH + (rowH - 18) / 2.0 - 2));
        }

        if (done) {
            p.setPen(Qt::NoPen);
            p.setBrush(c.okSoft);
            p.drawEllipse(dot);
            p.drawPixmap(dot.toRect().adjusted(3, 3, -3, -3), Icons::pixmap(Icons::Id::Check, 12, c.okText));
        } else if (active) {
            const QColor tone = paused_ ? c.warn : c.accent;
            p.setPen(QPen(tone, 1.75));
            p.setBrush(Qt::NoBrush);
            p.drawEllipse(dot.adjusted(1, 1, -1, -1));
            p.setPen(Qt::NoPen);
            p.setBrush(tone);
            p.drawEllipse(dot.adjusted(5.5, 5.5, -5.5, -5.5));
        } else {
            p.setPen(QPen(c.borderStrong, 1.5));
            p.setBrush(Qt::NoBrush);
            p.drawEllipse(dot.adjusted(1, 1, -1, -1));
        }

        const QString note = done ? TR("done") : active ? (paused_ ? TR("on pause") : TR("in progress")) : QString();
        const int noteW = note.isEmpty() ? 0 : QFontMetrics(small).horizontalAdvance(note) + 12;
        const QRect textRect(34, y, width() - 34 - noteW, rowH);
        p.setFont(active ? strong : normal);
        p.setPen(active ? c.text : done ? c.text2 : c.text3);
        p.drawText(textRect, Qt::AlignLeft | Qt::AlignVCenter,
                   QFontMetrics(p.font()).elidedText(labels_[i], Qt::ElideRight, textRect.width()));
        if (!note.isEmpty()) {
            p.setFont(small);
            p.setPen(active ? (paused_ ? c.warnText : c.accentText) : c.text3);
            p.drawText(QRect(width() - noteW, y, noteW, rowH), Qt::AlignRight | Qt::AlignVCenter, note);
        }
    }
}

// ─── ScanPage ───

ScanPage::ScanPage(MainWindow* window)
    : Page(window, TR("Scan"), TR("Choose what to check. The scan runs with administrator rights, "
                                  "so Windows will ask for confirmation."))
{
    views_ = new QStackedWidget(this);
    body()->addWidget(views_);

    // ─── Настройка ───
    auto* setup = new QWidget();
    auto* s = new QVBoxLayout(setup);
    s->setContentsMargins(0, 0, 0, 0);
    s->setSpacing(Space::L);

    s->addWidget(makeLabel(TR("Scan type"), "label"));
    auto* modeGrid = new AdaptiveGrid(250, 3);
    struct ModeDef { Icons::Id icon; const char* title; const char* text; const char* note; };
    const ModeDef defs[] = {
        { Icons::Id::Bolt, "Quick scan",
          "Running programs, startup items and the folders where malware usually ends up: Downloads, "
          "desktop, temporary folders, AppData.", "Usually 1–3 minutes" },
        { Icons::Id::Drive, "Full scan",
          "Everything above plus every local and removable drive, file by file.",
          "From 10 minutes to an hour, depending on the disks" },
        { Icons::Id::Target, "Custom scan",
          "Only the folders and files you choose.", "Depends on the size of the selection" },
    };
    for (int i = 0; i < 3; ++i) {
        auto* card = new ChoiceCard(defs[i].icon, TR(defs[i].title), TR(defs[i].text), TR(defs[i].note));
        modes_ << card;
        modeGrid->addWidget(card);
        connect(card, &ChoiceCard::clicked, this, [this, i]() { selectMode(i); });
    }
    s->addWidget(modeGrid);

    // Выборочная: список путей.
    customBox_ = new Card(nullptr, 18);
    auto* cb = static_cast<Card*>(customBox_)->body();
    cb->addWidget(makeLabel(TR("Folders and files to check"), "subheading"));
    paths_ = new QListWidget();
    paths_->setMinimumHeight(110);
    paths_->setMaximumHeight(180);
    paths_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    paths_->setTextElideMode(Qt::ElideMiddle);
    cb->addWidget(paths_);
    auto* pathButtons = new QHBoxLayout();
    auto* addFolder = new Button(TR("Add folder…"), Button::Variant::Secondary);
    addFolder->setIconId(Icons::Id::Folder);
    auto* addFile = new Button(TR("Add files…"), Button::Variant::Secondary);
    addFile->setIconId(Icons::Id::File);
    auto* addDrive = new Button(TR("Add drive…"), Button::Variant::Secondary);
    addDrive->setIconId(Icons::Id::Drive);
    auto* remove = new Button(TR("Remove"), Button::Variant::Ghost);
    pathButtons->addWidget(addFolder);
    pathButtons->addWidget(addFile);
    pathButtons->addWidget(addDrive);
    pathButtons->addWidget(remove);
    pathButtons->addStretch(1);
    cb->addLayout(pathButtons);
    s->addWidget(customBox_);
    // Диски — меню со списком того, что подключено сейчас: флешку
    // проще выбрать по имени, чем искать её в диалоге выбора папки.
    connect(addDrive, &QPushButton::clicked, this, [this, addDrive]() {
        QMenu menu(this);
        for (const DriveWatcher::Drive& d : DriveWatcher::drives()) {
            QString text = d.title();
            if (d.totalBytes > 0)
                text += QStringLiteral("  ·  ") + TR("%1 free of %2").arg(formatBytes(d.freeBytes), formatBytes(d.totalBytes));
            const QString root = d.root;
            menu.addAction(text, this, [this, root]() {
                paths_->addItem(QDir::toNativeSeparators(root));
                savePaths();
            });
        }
        if (menu.isEmpty()) menu.addAction(TR("No drives found"))->setEnabled(false);
        menu.exec(addDrive->mapToGlobal(QPoint(0, addDrive->height() + 4)));
    });
    for (const QString& p : AppSettings::Get().customPaths()) paths_->addItem(QDir::toNativeSeparators(p));
    savePaths();
    connect(addFolder, &QPushButton::clicked, this, [this]() {
        const QString d = QFileDialog::getExistingDirectory(this, TR("Choose a folder to scan"));
        if (!d.isEmpty()) { paths_->addItem(QDir::toNativeSeparators(d)); savePaths(); }
    });
    connect(addFile, &QPushButton::clicked, this, [this]() {
        for (const QString& f : QFileDialog::getOpenFileNames(this, TR("Choose files to check")))
            paths_->addItem(QDir::toNativeSeparators(f));
        savePaths();
    });
    connect(remove, &QPushButton::clicked, this, [this]() {
        for (QListWidgetItem* item : paths_->selectedItems())
            if (!item->data(Qt::UserRole).toBool()) delete item;
        savePaths();
    });

    // Модули.
    auto* modCard = new Card(nullptr, 18);
    modCard->body()->addWidget(makeLabel(TR("What to check"), "subheading"));
    auto* modGrid = new AdaptiveGrid(300, 2);
    struct ModDef { int id; const char* title; const char* text; };
    const ModDef mods[] = {
        { ScanConfig::Files, "Files", "Programs, scripts, documents with macros and archives" },
        { ScanConfig::Processes, "Running programs", "What is running right now and where it was started from" },
        { ScanConfig::Autoruns, "Startup items", "Everything Windows starts by itself when you sign in" },
        { ScanConfig::Tasks, "Scheduled tasks", "Programs started by Task Scheduler" },
        { ScanConfig::Services, "Services and drivers", "Background services, drivers, WMI subscriptions and the hosts file" },
        { ScanConfig::Network, "Network connections", "Connections to mining pools and remote-control ports" },
    };
    for (const ModDef& m : mods) {
        auto* w = new QWidget();
        auto* col = new QVBoxLayout(w);
        col->setContentsMargins(0, 4, 0, 4);
        col->setSpacing(2);
        auto* box = new QCheckBox(TR(m.title));
        box->setChecked(AppSettings::Get().moduleEnabled(m.id));
        box->setProperty("module", m.id);
        connect(box, &QCheckBox::toggled, this, [id = m.id](bool on) {
            AppSettings::Get().setModuleEnabled(id, on);
        });
        modules_ << box;
        col->addWidget(box);
        auto* d = makeLabel(TR(m.text), "caption");
        d->setContentsMargins(28, 0, 0, 0);
        col->addWidget(d);
        modGrid->addWidget(w);
    }
    modCard->body()->addWidget(modGrid);
    s->addWidget(modCard);

    auto* startRow = new QHBoxLayout();
    start_ = new Button(TR("Start scan"), Button::Variant::Primary);
    start_->setSize(Button::Size::Large);
    start_->setIconId(Icons::Id::Play);
    startRow->addWidget(start_);
    auto* uac = makeLabel(TR("Windows will ask for administrator rights once per session."), "caption");
    startRow->addSpacing(8);
    startRow->addWidget(uac, 1);
    s->addLayout(startRow);
    s->addStretch(1);
    connect(start_, &QPushButton::clicked, this, [this, window]() {
        const int mode = AppSettings::Get().scanMode();
        const QStringList list = AppSettings::Get().customPaths();
        if (mode == 2 && list.isEmpty()) {
            window->toast("MED", TR("Add at least one folder or file"),
                          TR("A custom scan checks only what is in the list."));
            return;
        }
        window->startScan(mode, mode == 2 ? list : QStringList());
    });
    views_->addWidget(setup);

    // ─── Ход проверки ───
    auto* running = new QWidget();
    auto* r = new QVBoxLayout(running);
    r->setContentsMargins(0, 0, 0, 0);
    r->setSpacing(Space::L);
    auto* prog = new Card(nullptr, 24);
    auto* top = new QHBoxLayout();
    auto* titles = new QVBoxLayout();
    titles->setSpacing(4);
    modeLabel_ = makeLabel(QString(), "label");
    titles->addWidget(modeLabel_);
    stage_ = makeLabel(QString(), "hero");
    stage_->setWordWrap(true);
    titles->addWidget(stage_);
    hint_ = makeLabel(QString(), "muted");
    titles->addWidget(hint_);
    top->addLayout(titles, 1);
    percent_ = makeLabel(QString(), "metric");
    top->addWidget(percent_, 0, Qt::AlignTop);
    prog->body()->addLayout(top);
    progress_ = new ProgressBar();
    prog->body()->addWidget(progress_);

    auto* stats = new AdaptiveGrid(150, 3);
    auto stat = [&](const QString& label, QLabel** value) {
        auto* w = new QWidget();
        auto* c = new QVBoxLayout(w);
        c->setContentsMargins(0, 6, 0, 0);
        c->setSpacing(2);
        c->addWidget(makeLabel(label, "label"));
        *value = makeLabel(QString(), "subheading");
        c->addWidget(*value);
        stats->addWidget(w);
    };
    stat(TR("Checked"), &checked_);
    stat(TR("Elapsed"), &elapsed_);
    stat(TR("Remaining"), &eta_);
    prog->body()->addWidget(stats);
    current_ = new ElidedLabel(QString(), Qt::ElideMiddle);
    current_->setProperty("role", "mono");
    prog->body()->addWidget(current_);

    auto* foot = new QHBoxLayout();
    found_ = makeLabel(QString(), "body");
    foot->addWidget(found_, 1);
    showFound_ = new Button(TR("Show findings"), Button::Variant::Secondary);
    pause_ = new Button(TR("Pause"), Button::Variant::Secondary);
    pause_->setIconId(Icons::Id::Pause);
    pause_->setToolTip(TR("Free the disk and processor for a while. The scan continues from the same place."));
    cancel_ = new Button(TR("Stop scan"), Button::Variant::Secondary);
    cancel_->setIconId(Icons::Id::Stop);
    foot->addWidget(showFound_);
    foot->addWidget(pause_);
    foot->addWidget(cancel_);
    prog->body()->addSpacing(4);
    prog->body()->addLayout(foot);
    r->addWidget(prog);

    auto* stages = new Card(nullptr, 22);
    stages->body()->setSpacing(10);
    stages->body()->addWidget(makeLabel(TR("Scan stages"), "subheading"));
    stageList_ = new StageList();
    stages->body()->addWidget(stageList_);
    stagesCard_ = stages;
    r->addWidget(stages);
    r->addStretch(1);
    connect(showFound_, &QPushButton::clicked, this, [window]() { window->navigate(MainWindow::Results); });
    connect(cancel_, &QPushButton::clicked, this, [window]() { window->cancelScan(); });
    connect(pause_, &QPushButton::clicked, this, [window]() {
        window->pauseScan(!AppState::instance().scan().paused);
    });
    views_->addWidget(running);

    // ─── Итог ───
    auto* done = new QWidget();
    auto* d = new QVBoxLayout(done);
    d->setContentsMargins(0, 0, 0, 0);
    auto* res = new Card(nullptr, 24);
    auto* resRow = new QHBoxLayout();
    resRow->setSpacing(20);
    resultIcon_ = new IconLabel(Icons::Id::ShieldCheck, 28, ColorRole::Ok);
    resultIcon_->setTile(true, 56);
    resRow->addWidget(resultIcon_, 0, Qt::AlignTop);
    auto* resCol = new QVBoxLayout();
    resCol->setSpacing(6);
    resultTitle_ = makeLabel(QString(), "hero");
    resultTitle_->setWordWrap(true);
    resultText_ = makeLabel(QString(), "muted");
    resCol->addWidget(resultTitle_);
    resCol->addWidget(resultText_);
    auto* resButtons = new QHBoxLayout();
    resultPrimary_ = new Button(QString(), Button::Variant::Primary);
    auto* again = new Button(TR("New scan"), Button::Variant::Secondary);
    resButtons->addWidget(resultPrimary_);
    resButtons->addWidget(again);
    resButtons->addStretch(1);
    resCol->addSpacing(8);
    resCol->addLayout(resButtons);
    resRow->addLayout(resCol, 1);
    res->body()->addLayout(resRow);
    d->addWidget(res);
    d->addStretch(1);
    connect(again, &QPushButton::clicked, this, [this]() { showResult_ = false; refresh(); });
    connect(resultPrimary_, &QPushButton::clicked, this, [window]() {
        if (AppState::instance().foundInScan() == 0) window->navigate(MainWindow::History);
        else window->navigate(MainWindow::Results);
    });
    views_->addWidget(done);

    selectMode(AppSettings::Get().scanMode());

    connect(&AppState::instance(), &AppState::scanChanged, this, [this]() {
        if (AppState::instance().scan().running) showResult_ = true;
        refresh();
    });
    connect(&AppState::instance(), &AppState::itemAdded, this, &ScanPage::refresh);
    connect(&AppState::instance(), &AppState::itemChanged, this, &ScanPage::refresh);
    refresh();
}

void ScanPage::onShown() { refresh(); }

void ScanPage::selectMode(int mode) {
    AppSettings::Get().setScanMode(mode);
    for (int i = 0; i < modes_.size(); ++i) modes_[i]->setSelected(i == mode);
    customBox_->setVisible(mode == 2);
}

void ScanPage::savePaths() {
    // Строка-подсказка в пустом списке помечена UserRole и путём не является.
    QStringList list;
    for (int i = paths_->count() - 1; i >= 0; --i) {
        QListWidgetItem* item = paths_->item(i);
        if (item->data(Qt::UserRole).toBool()) delete paths_->takeItem(i);
    }
    for (int i = 0; i < paths_->count(); ++i) list << paths_->item(i)->text();
    list.removeDuplicates();
    AppSettings::Get().setCustomPaths(list);
    if (list.isEmpty()) {
        auto* hint = new QListWidgetItem(TR("The list is empty. Add folders or files with the buttons below."));
        hint->setFlags(Qt::NoItemFlags);
        hint->setData(Qt::UserRole, true);
        paths_->addItem(hint);
    }
}

void ScanPage::refresh() {
    const AppState& st = AppState::instance();
    const AppState::Scan& scan = st.scan();
    const int found = st.foundInScan();

    if (scan.running) {
        views_->setCurrentIndex(1);
        modeLabel_->setText(scan.singleTarget ? TR("Checking %1").arg(QDir::toNativeSeparators(scan.target))
                                              : Texts::modeLabel(scan.mode));
        stage_->setText(scan.paused ? TR("Paused")
                        : scan.stage.isEmpty() ? TR("Starting the helper…") : Texts::stageLabel(scan.stage));
        if (scan.percent >= 0) {
            percent_->setText(QString::number(scan.percent) + "%");
            progress_->setValue(scan.percent / 100.0);
        } else {
            percent_->setText(QString());
            // На паузе бегущая полоса обманывала бы: ничего не происходит.
            progress_->setValue(scan.paused ? 0.0 : -1);
        }
        checked_->setText(TR("%1 %2").arg(formatCount(scan.objects))
                              .arg(TRN(scan.objects, "object", "objects", "объект", "объекта", "объектов")));
        elapsed_->setText(formatDuration(scan.elapsedMs));
        eta_->setText(scan.paused ? TR("on pause")
                      : scan.etaMs >= 0 ? TR("about %1").arg(formatDuration(scan.etaMs))
                                        : (scan.percent < 0 ? TR("counting files…") : TR("estimating…")));
        hint_->setText(scan.paused
            ? TR("Nothing is being read from the disk. Press Continue when it is convenient.")
            : TR("You can keep working: the scan runs in the background with a lower priority."));
        pause_->setText(scan.paused ? TR("Continue") : TR("Pause"));
        pause_->setIconId(scan.paused ? Icons::Id::Play : Icons::Id::Pause);
        // Пока помощник не поднялся, приостанавливать нечего.
        pause_->setEnabled(!scan.stage.isEmpty());

        // Этапы: для проверки одного файла список из одной строки ничего
        // не говорит — тогда карточку не показываем.
        static const char* kStageTitles[] = { "Files", "Running programs", "Startup items", "Scheduled tasks",
                                              "Services and drivers", "Network connections" };
        QStringList labels;
        for (int module : scan.stages)
            if (module >= 0 && module < 6) labels << TR(kStageTitles[module]);
        stagesCard_->setVisible(labels.size() > 1);
        stageList_->set(labels, st.currentStageIndex(), scan.paused);
        current_->setFullText(QDir::toNativeSeparators(scan.currentItem));
        found_->setText(found ? TR("Found so far: %1").arg(found) : TR("Nothing found so far"));
        setStyleProp(found_, "tone", found ? "danger" : "");
        showFound_->setVisible(found > 0);
        cancel_->setEnabled(true);
        start_->setEnabled(false);
        return;
    }

    start_->setEnabled(true);
    if (scan.finished && showResult_) {
        views_->setCurrentIndex(2);
        const int pending = st.pendingCount();
        if (scan.cancelled) {
            resultIcon_->set(Icons::Id::Shield, ColorRole::Warn);
            resultTitle_->setText(TR("The scan was stopped"));
        } else if (found == 0) {
            resultIcon_->set(Icons::Id::ShieldCheck, ColorRole::Ok);
            resultTitle_->setText(TR("No threats found"));
        } else {
            resultIcon_->set(Icons::Id::ShieldAlert, pending ? ColorRole::Danger : ColorRole::Ok);
            resultTitle_->setText(pending ? TR("Found: %1, waiting for your decision: %2").arg(found).arg(pending)
                                          : TR("Found: %1, all handled").arg(found));
        }
        resultText_->setText(TR("%1 checked %2 %3 in %4.")
                                 .arg(scan.singleTarget ? TR("The check") : Texts::modeLabel(scan.mode))
                                 .arg(formatCount(scan.objects))
                                 .arg(TRN(scan.objects, "object", "objects", "объект", "объекта", "объектов"))
                                 .arg(formatDuration(scan.elapsedMs)));
        resultPrimary_->setText(found ? TR("Open results") : TR("Open history"));
        return;
    }
    views_->setCurrentIndex(0);
}
