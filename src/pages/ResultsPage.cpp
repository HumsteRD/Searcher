#include "ResultsPage.h"

#include "../app/AppState.h"
#include "../app/Lang.h"
#include "../app/MainWindow.h"
#include "../app/Texts.h"
#include "../app/VirusTotalClient.h"

#include <QApplication>
#include <QBoxLayout>
#include <QClipboard>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QProcess>
#include <QScrollArea>
#include <QUrl>
#include <QVBoxLayout>

using namespace Ui;

namespace {

ColorRole RoleFor(Severity s) {
    switch (s) {
    case Severity::Critical: return ColorRole::Danger;
    case Severity::High:     return ColorRole::High;
    case Severity::Medium:   return ColorRole::Warn;
    case Severity::Low:      return ColorRole::Low;
    default:                 return ColorRole::Text2;
    }
}

bool IsOpen(ThreatStatus s) {
    return s == ThreatStatus::Pending || s == ThreatStatus::Failed || s == ThreatStatus::Ignored;
}

void RevealInExplorer(const QString& path) {
    // Проводник с выделенным файлом; если файла уже нет — его папка.
    const QString native = QDir::toNativeSeparators(path);
    if (QFileInfo::exists(path)) {
        QProcess::startDetached("explorer.exe", { "/select,", native });
    } else {
        const QString dir = QFileInfo(path).absolutePath();
        if (QFileInfo::exists(dir)) QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
    }
}

QScrollArea* MakeScroll(QWidget* inner) {
    auto* s = new QScrollArea();
    s->setWidget(inner);
    // setWidget включает заливку фоном окна — внутри карточки это тёмное пятно.
    inner->setAutoFillBackground(false);
    s->setWidgetResizable(true);
    s->setFrameShape(QFrame::NoFrame);
    s->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    return s;
}

} // namespace

// ─── ThreatRow ───

ThreatRow::ThreatRow(int row, QWidget* parent) : QWidget(parent), row_(row) {
    setCursor(Qt::PointingHandCursor);
    setFixedHeight(72);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    connect(&Theme::instance(), &Theme::changed, this, qOverload<>(&QWidget::update));
}

void ThreatRow::refresh() { update(); }

void ThreatRow::setSelected(bool on) {
    selected_ = on;
    update();
}

void ThreatRow::mouseReleaseEvent(QMouseEvent* e) {
    if (e->button() == Qt::LeftButton) emit clicked(row_);
}

void ThreatRow::paintEvent(QPaintEvent*) {
    const auto& items = AppState::instance().items();
    if (row_ < 0 || row_ >= items.size()) return;
    const AppState::Item& it = items[row_];
    const Threat& t = it.threat;

    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    const Palette& c = pal();
    if (selected_ || hover_) {
        p.setPen(Qt::NoPen);
        p.setBrush(selected_ ? c.rowSelected : c.rowHover);
        p.drawRoundedRect(QRectF(rect()).adjusted(4, 2, -4, -2), 8, 8);
    }

    // Полоса уровня слева.
    const Tone tone = Theme::instance().tone(Texts::severityCode(t.severity));
    const bool open = IsOpen(t.status);
    p.setPen(Qt::NoPen);
    p.setBrush(open ? tone.solid : c.borderStrong);
    p.drawRoundedRect(QRectF(12, 16, 3, height() - 32), 1.5, 1.5);

    // Статус справа.
    const QString statusText = it.busy ? TR("Working…") : Texts::statusLabel(t.status);
    const Tone st = Theme::instance().tone(it.busy ? "INFO" : Texts::statusTone(t.status));
    const QFont pillFont = Font::make(Font::Caption, QFont::DemiBold);
    const int pillW = QFontMetrics(pillFont).horizontalAdvance(statusText) + 18;
    const QRectF pill(width() - pillW - 16, (height() - 22) / 2.0, pillW, 22);
    p.setBrush(st.background);
    p.drawRoundedRect(pill, 6, 6);
    p.setPen(st.text);
    p.setFont(pillFont);
    p.drawText(pill, Qt::AlignCenter, statusText);

    const int x = 28;
    const int textW = static_cast<int>(pill.left()) - x - 16;
    const QString name = QString::fromStdWString(t.name);
    p.setFont(Font::make(Font::Body, QFont::DemiBold));
    p.setPen(open ? c.text : c.text2);
    QFontMetrics fm(p.font());
    p.drawText(QRect(x, 12, textW, 20), Qt::AlignLeft | Qt::AlignVCenter,
               fm.elidedText(name, Qt::ElideRight, textW));

    p.setFont(Font::make(Font::Control, QFont::Normal));
    fm = QFontMetrics(p.font());
    const QString line2 = Texts::severityLabel(t.severity) + " · " + Texts::headline(t);
    p.setPen(open ? tone.text : c.text3);
    p.drawText(QRect(x, 32, textW, 18), Qt::AlignLeft | Qt::AlignVCenter,
               fm.elidedText(line2, Qt::ElideRight, textW));

    p.setFont(Font::make(Font::Caption));
    fm = QFontMetrics(p.font());
    p.setPen(c.text3);
    p.drawText(QRect(x, 50, textW, 16), Qt::AlignLeft | Qt::AlignVCenter,
               fm.elidedText(QString::fromStdWString(t.source), Qt::ElideMiddle, textW));
}

// ─── ThreatDetail ───

ThreatDetail::ThreatDetail(MainWindow* window, QWidget* parent) : QWidget(parent), window_(window) {
    layout_ = new QVBoxLayout(this);
    layout_->setContentsMargins(22, 20, 22, 22);
    layout_->setSpacing(14);
}

void ThreatDetail::show(int row) {
    row_ = row;
    clearLayout(layout_);

    const auto& items = AppState::instance().items();
    if (row < 0 || row >= items.size()) {
        auto* hint = new EmptyState(Icons::Id::Info, TR("Select a finding"),
                                    TR("Details, the reasons it was flagged and the available actions appear here."));
        layout_->addWidget(hint);
        layout_->addStretch(1);
        return;
    }
    const AppState::Item& it = items[row];
    const Threat& t = it.threat;
    const bool open = IsOpen(t.status);

    // Заголовок.
    auto* head = new QHBoxLayout();
    head->setSpacing(14);
    auto* icon = new IconLabel(open ? Icons::Id::ShieldAlert : Icons::Id::ShieldCheck, 22,
                               open ? RoleFor(t.severity) : ColorRole::Ok);
    icon->setTile(true, 44);
    head->addWidget(icon, 0, Qt::AlignTop);
    auto* titles = new QVBoxLayout();
    titles->setSpacing(4);
    auto* name = makeLabel(breakable(QString::fromStdWString(t.name)), "heading");
    name->setWordWrap(true);
    name->setTextInteractionFlags(Qt::TextSelectableByMouse);
    titles->addWidget(name);
    titles->addWidget(makeLabel(Texts::headline(t), "muted"));
    head->addLayout(titles, 1);
    layout_->addLayout(head);

    auto* pills = new QHBoxLayout();
    pills->setSpacing(6);
    pills->addWidget(new Pill(Texts::severityLabel(t.severity), Texts::severityCode(t.severity)));
    auto* status = new Pill(it.busy ? TR("Working…") : Texts::statusLabel(t.status),
                            it.busy ? "INFO" : Texts::statusTone(t.status));
    pills->addWidget(status);
    auto* kind = new Pill(Texts::kindLabel(t.kind), "INFO");
    kind->setDot(false);
    pills->addWidget(kind);
    pills->addStretch(1);
    layout_->addLayout(pills);

    layout_->addWidget(makeLabel(Texts::classExplain(t.malwareClass), "body"));

    // Почему найдено.
    const QList<Texts::Reason> reasons = Texts::reasons(t);
    auto* whyTitle = makeLabel(TR("Why it was flagged"), "label");
    layout_->addWidget(whyTitle);
    for (const Texts::Reason& r : reasons) {
        if (r.technical) continue;
        auto* row = new QHBoxLayout();
        row->setSpacing(10);
        auto* dot = new IconLabel(Icons::Id::ChevronRight, 14, ColorRole::Text3);
        row->addWidget(dot, 0, Qt::AlignTop);
        auto* col = new QVBoxLayout();
        col->setSpacing(1);
        col->addWidget(makeLabel(breakable(r.text), "body"));
        if (!r.detail.isEmpty()) {
            auto* d = makeLabel(breakable(r.detail), "caption");
            d->setTextInteractionFlags(Qt::TextSelectableByMouse);
            col->addWidget(d);
        }
        row->addLayout(col, 1);
        layout_->addLayout(row);
    }

    // Что делать.
    if (open) {
        auto* advice = new Banner("ACCENT", Icons::Id::Info, QString(), Texts::advice(t));
        layout_->addWidget(advice);
    }
    if (!t.actionMessage.empty()) {
        layout_->addWidget(makeLabel(Texts::actionResult(QString::fromStdWString(t.actionMessage),
                                                         t.status != ThreatStatus::Failed), "muted"));
    }

    // Действия. Ряды — с переносом: в узкой панели кнопки уходят на
    // следующую строку, а не растягивают панель за край.
    auto* actionsBox = new QWidget();
    auto* actions = new FlowLayout(actionsBox, 8, 8);
    if (it.busy) {
        auto* spin = new Spinner(18);
        spin->setRunning(true);
        actions->addWidget(spin);
        actions->addWidget(makeLabel(TR("Applying the action…"), "muted"));
    } else if (open) {
        const bool entry = t.kind == ThreatKind::RegistryValue || t.kind == ThreatKind::ScheduledTask ||
                           t.kind == ThreatKind::WmiConsumer || t.kind == ThreatKind::HostsEntry;
        const bool service = t.kind == ThreatKind::Service;
        auto* primary = new Button(service ? TR("Disable") : entry ? TR("Remove entry") : TR("Quarantine"),
                                   Button::Variant::Primary);
        primary->setIconId(Icons::Id::Quarantine);
        connect(primary, &QPushButton::clicked, this, [this, row]() { window_->applyAction(row, 0); });
        actions->addWidget(primary);
        if (t.kind == ThreatKind::File || t.kind == ThreatKind::Process) {
            auto* del = new Button(TR("Delete"), Button::Variant::Secondary);
            del->setIconId(Icons::Id::Trash);
            connect(del, &QPushButton::clicked, this, [this, row, t]() {
                Modal::confirm(window_->overlayHost(), TR("Delete the file for good?"),
                               TR("%1 will be deleted without the possibility of restoring it. "
                                  "Quarantine is the safer choice if you are not sure.")
                                   .arg(QString::fromStdWString(t.name)),
                               TR("Delete"), true, [this, row]() { window_->applyAction(row, 1); });
            });
            actions->addWidget(del);
        }
        if (t.status != ThreatStatus::Ignored) {
            auto* skip = new Button(TR("Skip"), Button::Variant::Ghost);
            skip->setToolTip(TR("Leave it as it is for now. You can come back to it later."));
            connect(skip, &QPushButton::clicked, this, [this, row]() { window_->applyAction(row, 2); });
            actions->addWidget(skip);
        }
    }
    layout_->addWidget(actionsBox);

    // Дополнительно: папка, VirusTotal, доверие.
    auto* extraBox = new QWidget();
    auto* extra = new FlowLayout(extraBox, 18, 6);
    const QString filePath = QString::fromStdWString(t.filePath);
    if (!filePath.isEmpty()) {
        auto* reveal = new Button(TR("Show in folder"), Button::Variant::Link);
        connect(reveal, &QPushButton::clicked, this, [filePath]() { RevealInExplorer(filePath); });
        extra->addWidget(reveal);
    }
    const QString sha = QString::fromStdString(t.sha256);
    if (!sha.isEmpty()) {
        auto* vt = new Button(it.vtState == 1 ? TR("Checking on VirusTotal…") : TR("Check on VirusTotal"),
                              Button::Variant::Link);
        vt->setEnabled(it.vtState != 1);
        connect(vt, &QPushButton::clicked, this, [this, row, sha]() {
            if (!VirusTotalClient::instance().hasApiKey()) {
                QDesktopServices::openUrl(QUrl("https://www.virustotal.com/gui/file/" + sha));
                return;
            }
            AppState::instance().setVirusTotal(row, 1, QString());
            VirusTotalClient::instance().lookup(row, sha);
        });
        extra->addWidget(vt);
        if (open) {
            auto* trust = new Button(TR("Trust this file"), Button::Variant::Link);
            trust->setToolTip(TR("Future scans will skip files with exactly the same contents."));
            connect(trust, &QPushButton::clicked, this, [this, row, t]() {
                Modal::confirm(window_->overlayHost(), TR("Trust this file?"),
                               TR("%1 will no longer be reported. Do this only if you are sure the file is safe, "
                                  "for example a tool you wrote yourself.").arg(QString::fromStdWString(t.name)),
                               TR("Trust"), false, [this, row]() { window_->allowItem(row); });
            });
            extra->addWidget(trust);
        }
    }
    layout_->addWidget(extraBox);
    if (!it.vtText.isEmpty()) {
        auto* vtResult = makeLabel(it.vtText, "muted");
        setStyleProp(vtResult, "tone", it.vtState == 3 ? "danger" : it.vtState == 2 ? "ok" : "");
        layout_->addWidget(vtResult);
    }

    // Технические подробности.
    layout_->addWidget(makeDivider());
    auto* techToggle = new Button(TR("Technical details"), Button::Variant::Ghost);
    techToggle->setIconId(Icons::Id::ChevronRight);   // свёрнуто — вправо, раскрыто — вниз
    techToggle->setSize(Button::Size::Small);
    auto* tech = new QWidget();
    auto* tl = new QVBoxLayout(tech);
    tl->setContentsMargins(0, 0, 0, 0);
    tl->setSpacing(10);
    auto field = [&](const QString& label, const QString& value) {
        if (value.isEmpty()) return;
        auto* col = new QVBoxLayout();
        col->setSpacing(2);
        col->addWidget(makeLabel(label, "label"));
        auto* v = makeLabel(breakable(value), "mono");
        v->setWordWrap(true);
        v->setTextInteractionFlags(Qt::TextSelectableByMouse);
        col->addWidget(v);
        tl->addLayout(col);
    };
    field(TR("Location"), QString::fromStdWString(t.source));
    if (filePath != QString::fromStdWString(t.source)) field(TR("File"), filePath);
    field("SHA-256", sha);
    field(TR("Digital signature"), t.signer.empty() ? TR("none") : QString::fromStdWString(t.signer));
    field(TR("Command line"), QString::fromStdWString(t.evidence));
    QStringList techLines;
    for (const Texts::Reason& r : reasons)
        if (r.technical) techLines << (r.detail.isEmpty() ? r.text : r.text + " — " + r.detail);
    field(TR("Engine details"), techLines.join("\n"));
    if (!sha.isEmpty()) {
        auto* copy = new Button(TR("Copy SHA-256"), Button::Variant::Secondary);
        copy->setSize(Button::Size::Small);
        copy->setIconId(Icons::Id::Copy);
        connect(copy, &QPushButton::clicked, this, [sha]() { QApplication::clipboard()->setText(sha); });
        auto* r = new QHBoxLayout();
        r->addWidget(copy);
        r->addStretch(1);
        tl->addLayout(r);
    }
    tech->setVisible(false);
    connect(techToggle, &QPushButton::clicked, this, [tech, techToggle]() {
        tech->setVisible(!tech->isVisible());
        techToggle->setIconId(tech->isVisible() ? Icons::Id::ChevronDown : Icons::Id::ChevronRight);
    });
    auto* toggleRow = new QHBoxLayout();
    toggleRow->addWidget(techToggle);
    toggleRow->addStretch(1);
    layout_->addLayout(toggleRow);
    layout_->addWidget(tech);
    layout_->addStretch(1);
}

// ─── ResultsPage ───

ResultsPage::ResultsPage(MainWindow* window)
    : Page(window, TR("Results"), TR("What the last scan found and what you decided to do with it."))
{
    setScrollable(false);

    search_ = new QLineEdit();
    search_->setPlaceholderText(TR("Search findings"));
    search_->setClearButtonEnabled(true);
    search_->setFixedWidth(200);
    actions()->addWidget(search_);
    connect(search_, &QLineEdit::textChanged, this, &ResultsPage::applyFilter);
    connect(window, &MainWindow::searchRequested, this, [this]() {
        if (!isVisible() || !search_->isVisible()) return;
        search_->setFocus();
        search_->selectAll();
    });

    filter_ = new Segmented({ TR("All"), TR("Need action"), TR("Handled") });
    actions()->addWidget(filter_);
    neutralize_ = new Button(TR("Neutralize all"), Button::Variant::Primary);
    neutralize_->setIconId(Icons::Id::Quarantine);
    actions()->addWidget(neutralize_);
    connect(neutralize_, &QPushButton::clicked, this, [window]() { window->neutralizeAll(); });
    connect(filter_, &Segmented::currentChanged, this, &ResultsPage::applyFilter);

    empty_ = new EmptyState(Icons::Id::ShieldCheck, TR("Nothing to show"),
                            TR("Findings from the current scan and from files you check appear here."));
    auto* scanNow = empty_->addAction(TR("Quick scan"), Button::Variant::Primary);
    connect(scanNow, &QPushButton::clicked, this, [window]() { window->startScan(0); });
    auto* emptyCard = new Card(this, 0);
    emptyCard->body()->addWidget(empty_);
    empty_->setParent(emptyCard);
    body()->addWidget(emptyCard);
    empty_->setProperty("card", QVariant());

    split_ = new QWidget(this);
    splitLayout_ = new QBoxLayout(QBoxLayout::LeftToRight, split_);
    splitLayout_->setContentsMargins(0, 0, 0, 0);
    splitLayout_->setSpacing(Space::L);

    listCard_ = new Card(nullptr, 0);
    auto* listInner = new QWidget();
    list_ = new QVBoxLayout(listInner);
    list_->setContentsMargins(0, 6, 0, 6);
    list_->setSpacing(0);
    noMatch_ = makeLabel(TR("Nothing matches the filter."), "muted");
    noMatch_->setContentsMargins(28, 18, 16, 18);
    noMatch_->setVisible(false);
    list_->addWidget(noMatch_);
    list_->addStretch(1);
    auto* listScroll = MakeScroll(listInner);
    static_cast<Card*>(listCard_)->body()->addWidget(listScroll);

    auto* detailCard = new Card(nullptr, 0);
    detail_ = new ThreatDetail(window);
    static_cast<Card*>(detailCard)->body()->addWidget(MakeScroll(detail_));
    detailCard->setMinimumWidth(360);

    splitLayout_->addWidget(listCard_, 5);
    splitLayout_->addWidget(detailCard, 4);
    body()->addWidget(split_, 1);

    auto& st = AppState::instance();
    connect(&st, &AppState::itemsReset, this, &ResultsPage::rebuild);
    connect(&st, &AppState::itemAdded, this, [this](int row) {
        // Обычный случай — находка добавилась в конец: дорисовываем одну
        // строку. Пересборка всего списка на каждую находку при сотне
        // угроз превращалась в десять тысяч созданных виджетов.
        if (row != rows_.size()) { rebuild(); return; }
        addRow(row);
        applyFilter();
        if (selected_ < 0) select(row);
        updateHeader();
    });
    connect(&st, &AppState::itemChanged, this, &ResultsPage::updateRow);
    connect(&VirusTotalClient::instance(), &VirusTotalClient::lookupFinished, this,
            [](int asked, QString sha, int malicious, int total, bool found, bool ok, QString error) {
                // Ответ приходит через секунды, а список за это время мог
                // смениться (новая проверка): ищем строку по хэшу, а не
                // верим номеру, с которым уходил запрос.
                const auto& items = AppState::instance().items();
                int row = -1;
                if (asked >= 0 && asked < items.size() &&
                    QString::fromStdString(items[asked].threat.sha256) == sha) {
                    row = asked;
                } else {
                    for (int i = 0; i < items.size(); ++i)
                        if (items[i].vtState == 1 && QString::fromStdString(items[i].threat.sha256) == sha) { row = i; break; }
                }
                if (row < 0) return;
                if (!ok) {
                    AppState::instance().setVirusTotal(row, 5, TR("VirusTotal: the request failed (%1)").arg(error));
                } else if (!found) {
                    AppState::instance().setVirusTotal(row, 4,
                        TR("VirusTotal has never seen this file. For a new or rare file that is normal and is not a verdict."));
                } else if (malicious == 0) {
                    AppState::instance().setVirusTotal(row, 2,
                        TR("VirusTotal: none of %1 antivirus engines flag this file.").arg(total));
                } else {
                    AppState::instance().setVirusTotal(row, 3,
                        TR("VirusTotal: %1 of %2 antivirus engines flag this file.").arg(malicious).arg(total));
                }
            });
    rebuild();
}

void ResultsPage::onShown() {
    rebuild();
}

void ResultsPage::resizeEvent(QResizeEvent* e) {
    Page::resizeEvent(e);
    relayout();
}

void ResultsPage::relayout() {
    // Узкое окно: подробности под списком, а не рядом — иначе обе
    // колонки становятся нечитаемо узкими.
    const bool wide = width() >= 1000;
    if (wide == wide_) return;
    wide_ = wide;
    splitLayout_->setDirection(wide ? QBoxLayout::LeftToRight : QBoxLayout::TopToBottom);
    splitLayout_->setStretch(0, wide ? 5 : 1);
    splitLayout_->setStretch(1, wide ? 4 : 1);
}

void ResultsPage::addRow(int i) {
    const auto& items = AppState::instance().items();
    auto* row = new ThreatRow(i);
    connect(row, &ThreatRow::clicked, this, &ResultsPage::select);

    // Сначала самое опасное; среди равных — в порядке обнаружения. По
    // состоянию не сортируем: строка не должна убегать из-под курсора,
    // когда над находкой выполнили действие.
    const int severity = static_cast<int>(items[i].threat.severity);
    int pos = 0;
    while (pos < order_.size() &&
           static_cast<int>(items[order_[pos]->row()].threat.severity) >= severity)
        ++pos;
    order_.insert(pos, row);
    list_->insertWidget(pos, row);
    rows_ << row;
}

void ResultsPage::rebuild() {
    for (ThreatRow* r : rows_) {
        r->hide();
        list_->removeWidget(r);   // сразу: новые строки встают по номеру места
        r->deleteLater();
    }
    rows_.clear();
    order_.clear();
    const auto& items = AppState::instance().items();
    for (int i = 0; i < items.size(); ++i) addRow(i);
    if (selected_ >= items.size()) selected_ = -1;
    if (selected_ < 0) {
        // По умолчанию — первая сверху находка, которая ждёт решения.
        for (ThreatRow* r : order_)
            if (IsOpen(items[r->row()].threat.status)) { selected_ = r->row(); break; }
        if (selected_ < 0 && !order_.isEmpty()) selected_ = order_.first()->row();
    }
    applyFilter();
    select(selected_);
    updateHeader();
    relayout();
}

void ResultsPage::updateRow(int row) {
    if (row >= 0 && row < rows_.size()) rows_[row]->refresh();
    if (row == selected_) detail_->show(row);
    applyFilter();
    updateHeader();
}

void ResultsPage::select(int row) {
    selected_ = row;
    for (ThreatRow* r : rows_) r->setSelected(r->row() == row);
    detail_->show(row);
}

void ResultsPage::applyFilter() {
    const auto& items = AppState::instance().items();
    const int mode = filter_->current();
    const QString needle = search_->text().trimmed();
    int visible = 0;
    for (ThreatRow* r : rows_) {
        if (r->row() >= items.size()) { r->setVisible(false); continue; }
        const Threat& t = items[r->row()].threat;
        const bool open = IsOpen(t.status);
        bool show = mode == 0 || (mode == 1 && open) || (mode == 2 && !open);
        if (show && !needle.isEmpty()) {
            // Имя, расположение, семейство и тип — то, что человек помнит
            // о находке и по чему её ищет.
            show = QString::fromStdWString(t.name).contains(needle, Qt::CaseInsensitive) ||
                   QString::fromStdWString(t.source).contains(needle, Qt::CaseInsensitive) ||
                   Texts::headline(t).contains(needle, Qt::CaseInsensitive) ||
                   QString::fromStdString(t.sha256).startsWith(needle, Qt::CaseInsensitive);
        }
        r->setVisible(show);
        visible += show;
    }
    const bool any = !items.isEmpty();
    noMatch_->setVisible(any && visible == 0);
    split_->setVisible(any);
    empty_->parentWidget()->setVisible(!any);
}

void ResultsPage::updateHeader() {
    const AppState& st = AppState::instance();
    const int total = st.items().size();
    const int pending = st.pendingCount();
    neutralize_->setVisible(pending > 0);
    neutralize_->setEnabled(!st.scan().running || pending > 0);
    filter_->setVisible(total > 0);
    search_->setVisible(total > 0);
    if (total == 0) {
        setSubtitle(TR("What the last scan found and what you decided to do with it."));
    } else {
        setSubtitle(TR("Found: %1. Waiting for your decision: %2.").arg(total).arg(pending));
    }
}
