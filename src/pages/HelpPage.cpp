#include "HelpPage.h"
#include "PageHelpers.h"
#include "../theme.h"
#include "../core/Lang.h"

#include <QVBoxLayout>
#include <QLabel>
#include <QFrame>
#include <QScrollArea>

namespace {

// Оба языка держим здесь, а не в общем словаре: ключом там служит
// английская строка, и для абзацев на 600 знаков такое сопоставление
// ломается от любой правки пробела.
struct Entry {
    const char* titleEn;
    const char* bodyEn;
    const char* titleRu;
    const char* bodyRu;
};

const Entry kEntries[] = {
{
    "What does a scan actually check?",
    "Five independent modules run one after another.\n\n"
    "• Registry — the keys Windows uses to start programs automatically. "
    "Malware hides here to survive a reboot.\n"
    "• Files — executables in folders where droppers usually land: Temp, "
    "AppData, ProgramData.\n"
    "• Processes — programs running right now, including ones whose parent "
    "process looks wrong.\n"
    "• Network — open TCP connections, matched against known mining pools.\n"
    "• Scheduled tasks — jobs that run on a timer, another classic way to "
    "survive a reboot.\n\n"
    "Nothing is deleted during a scan. The scan only looks.",

    "Что именно проверяется?",
    "Последовательно отрабатывают пять независимых модулей.\n\n"
    "• Реестр — ключи, из которых Windows запускает программы автоматически. "
    "Вредоносное ПО прячется здесь, чтобы пережить перезагрузку.\n"
    "• Файлы — исполняемые файлы в папках, куда обычно попадают загрузчики: "
    "Temp, AppData, ProgramData.\n"
    "• Процессы — то, что запущено прямо сейчас, включая процессы с "
    "подозрительным родителем.\n"
    "• Сеть — открытые TCP-соединения, сверяются с известными пулами майнинга.\n"
    "• Задачи планировщика — то, что запускается по расписанию: ещё один "
    "классический способ пережить перезагрузку.\n\n"
    "Во время проверки ничего не удаляется. Проверка только смотрит."
},
{
    "What do the severity levels mean?",
    "CRITICAL — matches a known malicious file by its SHA-256 hash. "
    "This is not a guess.\n"
    "HIGH — the name or location matches a well-known malware pattern.\n"
    "MEDIUM — an executable sits somewhere legitimate programs normally "
    "do not.\n"
    "LOW and INFO — worth a look, but on their own they mean little.\n\n"
    "A finding is a suspicion, not a verdict. Plenty of legitimate installers "
    "and game launchers land in Temp.",

    "Что значат уровни опасности?",
    "CRIT — совпадение с известным вредоносным файлом по хэшу SHA-256. "
    "Это не предположение, а точное совпадение.\n"
    "HIGH — имя или расположение совпадает с известным почерком вредоносных "
    "программ.\n"
    "MED — исполняемый файл лежит там, где обычные программы не лежат.\n"
    "LOW и INFO — стоит взглянуть, но сами по себе значат мало.\n\n"
    "Находка — это подозрение, а не приговор. В Temp попадает множество "
    "совершенно законных установщиков и игровых лаунчеров."
},
{
    "Quarantine or delete — what is the difference?",
    "Quarantine moves the file into a protected folder and scrambles its "
    "contents, so it can no longer run and no other antivirus will treat it "
    "as an active threat. The file stays recoverable: one click on Restore "
    "puts it back exactly where it was.\n\n"
    "Delete erases the file from disk. There is no way back.\n\n"
    "If you are not sure — choose Quarantine. That is what it exists for.\n\n"
    "For registry entries and scheduled tasks there is nothing to store, so "
    "the button is labelled Remove and the action is permanent.",

    "Карантин или удаление — в чём разница?",
    "Карантин переносит файл в защищённую папку и перемешивает его содержимое, "
    "так что запуститься он больше не может, и другие антивирусы не считают "
    "его активной угрозой. Файл при этом остаётся возвратным: одно нажатие "
    "«Восстановить» вернёт его ровно туда, где он был.\n\n"
    "Удаление стирает файл с диска. Обратного пути нет.\n\n"
    "Если сомневаетесь — выбирайте карантин. Он ровно для этого и нужен.\n\n"
    "У записей реестра и задач планировщика хранить нечего, поэтому там кнопка "
    "называется «Удалить запись», и действие необратимо."
},
{
    "How do I read the VirusTotal column?",
    "VirusTotal runs a file through dozens of antivirus engines at once and "
    "reports how many of them object.\n\n"
    "\"Clean · 0 of 74\" — none of the 74 engines consider the file dangerous.\n"
    "\"12 of 74 flagged\" — twelve do. One or two detections are often a false "
    "positive; a dozen almost never is.\n"
    "\"Unknown\" — VirusTotal has never seen this file. Normal for freshly "
    "built or rare software, and not a verdict by itself.\n"
    "\"—\" — the item has no file hash to look up, for example a registry entry.\n\n"
    "Only the file's hash is sent, never the file itself.",

    "Как читать столбец VirusTotal?",
    "VirusTotal прогоняет файл сразу через десятки антивирусов и сообщает, "
    "сколько из них возражают.\n\n"
    "«Clean · 0 of 74» — ни один из 74 антивирусов не считает файл опасным.\n"
    "«12 of 74 flagged» — двенадцать считают. Одно-два срабатывания часто "
    "оказываются ложными, дюжина — почти никогда.\n"
    "«Неизвестен» — VirusTotal никогда не встречал этот файл. Это нормально "
    "для свежесобранных или редких программ и само по себе не приговор.\n"
    "«—» — у объекта нет хэша для проверки, например у записи реестра.\n\n"
    "Отправляется только хэш файла, сам файл — никогда."
},
{
    "What is deep scan?",
    "By default the file module only computes a hash for files that already "
    "look suspicious by name or location. Deep scan computes the hash for "
    "every executable it meets and walks deeper into the folder tree.\n\n"
    "It catches known malware that carries a harmless name in a harmless "
    "place — at the cost of taking noticeably longer.",

    "Что такое глубокая проверка?",
    "Обычно файловый модуль считает хэш только для файлов, уже подозрительных "
    "по имени или расположению. В глубоком режиме хэш считается для каждого "
    "встреченного исполняемого файла, а обход дерева папок идёт глубже.\n\n"
    "Так ловятся известные вредоносные файлы с безобидным именем в безобидном "
    "месте — ценой заметно большего времени работы."
},
{
    "Why does the app ask for administrator rights?",
    "Without them it cannot read the system-wide registry branch, inspect "
    "processes owned by other users, or list scheduled tasks. The scan would "
    "silently miss exactly the places where persistent malware prefers to live.",

    "Зачем нужны права администратора?",
    "Без них нельзя прочитать общесистемную ветку реестра, заглянуть в чужие "
    "процессы и получить список задач планировщика. Проверка молча пропускала "
    "бы ровно те места, где закрепляется вредоносное ПО."
},
};

bool isRu() { return Lang::instance().current() == Lang::Id::Ru; }

} // namespace

HelpPage::HelpPage(QWidget* parent) : QWidget(parent) {
    setStyleSheet("background: transparent;");

    QVBoxLayout* outer = new QVBoxLayout(this);
    outer->setContentsMargins(Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_TOP,
                              Theme::Size::PAGE_PAD_X, Theme::Size::PAGE_PAD_X);
    outer->setSpacing(Theme::Space::M);

    outer->addWidget(PageHelpers::pageTitle(TR("Help"), this));
    outer->addWidget(PageHelpers::pageSubtitle(
        isRu() ? "Простыми словами: что делает этот инструмент "
                 "и что означают его результаты."
               : "Plain answers about what this tool does and what its "
                 "results mean.",
        this));
    outer->addSpacing(Theme::Space::S);

    QScrollArea* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background: transparent;");
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    QWidget* content = new QWidget(scroll);
    content->setStyleSheet("background: transparent;");
    QVBoxLayout* lay = new QVBoxLayout(content);
    lay->setContentsMargins(0, 0, Theme::Space::S, 0);
    lay->setSpacing(Theme::Space::S);

    for (const Entry& e : kEntries) {
        addSection(lay,
                   isRu() ? e.titleRu : e.titleEn,
                   isRu() ? e.bodyRu  : e.bodyEn);
    }
    lay->addStretch();

    scroll->setWidget(content);
    outer->addWidget(scroll, 1);
}

void HelpPage::addSection(QVBoxLayout* root, const QString& title,
                          const QString& body)
{
    QFrame* card = PageHelpers::card(this, Theme::Radius::CARD);
    QVBoxLayout* lay = new QVBoxLayout(card);
    lay->setContentsMargins(Theme::Space::XL, Theme::Space::L,
                            Theme::Space::XL, Theme::Space::L);
    lay->setSpacing(Theme::Space::XS);

    QLabel* t = new QLabel(title, card);
    t->setWordWrap(true);
    t->setStyleSheet(QString(
        "color: %1; font-size: %2px; font-weight: 600;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_PRIMARY).arg(Theme::Font::CARD));
    lay->addWidget(t);

    QLabel* b = new QLabel(body, card);
    b->setWordWrap(true);
    b->setTextFormat(Qt::PlainText);
    b->setStyleSheet(QString(
        "color: %1; font-size: %2px;"
        "background: transparent; border: none;"
    ).arg(Theme::TEXT_SECONDARY).arg(Theme::Font::BODY));
    lay->addWidget(b);

    // Карточка не должна сжиматься ниже своего текста, иначе абзацы
    // обрежутся, когда справка не влезает в окно.
    card->setMinimumHeight(card->sizeHint().height());
    root->addWidget(card);
}
