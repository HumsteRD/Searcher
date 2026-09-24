#include "HelpPage.h"

#include "../app/Lang.h"
#include "../app/MainWindow.h"

#include <QHBoxLayout>
#include <QVBoxLayout>

using namespace Ui;

namespace {

struct Topic {
    Icons::Id icon;
    const char* title;
    std::initializer_list<const char*> paragraphs;
};

// Одна тема — одна карточка. Отступы у всех одинаковые: заголовок,
// абзацы через 8 px, карточки через 16 px.
QWidget* MakeTopic(const Topic& t) {
    auto* card = new Card(nullptr, 22);
    card->body()->setSpacing(8);
    auto* head = new QHBoxLayout();
    head->setSpacing(12);
    auto* icon = new IconLabel(t.icon, 18, ColorRole::AccentText);
    icon->setTile(true, 34);
    head->addWidget(icon, 0, Qt::AlignTop);
    auto* title = makeLabel(TR(t.title), "heading");
    title->setWordWrap(true);
    head->addWidget(title, 1, Qt::AlignVCenter);
    card->body()->addLayout(head);
    for (const char* p : t.paragraphs) {
        auto* l = makeLabel(TR(p), "body");
        l->setContentsMargins(46, 0, 0, 0);
        card->body()->addWidget(l);
    }
    return card;
}

} // namespace

HelpPage::HelpPage(MainWindow* window)
    : Page(window, TR("Help"), TR("Short answers to the questions that come up in practice."))
{
    const Topic topics[] = {
        { Icons::Id::Scan, "Which scan to choose",
          { "Quick scan checks running programs, startup items and the folders where malware usually ends up. "
            "It takes a few minutes and is enough for regular use.",
            "Full scan goes through every file on every local drive. Run it when you suspect an infection or "
            "after the quick scan found something.",
            "To check one file, just drag it into the window. The verdict appears in seconds and does not need "
            "administrator rights." } },
        { Icons::Id::Alert, "What to do with a finding",
          { "Open Results and select the finding: it says what kind of threat it is, why it was flagged and "
            "what to do.",
            "Quarantine is the right choice in most cases: the file stops working but can be restored if it was a "
            "mistake. For a startup entry or a scheduled task, the entry is removed and the file it launches is "
            "quarantined.",
            "Skip leaves the finding as it is. Trust tells future scans to ignore exactly this file." } },
        { Icons::Id::Quarantine, "How quarantine works",
          { "A quarantined file is moved into a protected folder and scrambled, so it cannot run and other "
            "antivirus programs do not react to it.",
            "Restore puts the file back where it was. Delete removes it for good." } },
        { Icons::Id::Database, "How threats are detected",
          { "Every file is compared with a database of about 800 thousand known malicious files from "
            "MalwareBazaar. An exact match is a reliable verdict.",
            "Contents are checked against thousands of YARA signatures from YARA-Forge. Archives and Python "
            "programs packed with PyInstaller are unpacked and checked inside.",
            "Files signed by known vendors such as Microsoft, NVIDIA or Google are not flagged by signatures: that "
            "is what caused false alarms in the past." } },
        { Icons::Id::Lock, "Why administrator rights are needed",
          { "Reading other programs' processes, system startup entries and protected folders, and moving files "
            "into quarantine requires administrator rights. The window itself runs without them.",
            "Windows asks once per session. After that, a separate helper does the privileged work until you "
            "close the program." } },
        { Icons::Id::Download, "Download monitoring",
          { "While the program is open or in the tray, new files in Downloads and on the desktop are checked as "
            "soon as the browser finishes downloading them. If something dangerous arrives, you get a "
            "notification right away." } },
        { Icons::Id::Cube, "Behavior and Windows Sandbox",
          { "Behavior runs a file in Windows Sandbox, a disposable copy of Windows, and shows what it did: files, "
            "registry, processes, network. Nothing it does reaches your computer.",
            "Windows Sandbox exists only in Pro, Enterprise and Education editions. On Home it cannot be "
            "installed; the rest of the program works as usual." } },
        { Icons::Id::Info, "If a legitimate program is flagged",
          { "Mistakes happen, especially with rare or self-made programs. Check the file on VirusTotal from the "
            "finding card: if almost no antivirus engines flag it, it is most likely safe.",
            "Mark it as trusted, or restore it from quarantine. You can also exclude a whole folder in Settings." } },
        { Icons::Id::ArrowUp, "Updates",
          { "Signature databases update themselves once a day. New versions of the program are offered when they "
            "come out; in Settings you can let them install automatically." } },
    };
    for (const Topic& t : topics) body()->addWidget(MakeTopic(t));
    body()->addStretch(1);
}
