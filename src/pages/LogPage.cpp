#include "LogPage.h"

#include "../app/Lang.h"
#include "../app/MainWindow.h"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QScrollBar>
#include <QStandardPaths>
#include <QTextStream>
#include <QVBoxLayout>

using namespace Ui;

LogPage::LogPage(MainWindow* window)
    : Page(window, TR("Log"), TR("A technical record of what the program and its helper did. "
                                 "Useful if something went wrong."))
{
    setScrollable(false);
    search_ = new QLineEdit();
    search_->setPlaceholderText(TR("Search the log"));
    search_->setClearButtonEnabled(true);
    search_->setFixedWidth(220);
    actions()->addWidget(search_);
    filter_ = new Segmented({ TR("All"), TR("Warnings"), TR("Errors") });
    actions()->addWidget(filter_);
    auto* copy = new Button(TR("Copy"), Button::Variant::Secondary);
    copy->setIconId(Icons::Id::Copy);
    auto* save = new Button(TR("Save…"), Button::Variant::Secondary);
    save->setIconId(Icons::Id::Download);
    actions()->addWidget(copy);
    actions()->addWidget(save);

    auto* card = new Card(this, 1);
    view_ = new QPlainTextEdit();
    view_->setReadOnly(true);
    view_->setFont(Font::mono(12));
    view_->setLineWrapMode(QPlainTextEdit::NoWrap);
    view_->setStyleSheet("QPlainTextEdit { border: none; background: transparent; }");
    view_->setMaximumBlockCount(5000);
    card->body()->addWidget(view_);
    body()->addWidget(card, 1);

    connect(filter_, &Segmented::currentChanged, this, &LogPage::rebuild);
    connect(search_, &QLineEdit::textChanged, this, &LogPage::rebuild);
    connect(copy, &QPushButton::clicked, this, [this]() { QApplication::clipboard()->setText(view_->toPlainText()); });
    connect(save, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getSaveFileName(this, TR("Save the log"),
            QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/ThreatScanner-log.txt",
            TR("Text files (*.txt)"));
        if (path.isEmpty()) return;
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            this->window()->toast("CRIT", TR("Could not save the log"), f.errorString());
            return;
        }
        QTextStream out(&f);
        out.setEncoding(QStringConverter::Utf8);
        out.setGenerateByteOrderMark(true);
        // В файл идёт то, что на экране: если включён фильтр или поиск,
        // сохраняют обычно именно найденное.
        out << view_->toPlainText() << "\n";
    });
    connect(window, &MainWindow::logAppended, this, &LogPage::append);
    connect(window, &MainWindow::searchRequested, this, [this]() {
        if (!isVisible()) return;
        search_->setFocus();
        search_->selectAll();
    });
    rebuild();
}

void LogPage::onShown() {}

bool LogPage::passes(const QString& line, const QString& level) const {
    switch (filter_->current()) {
    case 1:  if (level != "WRN" && level != "ERR") return false; break;
    case 2:  if (level != "ERR") return false; break;
    default: break;
    }
    const QString needle = search_->text().trimmed();
    return needle.isEmpty() || line.contains(needle, Qt::CaseInsensitive);
}

void LogPage::rebuild() {
    // Одной вставкой: добавление пяти тысяч строк по одной заметно
    // подвешивало страницу на каждой букве поиска.
    QStringList shown;
    for (const QString& line : window()->logLines()) {
        if (passes(line, line.mid(9, 3))) shown << line;
    }
    view_->setPlainText(shown.join('\n'));
    QScrollBar* sb = view_->verticalScrollBar();
    sb->setValue(sb->maximum());
}

void LogPage::append(const QString& line, const QString& level) {
    if (!passes(line, level)) return;
    QScrollBar* sb = view_->verticalScrollBar();
    const bool atEnd = sb->value() >= sb->maximum() - 4;
    view_->appendPlainText(line);
    if (atEnd) sb->setValue(sb->maximum());
}
