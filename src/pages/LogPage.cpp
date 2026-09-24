#include "LogPage.h"

#include "../app/Lang.h"
#include "../app/MainWindow.h"

#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QFileDialog>
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
    connect(copy, &QPushButton::clicked, this, [this]() { QApplication::clipboard()->setText(view_->toPlainText()); });
    connect(save, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getSaveFileName(this, TR("Save the log"),
            QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/ThreatScanner-log.txt",
            TR("Text files (*.txt)"));
        if (path.isEmpty()) return;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&f);
            out.setEncoding(QStringConverter::Utf8);
            for (const QString& l : this->window()->logLines()) out << l << "\n";
        }
    });
    connect(window, &MainWindow::logAppended, this, &LogPage::append);
    rebuild();
}

void LogPage::onShown() {}

bool LogPage::passes(const QString& level) const {
    switch (filter_->current()) {
    case 1:  return level == "WRN" || level == "ERR";
    case 2:  return level == "ERR";
    default: return true;
    }
}

void LogPage::rebuild() {
    view_->clear();
    for (const QString& line : window()->logLines()) {
        const QString level = line.mid(9, 3);
        if (passes(level)) view_->appendPlainText(line);
    }
}

void LogPage::append(const QString& line, const QString& level) {
    if (!passes(level)) return;
    QScrollBar* sb = view_->verticalScrollBar();
    const bool atEnd = sb->value() >= sb->maximum() - 4;
    view_->appendPlainText(line);
    if (atEnd) sb->setValue(sb->maximum());
}
