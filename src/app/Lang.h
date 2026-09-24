#pragma once

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>

// Локализация интерфейса.
//
// Ключ — английская строка, она же английский перевод: непереведённое
// место показывается осмысленным английским, а не пустотой. Русский
// словарь — в LangRu.cpp. Режим снимков экрана (--shots) собирает ключи
// без перевода и пишет их в файл — так пропуски видно до релиза.
class Lang : public QObject {
    Q_OBJECT

public:
    enum class Id { En, Ru };

    static Lang& instance();

    Id   current() const { return current_; }
    void setLanguage(Id id);          // сохраняет выбор и шлёт languageChanged

    QString translate(const QString& key) const;

    // Ключи, для которых не нашлось перевода (только при включённом учёте).
    void trackMissing(bool on) { track_ = on; }
    QSet<QString> missing() const { return missing_; }

    // Язык системы: русский, если интерфейс Windows русский.
    static Id systemDefault();

signals:
    void languageChanged();

private:
    Lang();

    Id current_ = Id::Ru;
    QHash<QString, QString> ru_;
    bool track_ = false;
    mutable QSet<QString> missing_;
};

inline QString TR(const QString& key) {
    return Lang::instance().translate(key);
}

// Существительное при числе: в русском три формы, в английском две.
// TRN(4, "file", "files", "файл", "файла", "файлов") → «файла».
QString TRN(qint64 count, const QString& enOne, const QString& enMany,
            const QString& ruOne, const QString& ruFew, const QString& ruMany);

// Заполнение русского словаря — в LangRu.cpp.
void FillRussian(QHash<QString, QString>& dict);
