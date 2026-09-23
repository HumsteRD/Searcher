#pragma once

#include <QObject>
#include <QString>
#include <QHash>

// Локализация интерфейса.
//
// Ключом служит английская строка — она же и есть английский перевод,
// поэтому непереведённое место деградирует в осмысленный английский,
// а не в пустоту или в «MISSING_KEY».
class Lang : public QObject {
    Q_OBJECT

public:
    enum class Id { En, Ru };

    static Lang& instance();

    Id   current() const { return current_; }
    void setLanguage(Id id);

    // Перевод. Вызывать через макрос TR() ниже.
    QString translate(const QString& key) const;

signals:
    void languageChanged();

private:
    Lang();

    Id current_ = Id::En;
    QHash<QString, QString> ru_;
};

// Короткая форма. Намеренно не tr(): у нас нет .qm-файлов,
// словарь лежит в коде и переключается без перезапуска.
inline QString TR(const QString& key) {
    return Lang::instance().translate(key);
}

// Существительное при числе. В русском форм три, в английском две, общего
// правила нет — поэтому вызывающий передаёт все формы сразу.
// TRN(4, "process", "processes", "процесс", "процесса", "процессов")
QString TRN(int count, const QString& enOne, const QString& enMany,
            const QString& ruOne, const QString& ruFew, const QString& ruMany);
