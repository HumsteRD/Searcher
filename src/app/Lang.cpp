#include "Lang.h"

#include <QLocale>
#include <QSettings>

Lang& Lang::instance() {
    static Lang* l = new Lang();
    return *l;
}

Lang::Id Lang::systemDefault() {
    return QLocale::system().language() == QLocale::Russian ? Id::Ru : Id::En;
}

Lang::Lang() {
    QSettings store("ThreatScanner", "ThreatScanner");
    const QString stored = store.value("ui/language").toString();
    if (stored == "ru")      current_ = Id::Ru;
    else if (stored == "en") current_ = Id::En;
    else                     current_ = systemDefault();
    FillRussian(ru_);
}

void Lang::setLanguage(Id id) {
    if (id == current_) return;
    current_ = id;
    QSettings store("ThreatScanner", "ThreatScanner");
    store.setValue("ui/language", id == Id::Ru ? "ru" : "en");
    emit languageChanged();
}

QString Lang::translate(const QString& key) const {
    if (current_ == Id::En) return key;
    auto it = ru_.constFind(key);
    if (it != ru_.constEnd()) return *it;
    if (track_ && !key.trimmed().isEmpty()) missing_.insert(key);
    return key;
}

QString TRN(qint64 count, const QString& enOne, const QString& enMany,
            const QString& ruOne, const QString& ruFew, const QString& ruMany)
{
    if (Lang::instance().current() == Lang::Id::En) return count == 1 ? enOne : enMany;
    const qint64 n = count < 0 ? -count : count;
    const qint64 mod100 = n % 100, mod10 = n % 10;
    if (mod100 >= 11 && mod100 <= 14) return ruMany;
    if (mod10 == 1) return ruOne;
    if (mod10 >= 2 && mod10 <= 4) return ruFew;
    return ruMany;
}
