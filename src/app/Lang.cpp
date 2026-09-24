#include "Lang.h"
#include "AppSettings.h"

#include <QSettings>

Lang& Lang::instance() {
    static Lang* l = new Lang();
    return *l;
}

Lang::Lang() {
    QSettings store("ThreatScanner", "ThreatScanner");
    current_ = store.value("ui/language", "en").toString() == "ru"
             ? Id::Ru : Id::En;

    ru_ = {
        // ─── Навигация и каркас ───
        { "Home",        "Главная" },
        { "Behavior",    "Поведение" },
        { "Scan",        "Проверка" },
        { "Threats",     "Угрозы" },
        { "Quarantine",  "Карантин" },
        { "Logs",        "Журнал" },
        { "Settings",    "Настройки" },
        { "Help",        "Справка" },
        { "History",     "История" },
        { "Past scans are kept between sessions. Open a report to see what "
          "each scan found.",
          "Прошлые проверки сохраняются между запусками. Откройте отчёт, "
          "чтобы посмотреть, что нашла каждая из них." },
        { "Clear history", "Очистить историю" },
        { "Delete all saved scan records? The scans themselves are "
          "not affected — only this list.",
          "Удалить все сохранённые записи о проверках? На сами проверки "
          "это не влияет — очищается только список." },
        { "Date", "Дата" },
        { "Mode", "Режим" },
        { "Duration", "Длительность" },
        { "Objects checked", "Проверено объектов" },
        { "Threats found", "Найдено угроз" },
        { "Export", "Отчёт" },
        { "Save report", "Сохранить отчёт" },
        { "Could not write the file.", "Не удалось записать файл." },
        { "No scans yet", "Проверок ещё не было" },
        { "Once you run a scan, its result is saved here.",
          "Как только вы запустите проверку, её результат появится здесь." },
        { "critical", "критических" },
        { "Scan report", "Отчёт о проверке" },
        { "Nothing suspicious was found.", "Ничего подозрительного не найдено." },
        { "Scan was cancelled before it finished.",
          "Проверка была прервана до завершения." },

        // ─── Главная ───
        { "SYSTEM STATUS", "СОСТОЯНИЕ СИСТЕМЫ" },
        { "OVERVIEW",      "СВОДКА" },
        { "System is protected",        "Система защищена" },
        { "Threats detected",           "Обнаружены угрозы" },
        { "Critical threats detected!", "Обнаружены критические угрозы!" },
        { "No scan has been performed yet", "Проверка ещё не выполнялась" },
        { "Start scan",    "Начать проверку" },
        { "THREATS FOUND", "НАЙДЕНО УГРОЗ" },
        { "FILES SCANNED", "ПРОВЕРЕНО ОБЪЕКТОВ" },
        { "IN QUARANTINE", "В КАРАНТИНЕ" },
        { "No scan yet",        "Проверок ещё не было" },
        { "No action required", "Действий не требуется" },
        { "None critical",      "Критических нет" },
        { "Objects inspected",  "Проверено объектов" },
        { "Isolated files",     "Изолированных файлов" },

        // ─── Проверка ───
        { "Run a full system scan to detect threats across registry, files, "
          "processes, scheduled tasks and network connections.",
          "Полная проверка системы: реестр, файлы, процессы, "
          "задачи планировщика и сетевые соединения." },
        { "STATUS",        "СОСТОЯНИЕ" },
        { "Ready to scan", "Готов к проверке" },
        { "Scanning…",     "Идёт проверка…" },
        { "Scan complete", "Проверка завершена" },
        { "Cancel",        "Отмена" },
        { "CRITICAL",      "КРИТИЧЕСКИХ" },
        { "objects checked", "объектов проверено" },
        { "elapsed",       "прошло" },
        { "about",         "примерно" },
        { "left",          "осталось" },
        { "min",           "мин" },
        { "s",             "с" },

        { "SCAN SCOPE",  "ОБЛАСТЬ ПРОВЕРКИ" },
        { "MODULES",     "МОДУЛИ" },
        { "Quick",       "Быстрая" },
        { "Full",        "Полная" },
        { "Folder",      "Папка" },
        { "Choose folder…",        "Выбрать папку…" },
        { "Choose file…",          "Выбрать файл…" },
        { "Folder…",               "Папку…" },
        { "File…",                 "Файл…" },
        { "Nothing chosen yet",    "Пока ничего не выбрано" },
        { "Choose file to scan",   "Выберите файл для проверки" },
        { "All files (*)",         "Все файлы (*)" },
        { "Choose folder to scan", "Выберите папку для проверки" },
        { "No folder chosen yet",  "Папка ещё не выбрана" },
        { "Registry",  "Реестр" },
        { "Files",     "Файлы" },
        { "Processes", "Процессы" },
        { "Network",   "Сеть" },
        { "Scheduled tasks", "Задачи планировщика" },
        { "Scripts",     "Скрипты" },
        { "System persistence", "Закрепление в системе" },
        { "The hosts file redirects a security or update domain — this is how "
          "malware cuts the machine off from antivirus updates.",
          "Файл hosts перенаправляет адрес антивируса или службы обновлений — "
          "так вредоносное ПО отрезает машину от обновлений защиты." },
        { "Open the hosts file and remove this line if you did not add it "
          "yourself.",
          "Откройте файл hosts и удалите эту строку, если добавляли не вы." },
        { "A Windows service runs from a user or temporary folder. Software "
          "installed normally does not live there.",
          "Служба Windows запускается из пользовательской или временной папки. "
          "Нормально установленные программы там не живут." },
        { "Check what installed this service before removing it.",
          "Выясните, что установило эту службу, прежде чем удалять." },
        { "A WMI subscription runs a command when a system event happens. It "
          "survives reboots and is not visible in startup lists or Task "
          "Scheduler.",
          "Подписка WMI запускает команду при системном событии. Она переживает "
          "перезагрузку и не видна ни в автозагрузке, ни в планировщике задач." },
        { "Unless you set this up yourself, treat it as malicious persistence.",
          "Если это настраивали не вы — считайте закреплением вредоносного ПО." },
        { "Quick: the three riskiest folders, shallow depth. Takes seconds.",
          "Быстрая: три самые рискованные папки, малая глубина. Занимает секунды." },
        { "Full: every risky folder in the list. Takes the longest.",
          "Полная: все рискованные папки из списка. Занимает больше всего времени." },
        { "Folder: only the folder you picked, scanned deeply.",
          "Папка: только выбранная вами папка, зато с полной глубиной." },
        { "All modules are off — there is nothing to scan.",
          "Все модули выключены — проверять нечего." },
        { "Modules enabled: %1 of 7.", "Включено модулей: %1 из 7." },

        // ─── Угрозы ───
        { "Detected suspicious items across registry, files and processes. "
          "Double-click a row to see why it was flagged.",
          "Подозрительные объекты в реестре, файлах и процессах. "
          "Дважды щёлкните по строке, чтобы увидеть, почему она помечена." },
        { "Severity",   "Уровень" },
        { "Name",       "Название" },
        { "Source",     "Расположение" },
        { "VirusTotal", "VirusTotal" },
        { "Status",     "Статус" },
        { "Actions",    "Действия" },
        { "Check all on VirusTotal",  "Проверить всё в VirusTotal" },
        { "Quarantine all critical",  "Все критические в карантин" },
        { "Remove",     "Удалить запись" },
        { "Delete",     "Удалить" },
        { "Ignore",     "Пропустить" },
        { "Pending",     "Ожидает" },
        { "Quarantined", "В карантине" },
        { "Deleted",     "Удалено" },
        { "Ignored",     "Пропущено" },
        { "Failed",      "Ошибка" },
        { "Not checked", "Не проверено" },
        { "Why it was flagged", "Почему помечено" },
        { "No details available.", "Подробностей нет." },
        { "Close", "Закрыть" },
        { "Checking…",   "Проверяем…" },
        { "Unknown",     "Неизвестен" },
        { "Error",       "Ошибка" },
        { "No API key",  "Нет ключа" },
        { "No threats yet.\nRun a scan from the Scan tab to see results here.",
          "Угроз пока нет.\nЗапустите проверку на вкладке «Проверка»." },

        { "No threats found", "Угроз не найдено" },
        { "Run a scan to see results here.",
          "Запустите проверку, чтобы увидеть результаты." },

        // ─── Карантин ───
        { "Files moved here are isolated and obfuscated. "
          "You can restore them or delete permanently.",
          "Файлы здесь изолированы и обезврежены. "
          "Их можно вернуть на место или удалить навсегда." },
        { "Open folder", "Открыть папку" },
        { "Refresh",     "Обновить" },
        { "Restore",     "Восстановить" },
        { "File",        "Файл" },
        { "Threat",      "Угроза" },
        { "Original location", "Откуда изъят" },
        { "Quarantined at",    "Помещён" },
        { "Size",        "Размер" },
        { "Quarantine is empty", "Карантин пуст" },
        { "When you quarantine a threat, it will appear here.\n"
          "Quarantined items are safely stored and can be restored at any time.",
          "Когда вы отправите угрозу в карантин, она появится здесь.\n"
          "Файлы хранятся безопасно, вернуть их можно в любой момент." },

        // ─── Журнал ───
        { "Detailed information about scans, modules and detected events.",
          "Подробности о проверках, модулях и найденных событиях." },
        { "Clear log", "Очистить журнал" },

        // ─── Настройки ───
        { "Configure scan behavior and external integrations.",
          "Поведение проверки и внешние сервисы." },
        { "INTEGRATIONS",  "ИНТЕГРАЦИИ" },
        { "SCAN BEHAVIOR", "ПОВЕДЕНИЕ ПРОВЕРКИ" },
        { "INTERFACE",     "ИНТЕРФЕЙС" },
        { "AUTOMATION",    "АВТОМАТИЗАЦИЯ" },
        { "SIGNATURES",    "СИГНАТУРЫ" },
        { "Checking dropped file: ",   "Проверяю перетащенный файл: " },
        { "Checking dropped folder: ", "Проверяю перетащенную папку: " },
        { "A scan is already running — drop ignored.",
          "Проверка уже идёт — перетаскивание пропущено." },
        { "Drag a file or folder onto the window to check just that.",
          "Перетащите файл или папку в окно, чтобы проверить только их." },
        { "Signature database", "База сигнатур" },
        { "Built-in signatures always apply. You can add your own in a JSON "
          "file with hashes, file-name patterns and mining pools — your "
          "entries are added on top, never replacing the built-in ones.",
          "Встроенные сигнатуры действуют всегда. Свои можно добавить в "
          "JSON-файл: хэши, шаблоны имён и адреса пулов. Ваши записи "
          "добавляются поверх и никогда не отменяют встроенные." },
        { "Reload",    "Перечитать" },
        { "Open file", "Открыть файл" },
        { "No custom signature file yet — only built-in signatures are in use.",
          "Своего файла сигнатур пока нет — работают только встроенные." },
        { "Loaded from your file: %1 hashes, %2 name patterns, %3 pools.",
          "Из вашего файла загружено: хэшей %1, шаблонов имён %2, пулов %3." },
        { "Autostart",     "Автозапуск" },
        { "Start with Windows", "Запускать вместе с Windows" },
        { "Launch Threat Scanner when you sign in to Windows.",
          "Запускать Threat Scanner при входе в Windows." },
        { "Tray icon",     "Значок в трее" },
        { "Keep running in the tray", "Продолжать работу в трее" },
        { "Closing the window hides it to the tray instead of quitting, "
          "so scheduled scans keep working.",
          "Закрытие окна будет прятать его в трей, а не завершать программу, "
          "чтобы проверки по расписанию продолжали работать." },
        { "Scheduled scan", "Проверка по расписанию" },
        { "Runs a scan automatically at the chosen hour. The app must be "
          "running — enable autostart and the tray icon for it to be reliable.",
          "Запускает проверку в выбранный час. Приложение должно быть "
          "запущено — для надёжности включите автозапуск и значок в трее." },
        { "Off",         "Выключено" },
        { "Every day",   "Каждый день" },
        { "Every week",  "Каждую неделю" },
        { "Open Threat Scanner", "Открыть Threat Scanner" },
        { "Quit",        "Выйти" },
        { "Scan finished — nothing suspicious found.",
          "Проверка завершена — ничего подозрительного не найдено." },
        { "Scan finished — %1 threats, %2 of them critical.",
          "Проверка завершена — угроз: %1, из них критических: %2." },
        { "Scan finished — %1 threats found.",
          "Проверка завершена — найдено угроз: %1." },
        { "Scan cancellation requested", "Запрошена отмена проверки" },
        { "Language",      "Язык" },
        { "Interface language. Applies immediately.",
          "Язык интерфейса. Применяется сразу." },
        { "VirusTotal API key", "Ключ VirusTotal" },
        { "Paste your VirusTotal API key here", "Вставьте сюда ключ VirusTotal" },
        { "Test key", "Проверить ключ" },
        { "Optional. Adds cloud-based threat verification. Get a free key at "
          "virustotal.com. Free keys allow 4 lookups per minute, so checks are queued.",
          "Необязательно. Добавляет облачную проверку файлов. Бесплатный ключ "
          "выдают на virustotal.com. Он допускает 4 запроса в минуту, поэтому "
          "проверки выстраиваются в очередь." },
        { "Deep scan", "Глубокая проверка" },
        { "Enable deep file scanning (slower, more thorough)",
          "Включить глубокую проверку файлов (медленнее, но тщательнее)" },
        { "Computes SHA-256 hashes of all files in hot directories. "
          "Slower but more reliable for catching known malware.",
          "Считает SHA-256 для всех файлов в рискованных папках. "
          "Медленнее, но надёжнее находит уже известные вредоносные файлы." },
        { "Auto-quarantine", "Авто-карантин" },
        { "Automatically quarantine critical threats",
          "Автоматически отправлять критические угрозы в карантин" },
        { "When enabled, threats marked as Critical will be moved to quarantine "
          "without asking.",
          "Критические угрозы будут отправляться в карантин без вопросов." },
        { "API key works", "Ключ работает" },
        { "Invalid API key.", "Неверный ключ." },
        { "Enter an API key first.", "Сначала введите ключ." },

        { "Last scan: just now — no threats",
          "Последняя проверка: только что — угроз нет" },
        { "Last scan: just now — threats found: %1",
          "Последняя проверка: только что — найдено угроз: %1" },
        { "Scan requested by user", "Проверка запущена пользователем" },
        { "Done", "Готово" },

        { "This cannot be undone", "Отменить это будет нельзя" },
        { "Move %1 critical item(s) to quarantine?",
          "Отправить в карантин критических объектов: %1?" },
        { "Restore this file to its original location?",
          "Вернуть файл на исходное место?" },
        { "The file was flagged as a threat — restore it only if you are "
          "sure it is safe.",
          "Файл был помечен как угроза. Возвращайте его, только если уверены, "
          "что он безопасен." },
        { "Permanently delete this item from quarantine?",
          "Удалить объект из карантина навсегда?" },

        // ─── Правила анализа скриптов ───
        { "line", "строка" },
        { "more", "ещё" },
        { "Downloads code from the internet", "Скачивает код из интернета" },
        { "Downloads a file from the internet", "Скачивает файл из интернета" },
        { "Downloads something from the internet", "Что-то скачивает из интернета" },
        { "Downloads a file in the background", "Скачивает файл в фоне" },
        { "Downloads a file using a system tool (a common trick to look legitimate)",
          "Скачивает файл системной утилитой — приём, чтобы выглядеть безобидно" },
        { "Decodes hidden data using a system tool",
          "Расшифровывает спрятанные данные системной утилитой" },
        { "Downloads a file using a system tool",
          "Скачивает файл системной утилитой" },
        { "Runs code built at runtime — the code is not visible in the file",
          "Запускает код, собранный на лету — в файле этого кода не видно" },
        { "Runs a command hidden inside encoded text",
          "Запускает команду, спрятанную в закодированном тексте" },
        { "Decodes hidden text into code or data",
          "Раскодирует спрятанный текст в код или данные" },
        { "Runs without showing any window", "Работает не показывая окна" },
        { "Runs external programs", "Запускает сторонние программы" },
        { "Changes Windows Defender settings",
          "Меняет настройки Защитника Windows" },
        { "Turns off Windows Defender real-time protection",
          "Отключает постоянную защиту Защитника Windows" },
        { "Hides a folder from Windows Defender",
          "Прячет папку от Защитника Windows" },
        { "Disables the Windows anti-malware interface",
          "Отключает системный интерфейс антивирусной проверки" },
        { "Stops Windows Defender", "Останавливает Защитник Windows" },
        { "Changes firewall rules", "Меняет правила брандмауэра" },
        { "Adds itself to Windows startup", "Прописывает себя в автозагрузку" },
        { "Creates a scheduled task so it runs again later",
          "Создаёт задачу в планировщике, чтобы запускаться снова" },
        { "Installs a Windows service", "Устанавливает системную службу" },
        { "Places a file in the startup folder",
          "Кладёт файл в папку автозагрузки" },
        { "Reads the clipboard", "Читает буфер обмена" },
        { "Touches the clipboard — check why",
          "Обращается к буферу обмена — стоит проверить зачем" },
        { "Reads saved browser passwords",
          "Читает сохранённые пароли из браузера" },
        { "Reads browser cookies", "Читает cookie браузера" },
        { "Records keystrokes", "Записывает нажатия клавиш" },
        { "Deletes itself after running", "Удаляет себя после запуска" },
        { "Erases Windows event logs", "Стирает журналы событий Windows" },
        { "Deletes system restore points — typical for ransomware",
          "Удаляет точки восстановления — типично для шифровальщиков" },
        { "Connects to a cryptocurrency mining pool",
          "Подключается к пулу майнинга криптовалюты" },
        { "A long scrambled line — the real content is hidden",
          "Длинная запутанная строка — настоящее содержимое скрыто" },
        { "Open the script and look at the lines above before running it.",
          "Откройте скрипт и посмотрите указанные строки, прежде чем запускать." },

        // ─── Диалоги ───
        { "Delete permanently", "Удалить навсегда" },
        { "Delete this item permanently? This cannot be undone.\n\n"
          "Quarantine is the safer option — it can be restored later.",
          "Удалить объект навсегда? Отменить это будет нельзя.\n\n"
          "Безопаснее отправить в карантин — оттуда файл можно вернуть." },
        { "Remove entry", "Удаление записи" },
        { "This item is not a file, so it cannot be quarantined — "
          "it will be removed permanently.\n\nContinue?",
          "Это не файл, поэтому в карантин его поместить нельзя — "
          "запись будет удалена навсегда.\n\nПродолжить?" },
        { "Restore file", "Восстановление файла" },
        { "Restore failed", "Не удалось восстановить" },
        { "Delete failed",  "Не удалось удалить" },
        { "Could not restore the file. See Logs for details.",
          "Не удалось восстановить файл. Подробности в журнале." },
        { "Could not delete the item. See Logs for details.",
          "Не удалось удалить запись. Подробности в журнале." },

        // ─── Поведение: динамический анализ в песочнице ───
        { "Behavior analysis", "Анализ поведения" },
        { "A file is started inside Windows Sandbox — a throwaway copy of "
          "Windows — and everything it does there is recorded. The sandbox "
          "is discarded afterwards, so nothing it changes touches this "
          "computer.",
          "Файл запускается внутри Windows Sandbox — одноразовой копии "
          "Windows — и всё, что он там делает, записывается. Песочница "
          "потом уничтожается, поэтому её изменения этого компьютера "
          "не касаются." },

        { "Windows Sandbox is ready", "Windows Sandbox готова" },
        { "Windows Sandbox is not available", "Windows Sandbox недоступна" },
        { "Windows Sandbox is not part of Home editions of Windows.",
          "В домашних редакциях Windows компонента Windows Sandbox нет." },
        { "The Windows Sandbox component is not installed.",
          "Компонент Windows Sandbox не установлен." },
        { "Hardware virtualization is disabled in firmware.",
          "Аппаратная виртуализация выключена в прошивке." },
        { "Enable virtualization (Intel VT-x or AMD-V) in the UEFI setup, "
          "then install the Windows Sandbox component.",
          "Включите виртуализацию (Intel VT-x или AMD-V) в настройках UEFI, "
          "затем установите компонент Windows Sandbox." },
        { "Turn on \"Windows Sandbox\" in Windows Features, or run as "
          "administrator: DISM /Online /Enable-Feature "
          "/FeatureName:Containers-DisposableClientVM /All",
          "Включите «Песочница Windows» в компонентах Windows или выполните "
          "от администратора: DISM /Online /Enable-Feature "
          "/FeatureName:Containers-DisposableClientVM /All" },
        { "There is no way to enable it on this edition. Everything "
          "else in the application works as usual.",
          "На этой редакции включить её нельзя. Всё остальное в приложении "
          "работает как обычно." },

        { "SAMPLE", "ОБРАЗЕЦ" },
        { "No file chosen", "Файл не выбран" },
        { "Choose file", "Выбрать файл" },
        { "Choose a file to observe", "Выберите файл для наблюдения" },
        { "Programs and scripts", "Программы и скрипты" },
        { "All files", "Все файлы" },
        { "Give the sandbox network access", "Дать песочнице доступ в сеть" },
        { "Many samples do nothing without it. The traffic is real and "
          "leaves your network, so turn this on deliberately.",
          "Без сети многие образцы просто ничего не делают. Трафик при этом "
          "настоящий и уходит из вашей сети — включайте осознанно." },
        { "Watch for", "Наблюдать" },
        { "15 seconds", "15 секунд" },
        { "30 seconds", "30 секунд" },
        { "1 minute",   "1 минуту" },
        { "2 minutes",  "2 минуты" },
        { "Run in sandbox", "Запустить в песочнице" },

        { "Preparing the isolated session", "Готовим изолированный сеанс" },
        { "Starting Windows Sandbox", "Запускаем Windows Sandbox" },
        { "Waiting for the sandbox to finish", "Ждём завершения песочницы" },
        { "Reading the report", "Читаем отчёт" },
        { "Stopping the session", "Останавливаем сеанс" },
        { "Windows Sandbox needs a while to boot. The window it opens "
          "belongs to the sandbox, not to this computer.",
          "Песочнице нужно время на загрузку. Окно, которое появится, "
          "принадлежит ей, а не этому компьютеру." },
        { "Session finished", "Сеанс завершён" },
        { "Session cancelled", "Сеанс отменён" },
        { "The session did not finish", "Сеанс не довели до конца" },
        { "The sample did not start", "Образец не запустился" },
        { "The sandbox has been discarded together with everything "
          "the sample did inside it.",
          "Песочница уничтожена вместе со всем, что образец успел в ней "
          "натворить." },

        { "Observed for", "Наблюдение" },
        { "processes", "процессов" },
        { "events", "событий" },
        { "time limit reached", "истёк лимит времени" },
        { "process tree was terminated", "дерево процессов снято" },

        { "PROCESSES", "ПРОЦЕССЫ" },
        { "Process", "Процесс" },
        { "PID", "PID" },
        { "Started", "Запуск" },
        { "Exited", "Завершение" },
        { "still running", "ещё работал" },
        { "code", "код" },
        { "unknown", "неизвестно" },

        { "WHAT IT DID", "ЧТО ОН ДЕЛАЛ" },
        { "Time", "Время" },
        { "Event", "Событие" },
        { "Object", "Объект" },
        { "Details", "Подробности" },
        // Приписки в колонке подробностей.
        { "exit code", "код возврата" },
        { "renamed from", "переименован из" },
        { "renamed from outside the watched root",
          "переименован из-за пределов наблюдаемого каталога" },
        { "established", "соединение установлено" },
        { "connecting",  "устанавливается" },
        { "closing",     "закрывается" },
        { "closed",      "закрыто" },
        { "listening",   "слушает" },
        { "Change buffer overflowed, some file events were lost",
          "Буфер изменений переполнился, часть файловых событий потеряна" },
        { "Directory watch could not be re-armed",
          "Не удалось возобновить наблюдение за каталогом" },

        { "The author of this change is not visible without a kernel driver.",
          "Кто внёс это изменение, без драйвера ядра не видно." },

        { "process started", "запуск процесса" },
        { "process exited", "процесс завершился" },
        { "file created", "файл создан" },
        { "file modified", "файл изменён" },
        { "file deleted", "файл удалён" },
        { "file renamed", "файл переименован" },
        { "registry value added", "значение добавлено" },
        { "registry value changed", "значение изменено" },
        { "registry value deleted", "значение удалено" },
        { "registry key created", "ключ создан" },
        { "registry key deleted", "ключ удалён" },
        { "network connection", "сетевое соединение" },
        { "listening socket", "открыт порт" },
        { "monitor note", "заметка наблюдателя" },

        { "WHAT THIS OBSERVATION CANNOT SEE", "ЧЕГО ЭТО НАБЛЮДЕНИЕ НЕ ВИДИТ" },
        { "Nothing has been observed yet", "Наблюдений ещё не было" },
        { "Open a report", "Открыть отчёт" },
        { "Sandbox", "Песочница" },   // режим в истории проверок

        // Фоновая служба в настройках.
        { "Service", "Служба" },   // режим в истории проверок
        { "This scan ran in the background; the list of findings "
          "was not kept.",
          "Эта проверка прошла в фоне, список находок не сохранялся." },
        { "Background service", "Фоновая служба" },
        { "Scan even when the app is closed",
          "Проверять, даже когда приложение закрыто" },
        { "Installs a Windows service that runs a scan once a day even when "
          "Threat Scanner is closed. Installing and removing it asks for "
          "administrator rights.",
          "Ставит службу Windows, которая раз в сутки проверяет систему "
          "даже при закрытом приложении. Установка и удаление спрашивают "
          "права администратора." },
        { "Checking the background service...", "Проверяем состояние службы..." },
        { "Installing the service...", "Устанавливаем службу..." },
        { "Removing the service...", "Удаляем службу..." },
        { "Installed and running.", "Установлена и работает." },
        { "Installed, but not running.", "Установлена, но не запущена." },
        { "Not installed.", "Не установлена." },
        { "The background service is unavailable.", "Служба недоступна." },
        { "Report loaded from a file", "Отчёт загружен из файла" },
        { "Could not read the report", "Не удалось прочитать отчёт" },

        // Вердикт по поведению.
        { "This behaviour is typical of malware.",
          "Так ведёт себя вредоносная программа." },
        { "The file did things that ordinary programs rarely do.",
          "Файл делал то, что обычные программы делают редко." },
        { "Some activity was observed, none of it typical of malware.",
          "Активность есть, но ничего характерного для вредоносных программ." },
        { "Nothing notable happened while it was watched. "
          "That is not proof the file is safe.",
          "За время наблюдения ничего примечательного не произошло. "
          "Это не доказательство, что файл безопасен." },
        { "The sample did not start, so there was nothing to watch.",
          "Образец не запустился, наблюдать было не за чем." },

        { "Hijacked the launch of another program",
          "Перехватил запуск другой программы" },
        { "Replaced a system logon component",
          "Подменил системный компонент входа" },
        { "Dropped a driver into the system folder",
          "Положил драйвер в системную папку" },
        { "Rewrote the hosts file", "Переписал файл hosts" },
        { "Registered a Windows service", "Зарегистрировал службу Windows" },
        { "Placed a file into the startup folder",
          "Положил файл в папку автозагрузки" },
        { "Added an autorun entry", "Добавил запись автозапуска" },
        { "Started a hidden or encoded command",
          "Запустил скрытую или закодированную команду" },
        { "Used a built-in Windows tool to run code",
          "Выполнял код через встроенную программу Windows" },
        { "Deleted itself after running", "Удалил себя после запуска" },
        { "Connected to an outside address", "Соединился с внешним адресом" },
        { "Wrote an executable file", "Записал исполняемый файл" },
        { "Opened a port for incoming connections",
          "Открыл порт на приём соединений" },
        { "Started an unusual number of processes",
          "Породил необычно много процессов" },

        { "Choose a file and run it in the sandbox. What it creates, where "
          "it writes, what it adds to the registry and which processes it "
          "starts will appear here.",
          "Выберите файл и запустите его в песочнице. Что он создаёт, куда "
          "пишет, что добавляет в реестр и какие процессы порождает — "
          "появится здесь." },

        // Ограничения наблюдения — приходят из ядра готовыми фразами.
        { "No kernel driver: code injection, in-memory activity and "
          "direct system calls are not observed.",
          "Драйвера ядра нет: внедрение кода, работа в памяти и прямые "
          "системные вызовы не видны." },
        { "File and registry changes are not attributed to a process: "
          "user-mode monitoring does not report the author of a change.",
          "Изменения файлов и реестра не привязаны к процессу: в "
          "пользовательском режиме автор изменения не сообщается." },
        { "Registry changes made and reverted between two notifications "
          "are invisible.",
          "Изменение реестра, сделанное и откаченное между двумя "
          "уведомлениями, остаётся невидимым." },
        { "Connection tables are polled, so connections shorter than the "
          "polling interval are missed; DNS lookups are not visible.",
          "Таблицы соединений опрашиваются, поэтому соединения короче "
          "интервала опроса теряются; запросы DNS не видны." },
        { "Time limit reached: the sample was still running and may "
          "do more than what is listed here.",
          "Истёк лимит времени: образец продолжал работать и мог сделать "
          "больше перечисленного." },
        { "Observation was cancelled by the user.",
          "Наблюдение прервано пользователем." },
        { "File system was not watched: no directory could be opened.",
          "Файловая система не наблюдалась: не удалось открыть ни один "
          "каталог." },
        { "Registry was not watched: no key could be opened.",
          "Реестр не наблюдался: не удалось открыть ни один ключ." },
        { "Network was not watched: connection tables are unavailable.",
          "Сеть не наблюдалась: таблицы соединений недоступны." },
        { "Only these directories were watched:",
          "Наблюдались только эти каталоги:" },
        { "Directory could not be watched:",
          "Не удалось наблюдать за каталогом:" },

        { "The session was cancelled. If the sandbox window is still open, "
          "close it manually.",
          "Сеанс отменён. Если окно песочницы осталось открытым, закройте "
          "его вручную." },
        { "The sandbox did not produce a report within the time limit. "
          "Windows Sandbox runs only one session at a time — if another "
          "one is open, close it and try again.",
          "Песочница не отдала отчёт за отведённое время. Windows Sandbox "
          "работает только в одном экземпляре — если открыт другой сеанс, "
          "закройте его и попробуйте снова." },
    };
}

void Lang::setLanguage(Id id) {
    if (id == current_) return;
    current_ = id;

    QSettings store("ThreatScanner", "ThreatScanner");
    store.setValue("ui/language", id == Id::Ru ? "ru" : "en");
    store.sync();

    emit languageChanged();
}

QString TRN(int count, const QString& enOne, const QString& enMany,
            const QString& ruOne, const QString& ruFew, const QString& ruMany)
{
    if (Lang::instance().current() == Lang::Id::En)
        return count == 1 ? enOne : enMany;

    const int last = count % 10;
    const int lastTwo = count % 100;

    // 11–14 идут по общей форме, несмотря на последнюю цифру:
    // «11 процессов», но «21 процесс».
    if (lastTwo >= 11 && lastTwo <= 14) return ruMany;
    if (last == 1)                      return ruOne;
    if (last >= 2 && last <= 4)         return ruFew;
    return ruMany;
}

QString Lang::translate(const QString& key) const {
    if (current_ == Id::En) return key;
    // Нет перевода — отдаём исходную английскую строку: осмысленный текст
    // лучше, чем заглушка вроде «???».
    return ru_.value(key, key);
}
