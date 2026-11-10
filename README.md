# Threat Scanner

Проверка Windows на вредоносные программы: файлы, процессы, автозапуск,
задачи планировщика, службы и сетевые соединения.

**[Скачать установщик](https://github.com/HumsteRD/Searcher/releases/latest)** — файл
`ThreatScanner-Setup-<версия>.exe`. Windows 10 1809 и новее, 64 бит.

> Установщик не подписан сертификатом, поэтому SmartScreen может показать
> «Windows защитила ваш компьютер». Нажмите «Подробнее» → «Выполнить в любом случае».
> Контрольная сумма SHA-256 указана в описании релиза.

## Возможности

- **Три режима проверки**: быстрая (места, где обычно прячется вредоносное ПО),
  полная (все локальные диски) и выборочная (свои папки, файлы и диски).
  Проверку можно поставить на паузу и продолжить с того же места; нагрузка
  на процессор выбирается в настройках.
- **Проверка файла из проводника** — пункт «Проверить в Threat Scanner» в меню
  по правому клику, перетаскивание файла в окно. По каждому файлу — карточка
  с вердиктом, подписью и SHA-256.
- **Флешки и внешние диски**: при подключении программа предлагает проверить
  носитель до того, как с него открыли файлы.
- **Сигнатуры**: база хэшей [MalwareBazaar](https://bazaar.abuse.ch/) (около миллиона
  образцов) и правила [YARA-Forge](https://github.com/YARAHQ/yara-forge).
  Архивы ZIP и упакованные PyInstaller-программы распаковываются и проверяются изнутри.
- **Мало ложных срабатываний**: подписанные файлы известных производителей
  не помечаются по одним эвристикам, слабые правила требуют подтверждения.
- **Действия**: карантин с возможностью восстановления, удаление, отключение
  автозапуска и задач, завершение процесса. Всё, что требует прав администратора,
  выполняет отдельный помощник — окно программы работает без повышенных прав.
- **Слежение за загрузками**: новые файлы в «Загрузках» и на рабочем столе
  проверяются сразу, пока программа открыта или свёрнута в трей. У находки
  видно, с какого адреса файл скачан.
- **Не мешает**: пока на весь экран идёт игра, фильм или презентация,
  плановая проверка ждёт, а показываются только предупреждения об угрозах.
- **Отчёты**: отчёт по любой проверке из истории сохраняется как веб-страница,
  текст или JSON; в результатах и в журнале есть поиск.
- **Анализ поведения** в Windows Sandbox (Windows Pro и Enterprise):
  файл запускается в изолированной машине, программа показывает, что он делал.
- **VirusTotal** — проверка хэша по своему ключу API.
- **Обновления**: базы сигнатур обновляются сами, о новой версии программа
  сообщает и ставит её по нажатию (или сама — если включить в настройках).
- Светлая, тёмная и графитовая темы, русский и английский языки.

## Сборка из исходников

Нужны Visual Studio 2022+ (C++), [vcpkg](https://github.com/microsoft/vcpkg),
Python 3 и [Inno Setup 6](https://jrsoftware.org/isinfo.php) для установщика.

```
vcpkg install qtbase qtsvg yara[dotnet] zlib --triplet x64-windows
python tools/sigdb/fetch_signatures.py
cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
build\Release\engine_selftest.exe
build\Release\core_selftest.exe
powershell -ExecutionPolicy Bypass -File tools/package.ps1
```

`fetch_signatures.py` скачивает базы в `res/signatures` (в репозитории они не хранятся),
`engine_selftest` и `core_selftest` проверяют ядро и карантин без образцов и без прав
администратора, `package.ps1` собирает установщик в `release/`.

Qt из vcpkg по умолчанию тянет ICU, SQL и D-Bus, которые программе не нужны. Сборка
быстрее, а установщик меньше, если поставить только нужное:

```
vcpkg install "qtbase[core,async-io,brotli,concurrent,dnslookup,doubleconversion,freetype,gui,harfbuzz,jpeg,network,openssl,pcre2,png,sessionmanager,thread,widgets,zstd]" qtsvg "yara[dotnet]" zlib --triplet x64-windows
```

### Базы хэшей

Базы для релиза `signatures-latest` собирает `.github/workflows/signatures.yml`:
свежие записи — каждый день, полную базу — раз в неделю. MalwareBazaar отдаёт выгрузки
только по личному ключу, поэтому сборке нужен секрет репозитория `ABUSE_CH_AUTH_KEY`
(бесплатный ключ: <https://auth.abuse.ch/>). Сама программа к MalwareBazaar не
обращается — она берёт готовые базы из релиза. В файлы репозитория ключ не кладётся.

Собрать полную базу у себя: `python tools/sigdb/fetch_signatures.py --full` с ключом
в переменной окружения `ABUSE_CH_AUTH_KEY`.

## Лицензии

Используемые библиотеки и базы сигнатур перечислены в [THIRD-PARTY.md](THIRD-PARTY.md).

---

**English.** Threat Scanner checks Windows for malware: files, processes, autoruns,
scheduled tasks, services and network connections. Signatures come from MalwareBazaar
and YARA-Forge. Download the installer from
[Releases](https://github.com/HumsteRD/Searcher/releases/latest); the interface
language can be switched to English in Settings.
