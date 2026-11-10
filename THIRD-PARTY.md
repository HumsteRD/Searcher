# Сторонние компоненты

Threat Scanner использует следующие компоненты и данные. Каждый распространяется
на условиях своей лицензии.

| Компонент | Для чего | Лицензия |
|---|---|---|
| [Qt 6](https://www.qt.io/) | интерфейс, сеть | LGPL v3 (подключается динамически, библиотеки лежат рядом с программой и заменяемы) |
| [YARA](https://github.com/VirusTotal/yara) | движок сигнатурного поиска | BSD 3-Clause |
| [YARA-Forge](https://github.com/YARAHQ/yara-forge) | набор правил YARA | у каждого правила — лицензия исходного репозитория, указана в `meta` правила (`license_url`) |
| [MalwareBazaar](https://bazaar.abuse.ch/) от abuse.ch | хэши известных вредоносных файлов | CC0 |
| [OpenSSL](https://www.openssl.org/) | HTTPS для обновлений и VirusTotal | Apache 2.0 |
| [zlib](https://zlib.net/) | распаковка архивов | zlib License |
| [zstd](https://github.com/facebook/zstd), FreeType, HarfBuzz, libpng, PCRE2, Brotli, bzip2, double-conversion, md4c | зависимости Qt | лицензии соответствующих проектов |
| Среда выполнения Microsoft Visual C++ (`vcruntime140*.dll`, `msvcp140*.dll`) | стандартная библиотека C++, лежит рядом с программой | распространяемые файлы Visual Studio, условия лицензии Microsoft |

Базы сигнатур — данные третьих сторон: они описывают известные угрозы и не дают
гарантии, что неизвестный файл безопасен.
