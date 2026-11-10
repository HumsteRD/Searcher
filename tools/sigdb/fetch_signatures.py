"""Скачивает базы сигнатур в res/signatures (в git они не хранятся).

Использование:
    python tools/sigdb/fetch_signatures.py          готовая база из релиза проекта
    python tools/sigdb/fetch_signatures.py --full   собрать базу из полной выгрузки

Что скачивается:
    rules-core.yar      YARA-Forge, пакет core
    rules-extended.yar  YARA-Forge, пакет extended
    base.tsdb           база хэшей MalwareBazaar (abuse.ch, CC0)

Базу хэшей собирает .github/workflows/signatures.yml и кладёт в релиз
signatures-latest; по умолчанию отсюда берётся она — та же, которую
программа скачивает сама. Этого хватает, чтобы собрать программу.

--full собирает базу заново из полной выгрузки (build_sigdb.py). Выгрузки
выдаются только по личному ключу: бесплатный Auth-Key с
https://auth.abuse.ch/ должен лежать в переменной окружения
ABUSE_CH_AUTH_KEY. В файлы проекта ключ не класть — репозиторий открытый.
"""
import io, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "..", "res", "signatures"))
FORGE_API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
PREBUILT_BASE = "https://github.com/HumsteRD/Searcher/releases/download/signatures-latest/base.tsdb"
EXPORTS = "https://mb-api.abuse.ch/v2/files/exports/{key}/{name}"
UA = {"User-Agent": "ThreatScanner-build"}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=300) as r:
        return r.read()


def download_resumable(url, path):
    """Большой файл: соединение посреди него рвётся, докачиваем с места обрыва."""
    for attempt in range(8):
        have = os.path.getsize(path) if os.path.exists(path) else 0
        headers = dict(UA)
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=300) as r:
                if have and r.status != 206:
                    have = 0   # сервер не поддержал докачку — с начала
                with open(path, "ab" if have else "wb") as f:
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
            if zipfile.is_zipfile(path):
                return
        except urllib.error.HTTPError as e:
            if e.code == 416 and zipfile.is_zipfile(path):
                return   # уже скачан целиком
            if e.code in (401, 403, 404):
                # Адрес с ключом в текст ошибки не выводим.
                sys.exit(f"MalwareBazaar refused the request (HTTP {e.code}): check ABUSE_CH_AUTH_KEY")
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
            pass
        time.sleep(3)
    sys.exit("the full export could not be downloaded completely")


def forge_rules(release, package):
    name = f"yara-forge-rules-{package}.zip"
    asset = next(a for a in release["assets"] if a["name"] == name)
    z = zipfile.ZipFile(io.BytesIO(get(asset["browser_download_url"])))
    member = next(n for n in z.namelist() if n.endswith(".yar"))
    with open(os.path.join(OUT, f"rules-{package}.yar"), "wb") as f:
        f.write(z.read(member))
    print(f"rules-{package}.yar: {release['tag_name']}")


def main():
    os.makedirs(OUT, exist_ok=True)
    release = json.loads(get(FORGE_API))
    for package in ("core", "extended"):
        forge_rules(release, package)

    if "--full" in sys.argv:
        key = os.environ.get("ABUSE_CH_AUTH_KEY", "").strip()
        if not key:
            sys.exit("--full needs the ABUSE_CH_AUTH_KEY environment variable (free key: https://auth.abuse.ch/)")
        with tempfile.TemporaryDirectory() as tmp:
            full = os.path.join(tmp, "full.csv.zip")
            download_resumable(EXPORTS.format(key=key, name="full.csv.zip"), full)
            subprocess.check_call([sys.executable, os.path.join(HERE, "build_sigdb.py"),
                                   full, os.path.join(OUT, "base.tsdb")])
        return

    data = get(PREBUILT_BASE)
    # Заголовок формата — см. build_sigdb.py. Страница ошибки вместо базы
    # не должна молча лечь рядом с программой.
    if data[:5] != b"TSHDB":
        sys.exit("base.tsdb: unexpected content, not a signature database")
    with open(os.path.join(OUT, "base.tsdb"), "wb") as f:
        f.write(data)
    print(f"base.tsdb: {len(data) // 1024} KB")


if __name__ == "__main__":
    main()
