"""Скачивает базы сигнатур в res/signatures (в git они не хранятся).

Использование:
    python tools/sigdb/fetch_signatures.py

Что скачивается:
    base.tsdb           из полной выгрузки MalwareBazaar (abuse.ch, CC0),
                        сборка — build_sigdb.py
    rules-core.yar      YARA-Forge, пакет core
    rules-extended.yar  YARA-Forge, пакет extended
"""
import io, json, os, subprocess, sys, tempfile, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "..", "res", "signatures"))
BAZAAR_FULL = "https://bazaar.abuse.ch/export/csv/full/"
FORGE_API = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
UA = {"User-Agent": "ThreatScanner-build"}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=300) as r:
        return r.read()


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

    with tempfile.TemporaryDirectory() as tmp:
        full = os.path.join(tmp, "full.zip")
        with open(full, "wb") as f:
            f.write(get(BAZAAR_FULL))
        subprocess.check_call([sys.executable, os.path.join(HERE, "build_sigdb.py"),
                               full, os.path.join(OUT, "base.tsdb")])


if __name__ == "__main__":
    main()
