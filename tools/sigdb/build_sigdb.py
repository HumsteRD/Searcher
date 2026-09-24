"""Сборка встроенной базы хэшей из выгрузки MalwareBazaar (abuse.ch, CC0).

Использование:
    python build_sigdb.py <full.zip|recent.csv> <out.tsdb>

Формат .tsdb (всё little-endian):
    8  байт  magic  b"TSHDB\0\0\1"
    4  байта дата сборки yyyymmdd
    4  байта число записей N
    4  байта число семейств F
    F  строк: 1 байт длины + UTF-8
    N  × 8 байт  ключ = первые 8 байт SHA-256 как big-endian uint64, по возрастанию
    N  × 2 байта индекс семейства (0 = не определено)

Восемь байт хэша вместо тридцати двух: вероятность случайного совпадения
чистого файла с одной из миллиона записей — порядка 1e-13, а база
становится в четыре раза меньше.
"""
import csv, io, struct, sys, zipfile, datetime

WINDOWS_TYPES = {
    "exe", "dll", "msi", "sys", "scr", "cpl", "ocx",
    "js", "jse", "vbs", "vbe", "ps1", "psm1", "bat", "cmd", "hta", "wsf", "lnk", "py", "jar",
    "zip", "rar", "7z", "iso", "img", "vhd", "vhdx", "cab", "gz", "tar", "xz", "arj", "ace", "lzh", "z",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "rtf", "one", "pdf",
    "chm", "html", "htm", "svg", "xll", "url", "reg", "inf", "msc", "appx", "msix",
}

def rows(path):
    if path.lower().endswith(".zip"):
        z = zipfile.ZipFile(path)
        f = z.open(z.namelist()[0])
    else:
        f = open(path, "rb")
    text = io.TextIOWrapper(f, encoding="utf-8", errors="replace")
    for line in text:
        if not line.strip() or line.startswith("#"):
            continue
        row = next(csv.reader([line], skipinitialspace=True))
        if len(row) >= 9:
            yield row

def main():
    src, out = sys.argv[1], sys.argv[2]
    entries = {}
    families = ["n/a"]
    fam_index = {"n/a": 0}
    for row in rows(src):
        sha, ftype, sig = row[1].strip().lower(), row[6].strip().lower(), row[8].strip()
        if len(sha) != 64 or ftype not in WINDOWS_TYPES:
            continue
        if not sig or sig.lower() in ("n/a", "null"):
            sig = "n/a"
            # Без названия семейства в выгрузку попадает и мусор: легитимные
            # программы, присланные «на всякий случай». Такие записи берём,
            # только если файл опознают хотя бы 10% антивирусов на VirusTotal.
            try:
                vt = float(row[10]) if len(row) > 10 else -1.0
            except ValueError:
                vt = -1.0
            if vt < 10.0:
                continue
        idx = fam_index.get(sig)
        if idx is None:
            if len(families) >= 65535:
                idx = 0
            else:
                idx = len(families)
                families.append(sig)
                fam_index[sig] = idx
        key = int(sha[:16], 16)
        # При совпадении ключа оставляем запись с известным семейством.
        if key not in entries or entries[key] == 0:
            entries[key] = idx
    keys = sorted(entries)
    today = int(datetime.date.today().strftime("%Y%m%d"))
    with open(out, "wb") as f:
        f.write(b"TSHDB\0\0\1")
        f.write(struct.pack("<III", today, len(keys), len(families)))
        for name in families:
            b = name.encode("utf-8")[:255]
            f.write(struct.pack("<B", len(b)) + b)
        f.write(b"".join(struct.pack("<Q", k) for k in keys))
        f.write(b"".join(struct.pack("<H", entries[k]) for k in keys))
    print(f"{len(keys)} hashes, {len(families)} families -> {out}")

if __name__ == "__main__":
    main()
