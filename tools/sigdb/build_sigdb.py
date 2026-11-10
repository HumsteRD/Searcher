"""Сборка базы хэшей из выгрузки MalwareBazaar (abuse.ch, CC0).

Использование:
    python build_sigdb.py <full.zip|recent.csv> <out.tsdb> [--merge <old.tsdb>]...
    python build_sigdb.py --only-merge <out.tsdb> --merge <a.tsdb> --merge <b.tsdb>

--merge добавляет к результату записи уже собранной базы. Так база
растёт от выпуска к выпуску без полной выгрузки: к прежней base.tsdb
подмешиваются свежие записи (выгрузка recent.csv — последние 48 часов).

Формат .tsdb (всё little-endian):
    8  байт  magic  b"TSHDB\\0\\0\\1"
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

MAGIC = b"TSHDB\0\0\1"

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


def read_tsdb(path):
    """Записи готовой базы: {ключ: название семейства}."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != MAGIC:
        sys.exit(f"{path}: not a signature database")
    _, count, fams = struct.unpack_from("<III", data, 8)
    pos = 20
    names = []
    for _ in range(fams):
        n = data[pos]
        names.append(data[pos + 1:pos + 1 + n].decode("utf-8", "replace"))
        pos += 1 + n
    if len(data) != pos + count * 10:
        sys.exit(f"{path}: damaged database (length does not match the header)")
    keys = struct.unpack_from(f"<{count}Q", data, pos)
    idx = struct.unpack_from(f"<{count}H", data, pos + count * 8)
    return {k: (names[i] if i < len(names) else "n/a") for k, i in zip(keys, idx)}


def read_export(path):
    """Записи выгрузки MalwareBazaar: {ключ: название семейства}."""
    out = {}
    for row in rows(path):
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
        try:
            key = int(sha[:16], 16)
        except ValueError:
            continue
        # При совпадении ключа оставляем запись с известным семейством.
        if key not in out or out[key] == "n/a":
            out[key] = sig
    return out


def write_tsdb(path, entries):
    families = ["n/a"]
    fam_index = {"n/a": 0}
    indexed = {}
    for key, sig in entries.items():
        idx = fam_index.get(sig)
        if idx is None:
            if len(families) >= 65535:
                idx = 0
            else:
                idx = len(families)
                families.append(sig)
                fam_index[sig] = idx
        indexed[key] = idx
    keys = sorted(indexed)
    today = int(datetime.date.today().strftime("%Y%m%d"))
    with open(path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<III", today, len(keys), len(families)))
        for name in families:
            b = name.encode("utf-8")[:255]
            f.write(struct.pack("<B", len(b)) + b)
        f.write(struct.pack(f"<{len(keys)}Q", *keys))
        f.write(struct.pack(f"<{len(keys)}H", *(indexed[k] for k in keys)))
    print(f"{len(keys)} hashes, {len(families)} families -> {path}")


def main():
    args = sys.argv[1:]
    merges = []
    while "--merge" in args:
        i = args.index("--merge")
        if i + 1 >= len(args):
            sys.exit("--merge needs a file")
        merges.append(args[i + 1])
        del args[i:i + 2]
    only_merge = "--only-merge" in args
    if only_merge:
        args.remove("--only-merge")

    if only_merge:
        if len(args) != 1 or not merges:
            sys.exit(__doc__)
        src, out = None, args[0]
    else:
        if len(args) != 2:
            sys.exit(__doc__)
        src, out = args

    entries = {}
    for path in merges:
        old = read_tsdb(path)
        for key, sig in old.items():
            if key not in entries or entries[key] == "n/a":
                entries[key] = sig
        print(f"{len(old)} hashes from {path}")

    if src:
        fresh = read_export(src)
        # Пустой разбор — это не «новых образцов нет», а страница ошибки
        # вместо выгрузки или сменившийся формат. Публиковать такое нельзя:
        # программа получила бы базу без записей.
        if not fresh:
            sys.exit(f"{src}: no usable rows. Wrong Auth-Key, an error page instead of the export, "
                     "or the export format has changed")
        added = 0
        for key, sig in fresh.items():
            if key not in entries:
                added += 1
                entries[key] = sig
            elif entries[key] == "n/a" and sig != "n/a":
                entries[key] = sig
        print(f"{len(fresh)} hashes from {src}, {added} new")

    write_tsdb(out, entries)


if __name__ == "__main__":
    main()
