"""Сбор строк интерфейса для перевода.

Ключ перевода — английская строка. Берём:
  * аргументы TR(...) — в том числе склеенные из нескольких литералов;
  * строки из таблиц, которые потом проходят через TR (справка, типы
    проверки, причины находок, темы);
  * строки ядра, которые интерфейс переводит по словарю (стадии песочницы,
    вердикты и находки наблюдения за поведением, ограничения).

    python tools/i18n/extract.py          ключи без перевода -> build/i18n-missing.json
    python tools/i18n/extract.py --gen    собрать src/app/LangRu.cpp из tools/i18n/ru.json
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[2]
src = root / "src"

LIT = r'"((?:[^"\\]|\\.)*)"'


def unescape(s):
    return (s.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t")
             .replace("\\\\", "\\"))


def literals_in(text):
    out = []
    for m in re.finditer(r'(?:' + LIT + r'\s*)+', text):
        parts = re.findall(LIT, m.group(0))
        out.append("".join(unescape(p) for p in parts))
    return out


def collect():
    keys = set()
    files = list((src / "app").glob("*.cpp")) + list((src / "pages").glob("*.cpp")) + \
        list((src / "ui").glob("*.cpp"))
    for f in files:
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r'\bTR\(\s*((?:' + LIT + r'\s*)+)\)', text):
            keys.update(literals_in(m.group(1)))
        if f.name in ("HelpPage.cpp", "ScanPage.cpp", "Texts.cpp", "SettingsPage.cpp"):
            for block in re.findall(r'\{[^{}]*\}', text):
                for s in literals_in(block):
                    if (re.search(r'[A-Za-z]{3}', s) and " " in s) or s in ("Light", "Dark", "Graphite", "Files"):
                        if not s.startswith(("script.", "cmd.", "http")) and "\\" not in s:
                            keys.add(s)

    for rel in ["core/BehaviorVerdict.cpp", "core/BehaviorMonitor.cpp", "core/SandboxSession.cpp",
                "core/SandboxEnvironment.cpp"]:
        text = (src / rel).read_text(encoding="utf-8")
        for m in re.finditer(r'L((?:"(?:[^"\\]|\\.)*"\s*L?\s*)+)', text):
            s = "".join(unescape(p) for p in re.findall(LIT, m.group(1)))
            if re.match(r'^[A-Z][a-z]', s) and len(s) > 12 and " " in s:
                keys.add(s.strip())

    runtime = root.parent / "shots" / "missing-ru.txt"
    if runtime.exists():
        keys.update(l.rstrip("\n") for l in runtime.read_text(encoding="utf-8").splitlines() if l.strip())
    return keys


def cpp_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def generate(ru):
    lines = [
        '#include "Lang.h"',
        "",
        "// Русский словарь. Собирается из tools/i18n/ru.json скриптом",
        "// tools/i18n/extract.py --gen — править надо там, а не здесь.",
        "void FillRussian(QHash<QString, QString>& d) {",
        f"    d.reserve({len(ru)});",
    ]
    for k in sorted(ru):
        lines.append(f'    d.insert(QStringLiteral("{cpp_escape(k)}"), QStringLiteral("{cpp_escape(ru[k])}"));')
    lines.append("}")
    (src / "app" / "LangRu.cpp").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    dict_path = pathlib.Path(__file__).with_name("ru.json")
    ru = json.loads(dict_path.read_text(encoding="utf-8")) if dict_path.exists() else {}
    if "--gen" in sys.argv:
        generate(ru)
        print(len(ru), "translations written")
        return
    keys = collect()
    missing = sorted(k for k in keys if k not in ru and k.strip())
    print(len(keys), "keys,", len(missing), "missing")
    (root / "build" / "i18n-missing.json").write_text(json.dumps(missing, ensure_ascii=False, indent=1),
                                                     encoding="utf-8")


if __name__ == "__main__":
    main()
