"""Проверка контраста палитр интерфейса (WCAG 2.1).

Пары «текст на фоне» из src/ui/Theme.cpp: основной и вторичный текст
должны давать не меньше 4.5:1, крупные заголовки и значки — 3:1.
Запуск: python tools/design/contrast.py
"""
import re, sys, pathlib

src = pathlib.Path(__file__).resolve().parents[2] / "src" / "ui" / "Theme.cpp"
text = src.read_text(encoding="utf-8")

def lum(hexcolor):
    h = hexcolor.lstrip("#")
    r, g, b = (int(h[i:i+2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)

def ratio(a, b):
    la, lb = lum(a), lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)

blocks = re.findall(r"// palette:(\w+)\n(.*?)// end", text, re.S)
checks = [
    ("text", "surface", 7.0), ("text", "window", 7.0), ("text2", "surface", 4.5),
    ("text2", "window", 4.5), ("text3", "surface", 4.5), ("text3", "window", 4.5),
    ("text3", "surfaceAlt", 4.5), ("text2", "sidebar", 4.5), ("accentText", "surface", 4.5),
    ("textOnAccent", "accent", 4.5), ("dangerText", "surface", 4.5), ("dangerText", "dangerSoft", 4.5),
    ("highText", "highSoft", 4.5), ("warnText", "warnSoft", 4.5),
    ("okText", "okSoft", 4.5), ("lowText", "lowSoft", 4.5), ("textOnAccent", "danger", 4.5),
    ("accentText", "accentSoft", 4.5), ("text2", "infoSoft", 4.5), ("text", "rowSelected", 7.0),
    ("borderStrong", "surface", 1.6), ("text2", "surfaceAlt", 4.5), ("text3", "sidebar", 4.5), ("okText", "surface", 4.5), ("warnText", "surface", 4.5),
]
failed = 0
for name, body in blocks:
    colors = dict(re.findall(r'\{\s*"(\w+)",\s*"(#[0-9A-Fa-f]{6})"', body))
    print(f"== {name}")
    for fg, bg, need in checks:
        if fg not in colors or bg not in colors:
            print(f"   missing {fg}/{bg}"); failed += 1; continue
        r = ratio(colors[fg], colors[bg])
        mark = "ok " if r >= need else "LOW"
        if r < need: failed += 1
        print(f"   {mark} {fg:13} on {bg:16} {r:5.2f} (need {need})")
print("FAILED" if failed else "ALL OK", failed)
sys.exit(1 if failed else 0)
