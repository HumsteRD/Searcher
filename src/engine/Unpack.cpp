#include "Unpack.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace Unpack {
namespace {

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t Le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t Le64(const uint8_t* p) {
    return static_cast<uint64_t>(Le32(p)) | (static_cast<uint64_t>(Le32(p + 4)) << 32);
}
uint32_t Be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

std::string LowerExt(const std::string& name) {
    const size_t dot = name.find_last_of('.');
    const size_t slash = name.find_last_of("/\\");
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) return {};
    std::string e = name.substr(dot);
    std::transform(e.begin(), e.end(), e.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return e;
}

// Медиа и шрифты сигнатурами не проверяются — их извлечение только
// съедает предел по объёму.
bool IsInertExtension(const std::string& ext) {
    static const std::unordered_set<std::string> kInert = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
        ".mp3", ".mp4", ".wav", ".ogg", ".flac", ".avi", ".mkv", ".mov", ".webm",
        ".ttf", ".otf", ".woff", ".woff2", ".txt", ".md", ".css", ".map",
    };
    return kInert.count(ext) > 0;
}

// Отрезок [offset, offset + length) целиком внутри буфера из total байт.
// Смещения и длины приходят из файла и бывают любыми: складывать их
// напрямую нельзя — сумма переполняется и «проходит» проверку.
bool Fits(uint64_t offset, uint64_t length, uint64_t total) {
    return offset <= total && length <= total - offset;
}

// ───────────────────────────── ZIP ─────────────────────────────

bool ExtractZip(const uint8_t* d, size_t n, const Limits& lim, Result& r) {
    if (n < 22) return false;

    // Конец центрального каталога ищем с хвоста: после него может идти
    // комментарий до 64 КБ.
    const size_t scanFrom = n > 65557 ? n - 65557 : 0;
    size_t eocd = SIZE_MAX;
    for (size_t i = n - 22 + 1; i-- > scanFrom;) {
        if (d[i] == 'P' && d[i + 1] == 'K' && d[i + 2] == 5 && d[i + 3] == 6) { eocd = i; break; }
    }
    if (eocd == SIZE_MAX) return false;

    uint64_t total    = Le16(d + eocd + 10);
    uint64_t cdSize   = Le32(d + eocd + 12);
    uint64_t cdOffset = Le32(d + eocd + 16);

    // ZIP64: настоящие значения лежат в отдельной записи перед концом каталога.
    if ((cdOffset == 0xFFFFFFFFu || total == 0xFFFF) && eocd >= 20) {
        const uint8_t* loc = d + eocd - 20;
        if (Le32(loc) == 0x07064b50) {
            const uint64_t z64 = Le64(loc + 8);
            if (Fits(z64, 56, n) && Le32(d + z64) == 0x06064b50) {
                total    = Le64(d + z64 + 32);
                cdSize   = Le64(d + z64 + 40);
                cdOffset = Le64(d + z64 + 48);
            }
        }
    }

    // Архив, приклеенный к чему-то (самораспаковывающийся): смещения
    // считаются от начала архива, а не файла — поправку вычисляем так же,
    // как это делает unzip.
    uint64_t shift = 0;
    if (cdSize < eocd && cdOffset < eocd - cdSize) shift = eocd - cdSize - cdOffset;

    if (cdOffset >= n || shift >= n - cdOffset) return false;
    uint64_t pos = cdOffset + shift;

    r.container = "zip";
    size_t extracted = 0;

    for (uint64_t e = 0; e < total && pos + 46 <= n; ++e) {
        const uint8_t* h = d + pos;
        if (Le32(h) != 0x02014b50) break;

        const uint16_t flags   = Le16(h + 8);
        const uint16_t method  = Le16(h + 10);
        uint64_t compSize      = Le32(h + 20);
        uint64_t uncompSize    = Le32(h + 24);
        const uint16_t nameLen = Le16(h + 28);
        const uint16_t extLen  = Le16(h + 30);
        const uint16_t comLen  = Le16(h + 32);
        uint64_t lho           = Le32(h + 42);

        if (pos + 46 + nameLen + extLen + comLen > n) break;
        std::string name(reinterpret_cast<const char*>(h + 46), nameLen);

        // Размеры и смещение ZIP64 — в дополнительном поле 0x0001.
        const uint8_t* ex = h + 46 + nameLen;
        for (size_t k = 0; k + 4 <= extLen;) {
            const uint16_t id = Le16(ex + k), sz = Le16(ex + k + 2);
            if (k + 4 + sz > extLen) break;
            if (id == 0x0001) {
                size_t q = k + 4;
                if (uncompSize == 0xFFFFFFFFu && q + 8 <= k + 4 + sz) { uncompSize = Le64(ex + q); q += 8; }
                if (compSize   == 0xFFFFFFFFu && q + 8 <= k + 4 + sz) { compSize   = Le64(ex + q); q += 8; }
                if (lho        == 0xFFFFFFFFu && q + 8 <= k + 4 + sz) { lho        = Le64(ex + q); q += 8; }
            }
            k += 4 + sz;
        }
        pos += 46ull + nameLen + extLen + comLen;

        if (!name.empty() && (name.back() == '/' || name.back() == '\\')) continue;   // каталог
        if (flags & 1) { r.encrypted = true; continue; }

        const std::string ext = LowerExt(name);
        if (IsInertExtension(ext)) continue;

        if (static_cast<int>(r.items.size()) >= lim.maxItems ||
            uncompSize > lim.maxItemSize || extracted + uncompSize > lim.maxTotalSize ||
            (method != 0 && method != 8))
        {
            ++r.skipped;
            continue;
        }

        if (lho >= n || shift >= n - lho) { ++r.skipped; continue; }
        const uint64_t local = lho + shift;
        if (!Fits(local, 30, n) || Le32(d + local) != 0x04034b50) { ++r.skipped; continue; }
        const uint64_t dataAt = local + 30 + Le16(d + local + 26) + Le16(d + local + 28);
        if (!Fits(dataAt, compSize, n)) { ++r.skipped; continue; }

        Item item;
        item.name = name;
        if (method == 0) {
            // Несжатая запись: настоящий объём — compSize, а заявленному
            // uncompSize верить нельзя.
            if (compSize > lim.maxItemSize || extracted + compSize > lim.maxTotalSize) {
                ++r.skipped;
                continue;
            }
            item.data.assign(d + dataAt, d + dataAt + compSize);
        } else if (!Inflate(d + dataAt, static_cast<size_t>(compSize), true,
                            static_cast<size_t>(uncompSize), lim.maxItemSize, item.data)) {
            ++r.skipped;
            continue;
        }
        extracted += item.data.size();
        r.items.push_back(std::move(item));
    }
    return true;
}

// ───────────────────────────── PyInstaller ─────────────────────────────

// Минимальный читатель формата marshal — ровно столько, чтобы пройти
// оглавление архива PYZ: список пар (имя, (тип, смещение, длина)).
struct MValue {
    enum Kind { None, Int, Str, Seq, Other } kind = None;
    int64_t             i = 0;
    std::string         s;
    std::vector<MValue> items;
    size_t              weight = 1;   // число узлов вместе с вложенными
};

class Marshal {
public:
    Marshal(const uint8_t* d, size_t n) : d_(d), n_(n) {}

    bool Read(MValue& out, int depth = 0) {
        if (depth > 16 || p_ >= n_) return false;
        // Предел на число узлов: ссылка 'r' копирует значение целиком, и
        // список из ссылок на большой список раздувается в гигабайты из
        // нескольких килобайт данных.
        if (++nodes_ > kMaxNodes) return false;
        const uint8_t raw = d_[p_++];
        const bool addRef = (raw & 0x80) != 0;
        const char type = static_cast<char>(raw & 0x7F);
        size_t refSlot = 0;
        if (addRef) { refSlot = refs_.size(); refs_.emplace_back(); }

        switch (type) {
        case 'N': case 'F': case 'T': case '0': out.kind = MValue::None; break;
        case 'i':
            if (p_ + 4 > n_) return false;
            out.kind = MValue::Int; out.i = static_cast<int32_t>(Le32(d_ + p_)); p_ += 4;
            break;
        case 'z': case 'Z': {
            if (p_ + 1 > n_) return false;
            const size_t len = d_[p_++];
            if (!Bytes(len, out)) return false;
            break;
        }
        case 's': case 't': case 'u': case 'a': case 'A': {
            if (p_ + 4 > n_) return false;
            const size_t len = Le32(d_ + p_); p_ += 4;
            if (!Bytes(len, out)) return false;
            break;
        }
        case ')': case '(': case '[': {
            size_t count = 0;
            if (type == ')') { if (p_ + 1 > n_) return false; count = d_[p_++]; }
            else { if (p_ + 4 > n_) return false; count = Le32(d_ + p_); p_ += 4; }
            // Каждый элемент занимает хотя бы байт: больше, чем осталось
            // данных, элементов быть не может.
            if (count > 200000 || count > n_ - p_) return false;
            out.kind = MValue::Seq;
            out.items.resize(count);
            for (size_t k = 0; k < count; ++k) {
                if (!Read(out.items[k], depth + 1)) return false;
                out.weight += out.items[k].weight;
            }
            break;
        }
        case '{': {
            // Словарь в старых версиях: превращаем в список пар.
            out.kind = MValue::Seq;
            for (int guard = 0; guard < 200000; ++guard) {
                if (p_ >= n_) return false;
                if (d_[p_] == '0') { ++p_; break; }
                MValue key, value;
                if (!Read(key, depth + 1) || !Read(value, depth + 1)) return false;
                MValue pair; pair.kind = MValue::Seq;
                pair.weight = 1 + key.weight + value.weight;
                out.weight += pair.weight;
                pair.items.push_back(std::move(key));
                pair.items.push_back(std::move(value));
                out.items.push_back(std::move(pair));
            }
            break;
        }
        case 'r': {
            if (p_ + 4 > n_) return false;
            const size_t idx = Le32(d_ + p_); p_ += 4;
            if (idx >= refs_.size()) return false;
            nodes_ += refs_[idx].weight;
            if (nodes_ > kMaxNodes) return false;
            out = refs_[idx];
            break;
        }
        default:
            return false;   // коды и прочее в оглавлении не встречаются
        }
        if (addRef) refs_[refSlot] = out;
        return true;
    }

private:
    bool Bytes(size_t len, MValue& out) {
        if (p_ + len > n_) return false;
        out.kind = MValue::Str;
        out.s.assign(reinterpret_cast<const char*>(d_ + p_), len);
        p_ += len;
        return true;
    }

    static constexpr size_t kMaxNodes = 500000;

    const uint8_t*      d_;
    size_t              n_;
    size_t              p_ = 0;
    size_t              nodes_ = 0;
    std::vector<MValue> refs_;
};

// Модули стандартной библиотеки: одинаковы во всех сборках, и тратить на
// них предел по объёму незачем. Проверяется код самой программы и её
// сторонних зависимостей.
bool IsStdlibModule(const std::string& name) {
    static const std::unordered_set<std::string> kStd = {
        "abc", "argparse", "ast", "asyncio", "base64", "bdb", "binascii", "bisect", "bz2",
        "calendar", "cgi", "cmd", "code", "codecs", "collections", "colorsys", "concurrent",
        "configparser", "contextlib", "contextvars", "copy", "copyreg", "csv", "ctypes",
        "dataclasses", "datetime", "decimal", "difflib", "dis", "distutils", "doctest",
        "email", "encodings", "enum", "filecmp", "fnmatch", "fractions", "ftplib",
        "functools", "genericpath", "getopt", "getpass", "gettext", "glob", "gzip",
        "hashlib", "heapq", "hmac", "html", "http", "imaplib", "importlib", "inspect",
        "io", "ipaddress", "json", "keyword", "lib2to3", "linecache", "locale", "logging",
        "lzma", "mailbox", "mimetypes", "multiprocessing", "netrc", "ntpath", "nturl2path",
        "numbers", "opcode", "operator", "optparse", "os", "pathlib", "pdb", "pickle",
        "pkgutil", "platform", "plistlib", "poplib", "posixpath", "pprint", "py_compile",
        "pydoc", "pydoc_data", "queue", "quopri", "random", "re", "reprlib", "runpy",
        "sched", "secrets", "selectors", "shlex", "shutil", "signal", "site", "smtplib",
        "socket", "socketserver", "sqlite3", "sre_compile", "sre_constants", "sre_parse",
        "ssl", "stat", "statistics", "string", "stringprep", "struct", "subprocess",
        "sysconfig", "tarfile", "tempfile", "textwrap", "threading", "timeit", "tkinter",
        "token", "tokenize", "tomllib", "traceback", "tracemalloc", "turtle", "types",
        "typing", "unittest", "urllib", "uu", "uuid", "warnings", "wave", "weakref",
        "webbrowser", "xml", "xmlrpc", "zipfile", "zipimport", "zoneinfo", "_pyi_rth_utils",
        "pyimod01_archive", "pyimod02_importers", "pyimod03_ctypes", "pyimod04_pywin32",
        "__future__", "_compat_pickle", "_compression", "_py_abc", "_pydecimal",
        "_pyio", "_strptime", "_threading_local", "_weakrefset", "_aix_support",
        "_bootsubprocess", "_markupbase", "_osx_support", "_sitebuiltins", "selectors",
    };
    const std::string top = name.substr(0, name.find('.'));
    return kStd.count(top) > 0;
}

void ExtractPyz(const uint8_t* d, size_t n, const Limits& lim, size_t& total, Result& r) {
    if (n < 12 || std::memcmp(d, "PYZ\0", 4) != 0) return;
    const uint32_t tocOffset = Be32(d + 8);
    if (tocOffset >= n) return;

    Marshal m(d + tocOffset, n - tocOffset);
    MValue toc;
    if (!m.Read(toc) || toc.kind != MValue::Seq) return;

    for (const MValue& entry : toc.items) {
        if (entry.kind != MValue::Seq || entry.items.size() < 2) continue;
        const MValue& name = entry.items[0];
        const MValue& info = entry.items[1];
        if (name.kind != MValue::Str || info.kind != MValue::Seq || info.items.size() < 3) continue;
        if (IsStdlibModule(name.s)) continue;

        const int64_t pos = info.items[1].i, len = info.items[2].i;
        if (pos < 0 || len <= 0 || static_cast<uint64_t>(pos + len) > n) continue;
        if (static_cast<int>(r.items.size()) >= lim.maxItems || total >= lim.maxTotalSize) {
            ++r.skipped;
            continue;
        }

        Item item;
        item.name = "PYZ/" + name.s;
        if (!Inflate(d + pos, static_cast<size_t>(len), false, 0,
                     std::min(lim.maxItemSize, lim.maxTotalSize - total), item.data)) {
            ++r.skipped;   // зашифрованный PYZ (ключ --key) сюда же
            continue;
        }
        total += item.data.size();
        r.items.push_back(std::move(item));
    }
}

bool ExtractPyInstaller(const uint8_t* d, size_t n, const Limits& lim, Result& r) {
    static const uint8_t kMagic[8] = { 'M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E };

    // Короче самой метки — искать негде. Без этой проверки счётчик ниже
    // уходил за ноль и чтение шло мимо буфера: файл из пяти байт «MZ…»
    // ронял проверку.
    if (n < 24) return false;

    // Метка лежит в конце архива, но за ней может идти подпись Authenticode,
    // поэтому ищем в последнем мегабайте.
    const size_t window = std::min<size_t>(n, 1u << 20);
    size_t cookie = SIZE_MAX;
    for (size_t i = n - 8 + 1; i-- > n - window;) {
        if (d[i] == 'M' && std::memcmp(d + i, kMagic, 8) == 0) { cookie = i; break; }
    }
    if (cookie == SIZE_MAX || cookie + 24 > n) return false;

    const uint32_t pkgLen = Be32(d + cookie + 8);
    const uint32_t tocOff = Be32(d + cookie + 12);
    const uint32_t tocLen = Be32(d + cookie + 16);

    // Длина пакета считается вместе с меткой: 88 байт в версиях от 2.1,
    // 24 — в старых. Подходит та, при которой оглавление внутри файла.
    for (size_t cookieSize : { size_t(88), size_t(24) }) {
        if (cookie + cookieSize > n || pkgLen > cookie + cookieSize) continue;
        const size_t pkg = cookie + cookieSize - pkgLen;
        if (static_cast<uint64_t>(pkg) + tocOff + tocLen > n) continue;

        const uint8_t* toc = d + pkg + tocOff;
        size_t p = 0, total = 0;
        bool sane = true;
        r.container = "pyinstaller";

        while (p + 18 <= tocLen) {
            const uint32_t entrySize = Be32(toc + p);
            if (entrySize < 18 || p + entrySize > tocLen) { sane = false; break; }
            const uint32_t pos   = Be32(toc + p + 4);
            const uint32_t csize = Be32(toc + p + 8);
            const uint32_t usize = Be32(toc + p + 12);
            const uint8_t  flag  = toc[p + 16];
            const char     type  = static_cast<char>(toc[p + 17]);
            std::string name(reinterpret_cast<const char*>(toc + p + 18), entrySize - 18);
            name = name.c_str();   // имя дополнено нулями
            p += entrySize;

            if (static_cast<uint64_t>(pkg) + pos + csize > n) continue;
            const uint8_t* data = d + pkg + pos;

            // 's' — сценарии самой программы, 'z'/'Z' — архив модулей.
            // Служебные сценарии PyInstaller одинаковы везде — пропускаем.
            if (type == 's') {
                if (name.rfind("pyi_rth_", 0) == 0 || name.rfind("pyiboot", 0) == 0) continue;
                if (static_cast<int>(r.items.size()) >= lim.maxItems || total >= lim.maxTotalSize) {
                    ++r.skipped;
                    continue;
                }
                Item item;
                item.name = name;
                if (flag == 1) {
                    if (!Inflate(data, csize, false, usize,
                                 std::min(lim.maxItemSize, lim.maxTotalSize - total), item.data)) {
                        ++r.skipped;
                        continue;
                    }
                } else {
                    if (csize > lim.maxItemSize || csize > lim.maxTotalSize - total) {
                        ++r.skipped;
                        continue;
                    }
                    item.data.assign(data, data + csize);
                }
                total += item.data.size();
                r.items.push_back(std::move(item));
            } else if (type == 'z' || type == 'Z') {
                ExtractPyz(data, csize, lim, total, r);
            }
        }
        if (sane) return true;
        r.items.clear();
        r.container.clear();
    }
    return false;
}

} // namespace

bool Inflate(const uint8_t* data, size_t size, bool raw, size_t expected,
             size_t limit, std::vector<uint8_t>& out)
{
    z_stream zs{};
    if (inflateInit2(&zs, raw ? -MAX_WBITS : MAX_WBITS) != Z_OK) return false;

    out.clear();
    out.resize(std::min(limit, expected ? expected : std::min<size_t>(size * 4 + 1024, limit)));
    zs.next_in  = const_cast<Bytef*>(data);
    zs.avail_in = static_cast<uInt>(std::min<size_t>(size, UINT32_MAX));

    int rc = Z_OK;
    size_t produced = 0;
    while (rc == Z_OK) {
        if (produced == out.size()) {
            if (out.size() >= limit) { inflateEnd(&zs); return false; }
            out.resize(std::min(limit, out.size() * 2 + 4096));
        }
        zs.next_out  = out.data() + produced;
        zs.avail_out = static_cast<uInt>(out.size() - produced);
        rc = inflate(&zs, Z_NO_FLUSH);
        produced = out.size() - zs.avail_out;
        if (rc == Z_BUF_ERROR && zs.avail_in == 0) break;   // поток оборван
    }
    inflateEnd(&zs);
    if (rc != Z_STREAM_END && rc != Z_BUF_ERROR) return false;
    out.resize(produced);
    return produced > 0;
}

Result Extract(const uint8_t* data, size_t size, const Limits& limits) {
    Result r;
    if (!data || size < 4) return r;

    if (data[0] == 'P' && data[1] == 'K' && (data[2] == 3 || data[2] == 5)) {
        ExtractZip(data, size, limits, r);
        return r;
    }
    if (data[0] == 'M' && data[1] == 'Z') {
        if (ExtractPyInstaller(data, size, limits, r)) return r;
        r = {};
        // Самораспаковывающиеся ZIP: архив приклеен к исполняемому файлу.
        ExtractZip(data, size, limits, r);
        if (r.items.empty()) r = {};
    }
    return r;
}

} // namespace Unpack
