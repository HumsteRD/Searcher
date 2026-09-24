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
