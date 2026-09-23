#include "WsbGenerator.h"
#include "Logger.h"

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace {

// Пути внутри песочницы. Постоянные и короткие: их подставляют в
// команду запуска, и лишние пробелы с кавычками тут ни к чему.
const wchar_t* kSandboxSampleDir = L"C:\\sample";
const wchar_t* kSandboxAgentDir  = L"C:\\agent";
const wchar_t* kSandboxReportDir = L"C:\\report";

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring XmlEscape(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) {
        switch (c) {
        case L'&':  out += L"&amp;";  break;
        case L'<':  out += L"&lt;";   break;
        case L'>':  out += L"&gt;";   break;
        case L'"':  out += L"&quot;"; break;
        case L'\'': out += L"&apos;"; break;
        default:    out += c;         break;
        }
    }
    return out;
}

std::wstring TrimSlash(std::wstring s) {
    while (s.size() > 3 && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
    return s;
}

void MappedFolder(std::wostringstream& os, const std::wstring& host,
                  const wchar_t* sandbox, bool readOnly)
{
    os << L"    <MappedFolder>\r\n"
       << L"      <HostFolder>" << XmlEscape(TrimSlash(host)) << L"</HostFolder>\r\n"
       << L"      <SandboxFolder>" << sandbox << L"</SandboxFolder>\r\n"
       << L"      <ReadOnly>" << (readOnly ? L"true" : L"false")
       << L"</ReadOnly>\r\n"
       << L"    </MappedFolder>\r\n";
}

} // namespace

std::wstring WsbGenerator::BuildXml(const Options& opt) {
    const std::wstring sampleName = fs::path(opt.samplePath).filename().wstring();

    std::wostringstream cmd;
    cmd << kSandboxAgentDir << L"\\" << opt.agentExeName
        << L" --observe \"" << kSandboxSampleDir << L"\\" << sampleName << L"\""
        << L" --out \"" << kSandboxReportDir << L"\\" << opt.reportName << L"\""
        << L" --timeout " << opt.timeoutMs;
    if (!opt.sampleArguments.empty())
        cmd << L" --args \"" << opt.sampleArguments << L"\"";
    if (opt.closeWhenDone)
        cmd << L" --shutdown";

    // Порядок элементов — как в документации Microsoft. Проверить, что
    // разбор переживёт другой порядок, на домашней редакции нечем,
    // а гадать в файле, от которого зависит вся изоляция, незачем.
    std::wostringstream os;
    os << L"<Configuration>\r\n"
       << L"  <VGpu>Disable</VGpu>\r\n"
       << L"  <Networking>" << (opt.networking ? L"Default" : L"Disable")
       << L"</Networking>\r\n"
       << L"  <MappedFolders>\r\n";

    MappedFolder(os, opt.sampleDir, kSandboxSampleDir, true);
    MappedFolder(os, opt.agentDir,  kSandboxAgentDir,  true);
    MappedFolder(os, opt.reportDir, kSandboxReportDir, false);

    os << L"  </MappedFolders>\r\n"
       << L"  <LogonCommand>\r\n"
       << L"    <Command>" << XmlEscape(cmd.str()) << L"</Command>\r\n"
       << L"  </LogonCommand>\r\n"
       << L"  <AudioInput>Disable</AudioInput>\r\n"
       << L"  <VideoInput>Disable</VideoInput>\r\n"
       << L"  <ProtectedClient>" << (opt.protectedClient ? L"Enable" : L"Disable")
       << L"</ProtectedClient>\r\n"
       << L"  <PrinterRedirection>Disable</PrinterRedirection>\r\n"
       << L"  <ClipboardRedirection>Disable</ClipboardRedirection>\r\n"
       << L"  <MemoryInMB>" << opt.memoryMb << L"</MemoryInMB>\r\n"
       << L"</Configuration>\r\n";

    return os.str();
}

WsbGenerator::Result WsbGenerator::Write(const Options& opt,
                                         const std::wstring& wsbPath)
{
    Result result;
    std::error_code ec;

    auto require = [&](bool condition, const std::wstring& message) {
        if (!condition && result.error.empty()) result.error = message;
        return condition;
    };

    if (!require(!opt.samplePath.empty() && fs::exists(opt.samplePath, ec),
                 L"Sample not found: " + opt.samplePath) ||
        !require(!opt.sampleDir.empty() && fs::is_directory(opt.sampleDir, ec),
                 L"Sample folder not found: " + opt.sampleDir) ||
        !require(!opt.agentDir.empty() && fs::is_directory(opt.agentDir, ec),
                 L"Agent folder not found: " + opt.agentDir) ||
        !require(fs::exists(fs::path(opt.agentDir) / opt.agentExeName, ec),
                 L"Agent executable not found in " + opt.agentDir) ||
        !require(!opt.reportDir.empty() && fs::is_directory(opt.reportDir, ec),
                 L"Report folder not found: " + opt.reportDir))
    {
        return result;
    }

    // Образец обязан лежать в отображаемой папке, иначе внутри песочницы
    // по пути C:\sample\<имя> не окажется ничего.
    const auto sampleParent = fs::path(opt.samplePath).parent_path();
    if (!fs::equivalent(sampleParent, fs::path(opt.sampleDir), ec)) {
        result.error = L"Sample is not inside the mapped sample folder.";
        return result;
    }

    // Отчёт возвращается через папку с записью: если она открыта только
    // на чтение, песочница отработает и не отдаст ничего.
    std::ofstream file(wsbPath, std::ios::binary | std::ios::trunc);
    if (!file) {
        result.error = L"Cannot write configuration file: " + wsbPath;
        return result;
    }

    // .wsb читается как XML; пишем UTF-8 с объявлением кодировки,
    // иначе пути с кириллицей превращаются в мусор.
    const std::wstring xml = BuildXml(opt);
    file << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" << WideToUtf8(xml);
    if (!file) {
        result.error = L"Failed while writing " + wsbPath;
        return result;
    }
    file.close();

    result.ok         = true;
    result.wsbPath    = wsbPath;
    result.reportPath = (fs::path(opt.reportDir) / opt.reportName).wstring();

    Logger::Instance().Info("[Sandbox] configuration written: " +
                            WideToUtf8(wsbPath));
    return result;
}
