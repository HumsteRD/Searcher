#include "Classify.h"

#include <algorithm>
#include <cctype>
#include <utility>
#include <vector>

namespace Classify {
namespace {

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool Has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// Семейства, по имени которых тип не угадать. Таксономия — как в отчётах
// MalwareBazaar и Malpedia; только самые распространённые.
const std::vector<std::pair<const char*, MalwareClass>>& KnownFamilies() {
    static const std::vector<std::pair<const char*, MalwareClass>> k = {
        { "agenttesla", MalwareClass::Stealer },   { "formbook", MalwareClass::Stealer },
        { "xloader", MalwareClass::Stealer },      { "loki", MalwareClass::Stealer },
        { "vidar", MalwareClass::Stealer },        { "lumma", MalwareClass::Stealer },
        { "stealc", MalwareClass::Stealer },       { "raccoon", MalwareClass::Stealer },
        { "redline", MalwareClass::Stealer },      { "arkei", MalwareClass::Stealer },
        { "rhadamanthys", MalwareClass::Stealer }, { "azorult", MalwareClass::Stealer },
        { "metastealer", MalwareClass::Stealer },  { "risepro", MalwareClass::Stealer },
        { "mystic", MalwareClass::Stealer },       { "aurora", MalwareClass::Stealer },
        { "phemedrone", MalwareClass::Stealer },   { "stealerium", MalwareClass::Stealer },
        { "pony", MalwareClass::Stealer },
        { "snakekeylogger", MalwareClass::Keylogger }, { "masslogger", MalwareClass::Keylogger },
        { "hawkeye", MalwareClass::Keylogger },    { "keylog", MalwareClass::Keylogger },
        { "remcos", MalwareClass::Rat },           { "asyncrat", MalwareClass::Rat },
        { "njrat", MalwareClass::Rat },            { "nanocore", MalwareClass::Rat },
        { "xworm", MalwareClass::Rat },            { "dcrat", MalwareClass::Rat },
        { "quasar", MalwareClass::Rat },           { "avemaria", MalwareClass::Rat },
        { "warzone", MalwareClass::Rat },          { "netwire", MalwareClass::Rat },
        { "venomrat", MalwareClass::Rat },         { "orcus", MalwareClass::Rat },
        { "darkcomet", MalwareClass::Rat },        { "bitrat", MalwareClass::Rat },
        { "gh0st", MalwareClass::Rat },            { "plugx", MalwareClass::Rat },
        { "netsupport", MalwareClass::Rat },       { "darkgate", MalwareClass::Rat },
        { "cobaltstrike", MalwareClass::Backdoor },{ "sliver", MalwareClass::Backdoor },
        { "meterpreter", MalwareClass::Backdoor }, { "bruteratel", MalwareClass::Backdoor },
        { "havoc", MalwareClass::Backdoor },       { "systembc", MalwareClass::Backdoor },
        { "socks5systemz", MalwareClass::Backdoor },
        { "lockbit", MalwareClass::Ransomware },   { "conti", MalwareClass::Ransomware },
        { "ryuk", MalwareClass::Ransomware },      { "revil", MalwareClass::Ransomware },
        { "sodinokibi", MalwareClass::Ransomware },{ "gandcrab", MalwareClass::Ransomware },
        { "djvu", MalwareClass::Ransomware },
        { "phobos", MalwareClass::Ransomware },    { "dharma", MalwareClass::Ransomware },
        { "babuk", MalwareClass::Ransomware },     { "blackcat", MalwareClass::Ransomware },
        { "akira", MalwareClass::Ransomware },     { "wannacry", MalwareClass::Ransomware },
        { "blackbasta", MalwareClass::Ransomware },{ "medusa", MalwareClass::Ransomware },
        { "coinminer", MalwareClass::Miner },      { "xmrig", MalwareClass::Miner },
        { "guloader", MalwareClass::Loader },      { "smokeloader", MalwareClass::Loader },
        { "smoke loader", MalwareClass::Loader },  { "amadey", MalwareClass::Loader },
        { "gcleaner", MalwareClass::Loader },      { "privateloader", MalwareClass::Loader },
        { "bumblebee", MalwareClass::Loader },     { "pikabot", MalwareClass::Loader },
        { "latrodectus", MalwareClass::Loader },   { "hijackloader", MalwareClass::Loader },
        { "heodo", MalwareClass::Loader },         { "emotet", MalwareClass::Loader },
        { "quakbot", MalwareClass::Loader },       { "qakbot", MalwareClass::Loader },
        { "icedid", MalwareClass::Loader },        { "silentbuilder", MalwareClass::Loader },
        { "dridex", MalwareClass::Banker },        { "trickbot", MalwareClass::Banker },
        { "gozi", MalwareClass::Banker },          { "ursnif", MalwareClass::Banker },
        { "zeus", MalwareClass::Banker },          { "zloader", MalwareClass::Banker },
        { "mirai", MalwareClass::Botnet },         { "gafgyt", MalwareClass::Botnet },
        { "prometei", MalwareClass::Botnet },      { "phorpiex", MalwareClass::Worm },
        { "mimikatz", MalwareClass::HackTool },
    };
    return k;
}

} // namespace

MalwareClass FromName(const std::string& rawName) {
    const std::string n = Lower(rawName);
    if (n.empty()) return MalwareClass::Generic;

    if (Has(n, "eicar")) return MalwareClass::TestFile;

    // Сначала общие слова в имени — они надёжнее перечня семейств.
    if (Has(n, "ransom")) return MalwareClass::Ransomware;
    if (Has(n, "keylog")) return MalwareClass::Keylogger;
    if (Has(n, "steal") || Has(n, "grabber") || Has(n, "_pws") || Has(n, "infostealer"))
        return MalwareClass::Stealer;
    if (Has(n, "miner") || Has(n, "xmrig") || Has(n, "cryptojack")) return MalwareClass::Miner;
    if (Has(n, "webshell")) return MalwareClass::Webshell;
    if (Has(n, "rootkit") || Has(n, "bootkit")) return MalwareClass::Rootkit;
    if (Has(n, "banker") || Has(n, "banking")) return MalwareClass::Banker;
    if (Has(n, "worm")) return MalwareClass::Worm;
    if (Has(n, "hktl") || Has(n, "hacktool")) return MalwareClass::HackTool;
    if (Has(n, "pua_") || Has(n, "_pua") || Has(n, "riskware") || Has(n, "adware"))
        return MalwareClass::Pua;
    if (Has(n, "expl_") || Has(n, "exploit") || Has(n, "_cve_")) return MalwareClass::Exploit;

    for (const auto& [family, cls] : KnownFamilies()) {
        if (Has(n, family)) return cls;
    }

    if (Has(n, "_rat_") || Has(n, "_rat") || n.rfind("rat_", 0) == 0) return MalwareClass::Rat;
    if (Has(n, "backdoor") || Has(n, "implant") || Has(n, "beacon")) return MalwareClass::Backdoor;
    if (Has(n, "loader") || Has(n, "dropper") || Has(n, "downloader") || Has(n, "injector"))
        return MalwareClass::Loader;
    if (Has(n, "botnet")) return MalwareClass::Botnet;
    if (Has(n, "susp") || Has(n, "indicator")) return MalwareClass::Suspicious;
    return MalwareClass::Generic;
}

Strength RuleStrength(const std::string& rawRule, int score) {
    const std::string r = Lower(rawRule);

    // Индикаторы: упаковщики, обфускаторы, «подозрительные» признаки,
    // хакерские инструменты и драйверы, которые можно использовать во зло.
    // Сами по себе вредоносность не доказывают.
    static const char* kIndicator[] = {
        "susp", "indicator", "_obf", "obfusc", "packer", "packed", "_bundled",
        "singlefilehost", "hktl", "hacktool", "pua_", "_pua", "loldrivers",
        "generic_", "_generic", "heuristic", "anomaly", "_lnx_", "linux", "_elf",
        "macos", "_osx_", "android",
    };
    for (const char* k : kIndicator)
        if (Has(r, k)) return Strength::Indicator;

    // Автоматически сгенерированные правила Malpedia и общие «заглушки»
    // загрузчиков цепляются за код популярных библиотек.
    if (Has(r, "_auto") || Has(r, "stub") || Has(r, "shellcode"))
        return Strength::Weak;

    if (score >= 80) return Strength::Strong;
    return Strength::Normal;
}

std::string FamilyFromRule(const std::string& rule) {
    // MALPEDIA_Win_<Family>_Auto, CAPE_<Family>, DITEKSHEN_MALWARE_Win_<Family>,
    // SIGNATURE_BASE_MAL_<...>_<Family>_<Date>
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= rule.size()) {
        const size_t end = rule.find('_', start);
        parts.push_back(rule.substr(start, end == std::string::npos ? std::string::npos : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }

    static const char* kNoise[] = {
        "MALPEDIA", "CAPE", "DITEKSHEN", "MALWARE", "SIGNATURE", "BASE", "Win", "WIN",
        "MAL", "Mal", "Auto", "SEKOIA", "ARKBIRD", "SOLG", "RUSSIANPANDA", "ESET", "GCTI",
        "VOLEXITY", "TRELLIX", "ARC", "FIREEYE", "RT", "HARFANGLAB", "AVASTTI",
        "BLACKBERRY", "Ransom", "RANSOM", "Stealer", "Payload", "Loader", "Rat", "RAT",
        "APT", "Apt", "Malware", "Backdoor", "Trojan", "Unpacked", "Config", "Strings",
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        "INDICATOR", "SUSP", "NET", "DOTNET", "X64", "X86", "Generic", "Detect",
        "WITHSECURELABS", "EMBEERESEARCH", "ELCEEF", "SECUINFRA", "NCSC", "CRAIU",
        "TELEKOM", "SECURITY", "CADOSECURITY", "SBOUSSEADEN", "COD3NYM", "IIS",
        "Infostealer", "INFOSTEALER", "Str", "Stealers", "Keylogger", "Miner", "Dropper",
        "Downloader", "Injector", "Hacktool", "HKTL", "PUA", "Lnx", "Linux", "Mem", "Hunting",
        "RULE", "Rule", "Ind", "Sus", "B64", "Obfusc", "MSIL", "PE", "DLL", "EXE", "Bin",
        "OBF", "Indicators", "Indicator", "Auto", "Stub",
    };
    auto noise = [&](const std::string& p) {
        if (p.empty()) return true;
        if (std::all_of(p.begin(), p.end(), [](unsigned char c) { return std::isdigit(c); }))
            return true;
        if (p.size() <= 3 && std::isdigit(static_cast<unsigned char>(p.back()))) return true;
        // Даты вида Jan24, 2023, v2.
        if (p.size() <= 6 && std::isdigit(static_cast<unsigned char>(p.back())) &&
            std::isalpha(static_cast<unsigned char>(p.front())) && p.size() >= 4)
            return true;
        for (const char* k : kNoise) if (p == k) return true;
        return false;
    };

    // Семейство — первая непрерывная серия «значащих» частей: у Malpedia
    // название бывает из двух слов (Agent_Tesla → «Agent Tesla»).
    std::string family;
    int taken = 0;
    for (const std::string& p : parts) {
        if (noise(p) || p.size() < 3) {
            if (!family.empty()) break;
            continue;
        }
        if (!family.empty()) family += ' ';
        family += p;
        if (++taken == 3) break;
    }
    return family;
}

const char* ClassCode(MalwareClass cls) {
    switch (cls) {
    case MalwareClass::Stealer:    return "Stealer";
    case MalwareClass::Keylogger:  return "Keylogger";
    case MalwareClass::Rat:        return "RAT";
    case MalwareClass::Backdoor:   return "Backdoor";
    case MalwareClass::Ransomware: return "Ransomware";
    case MalwareClass::Miner:      return "Miner";
    case MalwareClass::Loader:     return "Loader";
    case MalwareClass::Banker:     return "Banker";
    case MalwareClass::Worm:       return "Worm";
    case MalwareClass::Exploit:    return "Exploit";
    case MalwareClass::HackTool:   return "HackTool";
    case MalwareClass::Pua:        return "PUA";
    case MalwareClass::Webshell:   return "Webshell";
    case MalwareClass::Rootkit:    return "Rootkit";
    case MalwareClass::Botnet:     return "Botnet";
    case MalwareClass::TestFile:   return "TestFile";
    case MalwareClass::Deceptive:  return "Deceptive";
    case MalwareClass::Suspicious: return "Suspicious";
    default:                       return "Malware";
    }
}

} // namespace Classify
