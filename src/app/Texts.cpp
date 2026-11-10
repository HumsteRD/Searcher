#include "Texts.h"
#include "Lang.h"

#include "../engine/Classify.h"
#include "../engine/Verdict.h"

#include <QHash>
#include <QStringList>

namespace Texts {
namespace {

QStringList Split(const std::string& code) {
    return QString::fromUtf8(code.data(), static_cast<int>(code.size())).split('\t');
}

QString Arg(const QStringList& parts, int i) {
    return i < parts.size() ? parts[i] : QString();
}

const QHash<QString, const char*>& ScriptReasons() {
    static const QHash<QString, const char*> k = {
        { "script.download-exec", "Downloads code from the internet and runs it" },
        { "script.download", "Downloads files from the internet" },
        { "script.drop-file", "Writes downloaded data to disk as a file" },
        { "script.lolbin-download", "Uses a Windows system tool to download files" },
        { "script.lolbin-decode", "Uses a Windows system tool to decode hidden data" },
        { "script.dynamic-code", "Builds and runs code on the fly, so the real code is not visible in the file" },
        { "script.encoded", "Runs a command hidden inside encoded text" },
        { "script.base64", "Decodes hidden Base64 data" },
        { "script.hidden-window", "Runs without showing a window" },
        { "script.shell", "Starts other programs" },
        { "script.defender", "Changes or turns off Microsoft Defender" },
        { "script.defender-exclusion", "Hides folders from Microsoft Defender" },
        { "script.amsi-bypass", "Disables the Windows anti-malware scan interface" },
        { "script.firewall", "Changes firewall rules" },
        { "script.autorun", "Adds itself to Windows startup" },
        { "script.task", "Creates a scheduled task to run again later" },
        { "script.service", "Installs a Windows service" },
        { "script.startup", "Puts a file into the Startup folder" },
        { "script.clipboard", "Reads the clipboard" },
        { "script.browser-passwords", "Reads passwords saved in browsers" },
        { "script.browser-cookies", "Reads browser cookies, that is, your signed-in sessions" },
        { "script.keylogger", "Records keystrokes" },
        { "script.self-delete", "Deletes itself after running" },
        { "script.clear-logs", "Erases Windows event logs" },
        { "script.delete-backups", "Deletes backups and restore points, which is typical for ransomware" },
        { "script.miner", "Connects to a cryptocurrency mining pool" },
        { "script.obfuscated", "Contains scrambled text that hides the real content" },
        { "cmd.encoded", "Runs PowerShell with a hidden (encoded) command" },
        { "cmd.download", "Downloads code from the internet and runs it" },
        { "cmd.mshta", "Runs a script through mshta, a common fileless attack technique" },
        { "cmd.regsvr32", "Uses regsvr32 to run a script from the internet" },
        { "cmd.rundll32-script", "Uses rundll32 to run script code" },
        { "cmd.certutil", "Uses certutil to download or decode files, a common way to disguise a download" },
        { "cmd.bitsadmin", "Uses bitsadmin to download files in the background" },
        { "cmd.hidden-script", "Runs a script in hidden mode" },
        { "winlogon.shell", "Replaces or extends the Windows desktop shell (Winlogon Shell)" },
        { "winlogon.userinit", "Adds a program to the Windows sign-in sequence (Winlogon Userinit)" },
        { "ifeo.accessibility", "Replaces an accessibility tool on the sign-in screen, which lets anyone open a command prompt without a password" },
        { "ifeo.debugger", "Hijacks the launch of a system program (Image File Execution Options)" },
        { "appinit", "Loads a library into every program that starts (AppInit_DLLs)" },
        { "location.risky", "Located in a folder where downloaded and temporary files usually end up" },
        { "task.disabled", "The task is currently turned off" },
        { "behavior", "Behaved dangerously when it was run in an isolated sandbox" },
        { "behavior.timeout", "Observation stopped at the time limit, so this may not be everything" },
        { "eicar", "This is the EICAR test file. It is harmless and exists only to check that antivirus software works" },
    };
    return k;
}

} // namespace

QString classTitle(int cls) {
    switch (static_cast<MalwareClass>(cls)) {
    case MalwareClass::Stealer:    return TR("Data stealer");
    case MalwareClass::Keylogger:  return TR("Keylogger");
    case MalwareClass::Rat:        return TR("Remote access trojan");
    case MalwareClass::Backdoor:   return TR("Backdoor");
    case MalwareClass::Ransomware: return TR("Ransomware");
    case MalwareClass::Miner:      return TR("Hidden miner");
    case MalwareClass::Loader:     return TR("Malware loader");
    case MalwareClass::Banker:     return TR("Banking trojan");
    case MalwareClass::Worm:       return TR("Worm");
    case MalwareClass::Exploit:    return TR("Exploit");
    case MalwareClass::HackTool:   return TR("Hacking tool");
    case MalwareClass::Pua:        return TR("Potentially unwanted program");
    case MalwareClass::Webshell:   return TR("Web shell");
    case MalwareClass::Rootkit:    return TR("Rootkit");
    case MalwareClass::Botnet:     return TR("Botnet agent");
    case MalwareClass::TestFile:   return TR("Antivirus test file");
    case MalwareClass::Deceptive:  return TR("Disguised file");
    case MalwareClass::Suspicious: return TR("Suspicious item");
    default:                       return TR("Malicious program");
    }
}

QString classExplain(int cls) {
    switch (static_cast<MalwareClass>(cls)) {
    case MalwareClass::Stealer:
        return TR("Steals saved passwords, browser cookies, messenger sessions and crypto wallets, and sends them to attackers.");
    case MalwareClass::Keylogger:
        return TR("Records everything you type, including passwords, and sends it to attackers.");
    case MalwareClass::Rat:
        return TR("Gives an attacker remote control over this computer: files, screen, camera and keyboard.");
    case MalwareClass::Backdoor:
        return TR("Opens a hidden way in for an attacker to run commands on this computer.");
    case MalwareClass::Ransomware:
        return TR("Encrypts your files and demands a ransom to get them back.");
    case MalwareClass::Miner:
        return TR("Uses your processor and graphics card to mine cryptocurrency for someone else.");
    case MalwareClass::Loader:
        return TR("Downloads and installs other malware.");
    case MalwareClass::Banker:
        return TR("Steals online banking credentials and payment data.");
    case MalwareClass::Worm:
        return TR("Spreads to other computers and removable drives by itself.");
    case MalwareClass::Exploit:
        return TR("Abuses a vulnerability to gain more rights or run its own code.");
    case MalwareClass::HackTool:
        return TR("A tool that attackers use. It can also have legitimate uses.");
    case MalwareClass::Pua:
        return TR("Not necessarily malicious, but does things most people do not want.");
    case MalwareClass::Webshell:
        return TR("Gives remote control over a web server.");
    case MalwareClass::Rootkit:
        return TR("Hides malware deep inside the system.");
    case MalwareClass::Botnet:
        return TR("Makes this computer part of a network controlled by attackers.");
    case MalwareClass::TestFile:
        return TR("Harmless. It exists only to check that antivirus software reacts.");
    case MalwareClass::Deceptive:
        return TR("Pretends to be something harmless to trick you into running it.");
    case MalwareClass::Suspicious:
        return TR("Shows several signs typical of malware, but is not a known threat.");
    default:
        return TR("Matches known malware.");
    }
}

QString severityLabel(Severity s) {
    switch (s) {
    case Severity::Critical: return TR("Critical");
    case Severity::High:     return TR("High");
    case Severity::Medium:   return TR("Medium");
    case Severity::Low:      return TR("Low");
    default:                 return TR("Info");
    }
}

QString severityCode(Severity s) {
    switch (s) {
    case Severity::Critical: return "CRIT";
    case Severity::High:     return "HIGH";
    case Severity::Medium:   return "MED";
    case Severity::Low:      return "LOW";
    default:                 return "INFO";
    }
}

QString statusLabel(ThreatStatus s) {
    switch (s) {
    case ThreatStatus::Ignored:     return TR("Skipped");
    case ThreatStatus::Quarantined: return TR("In quarantine");
    case ThreatStatus::Deleted:     return TR("Removed");
    case ThreatStatus::Disabled:    return TR("Disabled");
    case ThreatStatus::Restored:    return TR("Restored");
    case ThreatStatus::Failed:      return TR("Action failed");
    default:                        return TR("Needs action");
    }
}

QString statusTone(ThreatStatus s) {
    switch (s) {
    case ThreatStatus::Quarantined:
    case ThreatStatus::Deleted:
    case ThreatStatus::Disabled:    return "OK";
    case ThreatStatus::Failed:      return "CRIT";
    case ThreatStatus::Pending:     return "ACCENT";
    default:                        return "INFO";
    }
}

QString kindLabel(ThreatKind k) {
    switch (k) {
    case ThreatKind::RegistryValue: return TR("Startup entry");
    case ThreatKind::ScheduledTask: return TR("Scheduled task");
    case ThreatKind::Process:       return TR("Running process");
    case ThreatKind::Service:       return TR("Service");
    case ThreatKind::WmiConsumer:   return TR("WMI subscription");
    case ThreatKind::HostsEntry:    return TR("hosts file entry");
    default:                        return TR("File");
    }
}

QString stageLabel(const QString& stage) {
    if (stage == "Preparing")  return TR("Loading signature databases");
    if (stage == "Processes")  return TR("Checking running programs");
    if (stage == "Autoruns")   return TR("Checking startup items");
    if (stage == "Tasks")      return TR("Checking scheduled tasks");
    if (stage == "Services")   return TR("Checking services and drivers");
    if (stage == "Network")    return TR("Checking network connections");
    if (stage == "Files")      return TR("Checking files");
    if (stage == "Done")       return TR("Finishing");
    return stage;
}

QString modeLabel(int mode) {
    switch (mode) {
    case 1:  return TR("Full scan");
    case 2:  return TR("Custom scan");
    default: return TR("Quick scan");
    }
}

QString actionResult(const QString& code, bool ok) {
    QStringList out;
    for (const QString& part : code.split('+', Qt::SkipEmptyParts)) {
        if (part == "quarantined")          out << TR("moved to quarantine");
        else if (part == "quarantined-reboot") out << TR("moved to quarantine, the original will be removed after a restart");
        else if (part == "deleted")         out << TR("deleted");
        else if (part == "ignored")         out << TR("skipped");
        else if (part == "trusted")         out << TR("marked as trusted, future scans skip it");
        else if (part == "entry-removed")   out << TR("the entry was removed");
        else if (part == "disabled")        out << TR("the service was stopped and disabled");
        else if (part == "killed")          out << TR("the process was stopped");
        else if (part == "file-failed")     out << TR("the file itself could not be moved");
        else if (part == "missing")         out << TR("the object no longer exists");
        else if (part == "denied")          out << TR("access denied or the file is in use");
        else if (part == "unavailable")     out << TR("the system component is unavailable");
        else if (part == "already-handled") out << TR("an action was already applied");
        else if (part == "helper-gone")     out << TR("the helper with administrator rights is not running");
        else                                out << part;
    }
    QString s = out.join("; ");
    if (!s.isEmpty()) s[0] = s[0].toUpper();
    if (s.isEmpty()) s = ok ? TR("Done") : TR("Failed");
    return s;
}

QList<Reason> reasons(const Threat& t) {
    QList<Reason> out;
    bool yaraSaid = false;

    for (const std::string& raw : t.reasons) {
        const QStringList p = Split(raw);
        const QString code = Arg(p, 0);

        if (code == "hash") {
            const QString family = Arg(p, 1);
            Reason r;
            r.text = family.isEmpty()
                ? TR("Exactly matches a known malicious file from the MalwareBazaar database")
                : TR("Exactly matches a known malicious file: %1 (MalwareBazaar database)").arg(family);
            if (!Arg(p, 2).isEmpty()) r.detail = TR("Inside: %1").arg(Arg(p, 2));
            out << r;
        } else if (code == "yara") {
            const QString rule = Arg(p, 1);
            const QString desc = Arg(p, 3);
            const QString inner = Arg(p, 4);
            if (!yaraSaid) {
                const QString family = QString::fromStdString(Classify::FamilyFromRule(rule.toStdString()));
                Reason r;
                r.text = family.isEmpty() ? TR("Matches the signature of known malware")
                                          : TR("Matches the signature of %1").arg(family);
                if (!inner.isEmpty()) r.detail = TR("Inside: %1").arg(inner);
                out << r;
                yaraSaid = true;
            }
            Reason tech;
            tech.technical = true;
            tech.text = TR("Signature %1").arg(rule);
            tech.detail = desc;
            out << tech;
        } else if (code == "deceptive") {
            const QString why = Arg(p, 1);
            Reason r;
            if (why == "rtlo")
                r.text = TR("The name contains a hidden character that reverses text, so the real extension is disguised");
            else if (why == "padding")
                r.text = TR("The real extension is hidden behind a long run of spaces");
            else
                r.text = TR("Pretends to be a document: the name ends in %1, but it is a program")
                             .arg(why.section(':', 1));
            out << r;
        } else if (code == "container") {
            Reason r;
            r.technical = true;
            r.text = Arg(p, 1) == "pyinstaller"
                ? TR("A Python program packed with PyInstaller: its code was unpacked and checked")
                : TR("The contents of the archive were unpacked and checked");
            out << r;
        } else if (code == "origin") {
            // Адрес из «метки из интернета», которую ставит браузер.
            out << Reason{ TR("Downloaded from the internet"), Arg(p, 1) };
        } else if (code == "signed") {
            Reason r;
            r.technical = true;
            r.text = TR("Digitally signed by %1").arg(Arg(p, 1));
            out << r;
        } else if (code == "autorun") {
            out << Reason{ TR("Starts automatically when you sign in to Windows"), Arg(p, 1) };
        } else if (code == "runs") {
            out << Reason{ TR("Launches: %1").arg(Arg(p, 1)), {}, true };
        } else if (code == "task") {
            out << Reason{ TR("Runs on a schedule through Task Scheduler"), Arg(p, 1) };
        } else if (code == "service") {
            out << Reason{ TR("Installed as a Windows service and runs in the background"), Arg(p, 1) };
        } else if (code == "driver") {
            out << Reason{ TR("Installed as a system driver"), Arg(p, 1) };
        } else if (code == "process") {
            out << Reason{ TR("Running right now (process ID %1)").arg(Arg(p, 1)) };
        } else if (code == "wmi") {
            out << Reason{ TR("A hidden WMI subscription runs code on system events and survives restarts"),
                           Arg(p, 1) };
        } else if (code == "hosts.security") {
            out << Reason{ TR("The hosts file blocks %1, which cuts the computer off from security updates").arg(Arg(p, 1)),
                           Arg(p, 2) };
        } else if (code == "hosts.hijack") {
            out << Reason{ TR("The hosts file sends %1 to another server (%2), a classic phishing trick")
                               .arg(Arg(p, 1), Arg(p, 2)) };
        } else if (code == "masquerade") {
            out << Reason{ TR("Named like the Windows system process %1, but runs from a different folder").arg(Arg(p, 1)) };
        } else if (code == "net.pool") {
            out << Reason{ TR("Connected to a cryptocurrency mining pool (%1)").arg(Arg(p, 1)) };
        } else if (code == "net.stratum-port") {
            out << Reason{ TR("An unsigned program from a user folder uses a mining protocol port (%1)").arg(Arg(p, 1)) };
        } else if (code == "net.c2-port") {
            out << Reason{ TR("An unsigned program from a user folder talks on a port typical for remote-control tools (%1)").arg(Arg(p, 1)) };
        } else if (code == "behavior.finding") {
            out << Reason{ TR(Arg(p, 1)) };
        } else if (ScriptReasons().contains(code)) {
            out << Reason{ TR(ScriptReasons().value(code)) };
        } else if (!code.isEmpty()) {
            out << Reason{ code, {}, true };
        }
    }
    return out;
}

QString advice(const Threat& t) {
    const auto cls = static_cast<MalwareClass>(t.malwareClass);
    if (cls == MalwareClass::TestFile) return TR("No action is needed. You can delete the file.");
    if (t.kind == ThreatKind::HostsEntry) return TR("Remove the line from the hosts file if you did not add it yourself.");
    if (t.kind == ThreatKind::RegistryValue || t.kind == ThreatKind::ScheduledTask ||
        t.kind == ThreatKind::Service || t.kind == ThreatKind::WmiConsumer)
        return TR("Remove the entry and move the file it launches to quarantine.");
    if (cls == MalwareClass::Pua || cls == MalwareClass::HackTool)
        return TR("If you did not install it on purpose, remove it.");
    if (cls == MalwareClass::Deceptive || cls == MalwareClass::Suspicious || t.severity <= Severity::Medium)
        return TR("If you do not know where it came from, move it to quarantine.");
    if (t.kind == ThreatKind::Process)
        return TR("Stop the program and move its file to quarantine.");
    return TR("Move it to quarantine. The file stops working, and you can restore it if this is a mistake.");
}

QString headline(const Threat& t) {
    const QString title = classTitle(t.malwareClass);
    if (!t.family.empty() && static_cast<MalwareClass>(t.malwareClass) != MalwareClass::TestFile)
        return QString::fromStdString(t.family) + QStringLiteral(" · ") + title;
    return title;
}

} // namespace Texts
