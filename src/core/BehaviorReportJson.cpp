#include "BehaviorReportJson.h"

#include <Windows.h>
#include <fstream>
#include <sstream>
#include <cstring>

namespace {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

// Строку экранируем уже в UTF-8: все байты многобайтных символов
// больше 0x7F, под управляющие последовательности они не попадают.
std::string JsonString(const std::wstring& value) {
    const std::string utf8 = WideToUtf8(value);
    std::string out;
    out.reserve(utf8.size() + 2);
    out += '"';
    for (unsigned char c : utf8) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                char buf[8];
                sprintf_s(buf, "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
    return out;
}

std::string JsonString(const char* value) {
    return JsonString(std::wstring(value, value + strlen(value)));
}

} // namespace

const char* BehaviorEventTypeSlug(BehaviorEventType type) {
    switch (type) {
    case BehaviorEventType::ProcessStarted:       return "process_started";
    case BehaviorEventType::ProcessExited:        return "process_exited";
    case BehaviorEventType::FileCreated:          return "file_created";
    case BehaviorEventType::FileModified:         return "file_modified";
    case BehaviorEventType::FileDeleted:          return "file_deleted";
    case BehaviorEventType::FileRenamed:          return "file_renamed";
    case BehaviorEventType::RegistryValueSet:     return "registry_value_set";
    case BehaviorEventType::RegistryValueChanged: return "registry_value_changed";
    case BehaviorEventType::RegistryValueDeleted: return "registry_value_deleted";
    case BehaviorEventType::RegistryKeyCreated:   return "registry_key_created";
    case BehaviorEventType::RegistryKeyDeleted:   return "registry_key_deleted";
    case BehaviorEventType::NetworkConnection:    return "network_connection";
    case BehaviorEventType::NetworkListen:        return "network_listen";
    case BehaviorEventType::MonitorNote:          return "monitor_note";
    }
    return "monitor_note";
}

BehaviorEventType BehaviorEventTypeFromSlug(const char* slug, bool* ok) {
    static const BehaviorEventType kAll[] = {
        BehaviorEventType::ProcessStarted,
        BehaviorEventType::ProcessExited,
        BehaviorEventType::FileCreated,
        BehaviorEventType::FileModified,
        BehaviorEventType::FileDeleted,
        BehaviorEventType::FileRenamed,
        BehaviorEventType::RegistryValueSet,
        BehaviorEventType::RegistryValueChanged,
        BehaviorEventType::RegistryValueDeleted,
        BehaviorEventType::RegistryKeyCreated,
        BehaviorEventType::RegistryKeyDeleted,
        BehaviorEventType::NetworkConnection,
        BehaviorEventType::NetworkListen,
        BehaviorEventType::MonitorNote,
    };

    if (slug) {
        for (auto type : kAll) {
            if (strcmp(slug, BehaviorEventTypeSlug(type)) == 0) {
                if (ok) *ok = true;
                return type;
            }
        }
    }
    // Неизвестный слаг — это отчёт от более новой версии агента.
    // Роняться из-за этого нельзя, но и молча выдавать чужое событие
    // за понятное тоже: пусть будет заметкой наблюдателя.
    if (ok) *ok = false;
    return BehaviorEventType::MonitorNote;
}

std::string BehaviorReportToJson(const BehaviorReport& r) {
    std::ostringstream os;

    os << "{\n";
    os << "  \"version\": 1,\n";
    os << "  \"target\": "        << JsonString(r.target)        << ",\n";
    os << "  \"arguments\": "     << JsonString(r.arguments)     << ",\n";
    os << "  \"durationMs\": "    << r.durationMs                << ",\n";
    os << "  \"timedOut\": "      << (r.timedOut ? "true" : "false")     << ",\n";
    os << "  \"killed\": "        << (r.killed ? "true" : "false")       << ",\n";
    os << "  \"launchFailed\": "  << (r.launchFailed ? "true" : "false") << ",\n";
    os << "  \"failureReason\": " << JsonString(r.failureReason) << ",\n";
    os << "  \"rootExitCode\": "  << r.rootExitCode              << ",\n";

    os << "  \"processes\": [\n";
    for (size_t i = 0; i < r.processes.size(); ++i) {
        const auto& p = r.processes[i];
        os << "    {"
           << "\"pid\": "         << p.pid
           << ", \"parentPid\": " << p.parentPid
           << ", \"image\": "     << JsonString(p.image)
           << ", \"commandLine\": " << JsonString(p.commandLine)
           << ", \"startedAtMs\": " << p.startedAtMs
           << ", \"exitedAtMs\": "  << p.exitedAtMs
           << ", \"exitCode\": "    << p.exitCode
           << ", \"isRoot\": "      << (p.isRoot ? "true" : "false")
           << "}" << (i + 1 < r.processes.size() ? "," : "") << "\n";
    }
    os << "  ],\n";

    os << "  \"events\": [\n";
    for (size_t i = 0; i < r.events.size(); ++i) {
        const auto& e = r.events[i];
        os << "    {"
           << "\"type\": "      << JsonString(BehaviorEventTypeSlug(e.type))
           << ", \"atMs\": "    << e.atMs
           << ", \"pid\": "     << e.pid
           << ", \"target\": "  << JsonString(e.target)
           << ", \"detail\": "  << JsonString(e.detail)
           << "}" << (i + 1 < r.events.size() ? "," : "") << "\n";
    }
    os << "  ],\n";

    os << "  \"limitations\": [\n";
    for (size_t i = 0; i < r.limitations.size(); ++i) {
        os << "    " << JsonString(r.limitations[i])
           << (i + 1 < r.limitations.size() ? "," : "") << "\n";
    }
    os << "  ]\n";
    os << "}\n";

    return os.str();
}

bool WriteBehaviorReportJson(const BehaviorReport& report,
                             const std::wstring& path,
                             std::wstring* error)
{
    // Пишем во временный файл рядом и переименовываем: хост может
    // заглянуть в папку в любой момент, и увидеть половину отчёта
    // он не должен.
    const std::wstring temp = path + L".part";

    {
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        if (!file) {
            if (error) *error = L"Cannot create " + temp;
            return false;
        }
        file << BehaviorReportToJson(report);
        if (!file) {
            if (error) *error = L"Failed while writing " + temp;
            return false;
        }
    }

    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        if (error) {
            *error = L"Cannot move report into place: " + path +
                     L" (error " + std::to_wstring(GetLastError()) + L")";
        }
        return false;
    }
    return true;
}
