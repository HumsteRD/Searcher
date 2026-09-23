#include "FileActivityWatcher.h"
#include "Logger.h"

#include <algorithm>

namespace {

// Ключ завершения, которым будим поток на выходе. Никакой Root по этому
// адресу не лежит, спутать нельзя.
constexpr ULONG_PTR kQuitKey = 1;

constexpr DWORD kFilter =
      FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_CREATION;

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring JoinPath(const std::wstring& root, const std::wstring& rel) {
    if (root.empty()) return rel;
    if (root.back() == L'\\' || root.back() == L'/') return root + rel;
    return root + L"\\" + rel;
}

} // namespace

FileActivityWatcher::~FileActivityWatcher() {
    Stop();
}

bool FileActivityWatcher::Start(const std::vector<std::wstring>& roots,
                                BehaviorSink sink)
{
    if (port_) return false;   // уже запущен
    sink_ = std::move(sink);

    port_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (!port_) {
        Logger::Instance().Error("[Dyn/FS] completion port failed");
        return false;
    }

    // Дубликаты корней дали бы двойные события на один и тот же файл.
    std::vector<std::wstring> unique;
    for (const auto& r : roots) {
        if (r.empty()) continue;
        if (std::find(unique.begin(), unique.end(), r) == unique.end())
            unique.push_back(r);
    }

    for (const auto& path : unique) {
        auto root = std::make_unique<Root>();
        root->path = path;
        root->dir = CreateFileW(
            path.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr);

        if (root->dir == INVALID_HANDLE_VALUE) {
            Logger::Instance().Warn("[Dyn/FS] cannot watch " + WideToUtf8(path) +
                                    ", error " + std::to_string(GetLastError()));
            continue;
        }

        if (!CreateIoCompletionPort(root->dir, port_,
                                    reinterpret_cast<ULONG_PTR>(root.get()), 1)) {
            CloseHandle(root->dir);
            continue;
        }

        Root* raw = root.get();
        roots_.push_back(std::move(root));
        if (!Arm(*raw)) {
            Logger::Instance().Warn("[Dyn/FS] ReadDirectoryChangesW failed for " +
                                    WideToUtf8(path));
            continue;
        }
        watched_.push_back(path);
    }

    if (watched_.empty()) {
        Stop();
        return false;
    }

    thread_ = std::thread([this] { Pump(); });
    return true;
}

bool FileActivityWatcher::Arm(Root& root) {
    ZeroMemory(&root.ov, sizeof(root.ov));
    return ReadDirectoryChangesW(root.dir, root.buffer, sizeof(root.buffer),
                                 TRUE, kFilter, nullptr, &root.ov, nullptr) != FALSE;
}

void FileActivityWatcher::Stop() {
    if (!port_) return;

    stopping_ = true;
    for (auto& r : roots_) {
        if (r->dir != INVALID_HANDLE_VALUE) CancelIoEx(r->dir, &r->ov);
    }
    PostQueuedCompletionStatus(port_, 0, kQuitKey, nullptr);

    if (thread_.joinable()) thread_.join();

    for (auto& r : roots_) {
        if (r->dir != INVALID_HANDLE_VALUE) CloseHandle(r->dir);
    }
    roots_.clear();
    watched_.clear();
    lastSeen_.clear();

    CloseHandle(port_);
    port_ = nullptr;
    stopping_ = false;
}

void FileActivityWatcher::Emit(BehaviorEventType type, const std::wstring& path,
                               const std::wstring& detail)
{
    if (!sink_) return;

    // Окно склейки одинаковых событий. Зовётся только из потока Pump,
    // блокировка не нужна.
    constexpr ULONGLONG kDedupWindowMs = 1000;
    if (type != BehaviorEventType::MonitorNote) {
        const std::wstring key = std::to_wstring(static_cast<int>(type)) + L"|" + path;
        const ULONGLONG now = GetTickCount64();
        auto it = lastSeen_.find(key);
        if (it != lastSeen_.end() && now - it->second < kDedupWindowMs) {
            it->second = now;
            return;
        }
        if (lastSeen_.size() > 4096) lastSeen_.clear();   // не растём без конца
        lastSeen_[key] = now;
    }

    BehaviorEvent e;
    e.type   = type;
    e.pid    = 0;            // источник изменения неизвестен — см. заголовок
    e.target = path;
    e.detail = detail;
    sink_(std::move(e));
}

void FileActivityWatcher::Pump() {
    for (;;) {
        DWORD       bytes = 0;
        ULONG_PTR   key = 0;
        OVERLAPPED* ov = nullptr;

        BOOL ok = GetQueuedCompletionStatus(port_, &bytes, &key, &ov, INFINITE);

        if (key == kQuitKey) break;
        if (stopping_) break;

        Root* root = reinterpret_cast<Root*>(key);
        if (!root) continue;

        if (!ok) {
            // ERROR_OPERATION_ABORTED приходит на CancelIoEx при остановке;
            // всё остальное — потеря наблюдения за этим корнем.
            DWORD err = GetLastError();
            if (err != ERROR_OPERATION_ABORTED) {
                Emit(BehaviorEventType::MonitorNote, root->path,
                     L"Directory watch stopped, error " + std::to_wstring(err));
            }
            continue;
        }

        if (bytes == 0) {
            // Буфер переполнился: ядро сообщает «изменений было слишком
            // много», не перечисляя их. Молчать об этом нельзя — иначе
            // отчёт выглядит так, будто ничего и не происходило.
            Emit(BehaviorEventType::MonitorNote, root->path,
                 L"Change buffer overflowed, some file events were lost");
            Arm(*root);
            continue;
        }

        const BYTE* p = reinterpret_cast<const BYTE*>(root->buffer);
        for (;;) {
            auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(p);
            std::wstring rel(info->FileName,
                             info->FileNameLength / sizeof(wchar_t));
            std::wstring full = JoinPath(root->path, rel);

            switch (info->Action) {
            case FILE_ACTION_ADDED:
                Emit(BehaviorEventType::FileCreated, full);
                break;
            case FILE_ACTION_REMOVED:
                Emit(BehaviorEventType::FileDeleted, full);
                break;
            case FILE_ACTION_MODIFIED:
                Emit(BehaviorEventType::FileModified, full);
                break;
            case FILE_ACTION_RENAMED_OLD_NAME:
                root->pendingRenameFrom = full;
                break;
            case FILE_ACTION_RENAMED_NEW_NAME:
                // Пара OLD/NEW приходит двумя записями подряд; одиночный
                // NEW без пары бывает, если старое имя вне наблюдаемого корня.
                Emit(BehaviorEventType::FileRenamed, full,
                     root->pendingRenameFrom.empty()
                         ? L"renamed from outside the watched root"
                         : L"from " + root->pendingRenameFrom);
                root->pendingRenameFrom.clear();
                break;
            default:
                break;
            }

            if (info->NextEntryOffset == 0) break;
            p += info->NextEntryOffset;
        }

        if (!Arm(*root) && !stopping_) {
            Emit(BehaviorEventType::MonitorNote, root->path,
                 L"Directory watch could not be re-armed");
        }
    }
}
