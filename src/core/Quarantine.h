#pragma once

#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <chrono>

// Запись о файле в карантине
struct QuarantineItem {
    std::string  id;            // уникальный id (имя файла в карантине без расширения)
    std::wstring originalPath;  // откуда был взят
    std::wstring originalName;  // оригинальное имя файла
    std::wstring threatName;    // что за угроза
    std::wstring severity;      // CRIT/HIGH/...
    std::string  quarantinedAt; // ISO-время
    uint64_t     size = 0;
};

// Движок карантина: изоляция файлов в защищённой папке.
// Файлы XOR-обфусцируются, чтобы не могли исполняться и не палились
// другими антивирусами как активная угроза.
class Quarantine {
public:
    static Quarantine& Instance();

    // Папка карантина (%ProgramData%\ThreatScanner\Quarantine)
    std::filesystem::path Dir() const { return dir_; }

    // Поместить файл в карантин. Возвращает id при успехе.
    std::optional<std::string> QuarantineFile(
        const std::wstring& filePath,
        const std::wstring& threatName,
        const std::wstring& severity);

    // Восстановить файл из карантина на исходное место. Если там уже
    // лежит другой файл, он не затирается: восстановленный получает имя
    // «… (restored)». Куда именно — LastRestoredPath().
    bool Restore(const std::string& id);
    const std::wstring& LastRestoredPath() const { return lastRestoredPath_; }

    // Удалить файл из карантина навсегда.
    bool DeletePermanently(const std::string& id);

    // Список всех элементов в карантине.
    std::vector<QuarantineItem> List() const;

    // Сколько записей в карантине — без чтения самих записей.
    size_t Count() const;

    // Последний QuarantineFile не смог удалить занятый оригинал сразу
    // и поставил удаление на перезагрузку.
    bool LastPendingReboot() const { return lastPendingReboot_; }

private:
    Quarantine();
    void EnsureDir();
    std::filesystem::path MetaPath(const std::string& id) const;
    std::filesystem::path BlobPath(const std::string& id) const;

    std::filesystem::path dir_;
    bool lastPendingReboot_ = false;
    std::wstring lastRestoredPath_;
};
