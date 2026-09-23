#pragma once

#include <QString>

// Протокол между интерфейсом и привилегированным помощником.
//
// Одна строка — одно сообщение JSON в UTF-8, разделитель '\n'. Канал
// именованный, дуплексный: запросы идут в одну сторону, ответы и поток
// событий — в другую.
//
// Помощник запускается интерфейсом через UAC и живёт ровно столько,
// сколько открыт канал. Разрыв канала — команда на выход: висящий
// процесс с полными правами после закрытия окна не нужен никому.
namespace Ipc {

// Версия протокола. Помощник и интерфейс лежат рядом и обновляются
// вместе, но проверка рукопожатия стоит дёшево, а рассинхрон после
// частичного обновления ловится сразу и понятно.
inline constexpr int kProtocolVersion = 1;

// Поля сообщения.
inline constexpr const char* kFieldId      = "id";
inline constexpr const char* kFieldCommand = "cmd";
inline constexpr const char* kFieldArgs    = "args";
inline constexpr const char* kFieldOk      = "ok";
inline constexpr const char* kFieldError   = "error";
inline constexpr const char* kFieldResult  = "result";
inline constexpr const char* kFieldEvent   = "event";

// Команды.
inline constexpr const char* kCmdHello    = "hello";
inline constexpr const char* kCmdShutdown = "shutdown";

inline constexpr const char* kCmdStartScan   = "start_scan";
inline constexpr const char* kCmdCancelScan  = "cancel_scan";
inline constexpr const char* kCmdApplyAction = "apply_action";
inline constexpr const char* kCmdAddThreat   = "add_threat";

// Читать список карантина интерфейс умеет сам: хранилище лежит
// в %ProgramData% и открыто на чтение. А вот менять его — только сюда.
inline constexpr const char* kCmdQuarantineRestore = "quarantine_restore";
inline constexpr const char* kCmdQuarantineDelete  = "quarantine_delete";

// Windows Sandbox запускается только с правами администратора, поэтому
// сеанс целиком держит помощник. Наружу уходят стадии и путь к отчёту.
inline constexpr const char* kCmdSandboxRun    = "sandbox_run";
inline constexpr const char* kCmdSandboxCancel = "sandbox_cancel";

// Служба фоновых проверок. Ставится и удаляется только отсюда:
// диспетчер служб не разговаривает с непривилегированным процессом.
inline constexpr const char* kCmdServiceStatus    = "service_status";
inline constexpr const char* kCmdServiceInstall   = "service_install";
inline constexpr const char* kCmdServiceUninstall = "service_uninstall";
inline constexpr const char* kCmdServiceConfigure = "service_configure";

// События.
inline constexpr const char* kEventLog      = "log";
inline constexpr const char* kEventThreat   = "threat";
inline constexpr const char* kEventState    = "state";
inline constexpr const char* kEventStats    = "stats";
inline constexpr const char* kEventProgress = "progress";
inline constexpr const char* kEventDetail   = "detail";

inline constexpr const char* kEventSandboxStage = "sandbox_stage";
inline constexpr const char* kEventSandboxDone  = "sandbox_done";

// Имя канала: случайное на каждый запуск. Само по себе оно не защита —
// защищает список доступа, — но лишний экземпляр помощника, поймавший
// чужой канал, тоже никому не нужен.
QString MakePipeName();

// Полный путь вида \\.\pipe\<имя>.
QString PipePath(const QString& name);

} // namespace Ipc
