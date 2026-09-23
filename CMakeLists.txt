cmake_minimum_required(VERSION 3.21)

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(VCPKG_TARGET_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet")
endif()

project(ThreatScanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Gui Network Svg)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/MainWindow.h
    src/Sidebar.cpp
    src/Sidebar.h
    src/theme.h

    # Каркас окна и общие UI-примитивы
    src/ui/Icons.h
    src/ui/Icons.cpp
    src/ui/BackgroundWidget.h
    src/ui/BackgroundWidget.cpp
    src/ui/FramelessWindow.h
    src/ui/FramelessWindow.cpp
    src/ui/TitleBar.h
    src/ui/TitleBar.cpp
    src/ui/GradientButton.h
    src/ui/GradientButton.cpp
    src/ui/ToggleSwitch.h
    src/ui/ToggleSwitch.cpp
    src/ui/ConfirmDialog.h
    src/ui/ConfirmDialog.cpp

    src/pages/PageHelpers.h
    src/pages/PageHelpers.cpp
    src/pages/HomePage.cpp
    src/pages/HomePage.h
    src/pages/ScanPage.cpp
    src/pages/ScanPage.h
    src/pages/ThreatsPage.cpp
    src/pages/ThreatsPage.h
    src/pages/QuarantinePage.cpp
    src/pages/QuarantinePage.h
    src/pages/LogsPage.cpp
    src/pages/LogsPage.h
    src/pages/SettingsPage.cpp
    src/pages/SettingsPage.h
    src/pages/HelpPage.cpp
    src/pages/HelpPage.h
    src/pages/HistoryPage.cpp
    src/pages/HistoryPage.h
    src/pages/SandboxPage.cpp
    src/pages/SandboxPage.h

    # Ядро
    src/core/Logger.h
    src/core/Logger.cpp
    src/core/ThreatReport.h
    src/core/IScanModule.h
    src/core/Scanner.h
    src/core/Scanner.cpp
    src/core/RegistryScanner.h
    src/core/RegistryScanner.cpp
    src/core/ScannerBridge.h
    src/core/ScannerBridge.cpp
    src/core/ThreatActions.h
    src/core/ThreatActions.cpp
    src/core/ActionExecutor.h
    src/core/ActionExecutor.cpp
    src/core/Quarantine.h
    src/core/Quarantine.cpp
    src/core/AppSettings.h
    src/core/AppSettings.cpp
    src/core/Lang.h
    src/core/Lang.cpp
    src/core/ScanHistory.h
    src/core/ScanHistory.cpp
    src/core/Automation.h
    src/core/Automation.cpp

    # B2
    src/core/SignatureDB.h
    src/core/SignatureDB.cpp
    src/core/Hasher.h
    src/core/Hasher.cpp
    src/core/FileSystemScanner.h
    src/core/FileSystemScanner.cpp

    # B2.5
    src/core/SignatureVerifier.h
    src/core/SignatureVerifier.cpp
    src/core/PublisherWhitelist.h
    src/core/PublisherWhitelist.cpp

    # B3
    src/core/ProcessScanner.h
    src/core/ProcessScanner.cpp

    # B4
    src/core/NetworkScanner.h
    src/core/NetworkScanner.cpp

    # B5
    src/core/TaskSchedulerScanner.h
    src/core/TaskSchedulerScanner.cpp

    # B8: закрепление в системе (WMI, hosts, службы)
    src/core/PersistenceScanner.h
    src/core/PersistenceScanner.cpp

    # B7: статический анализ скриптов
    src/core/ScriptScanner.h
    src/core/ScriptScanner.cpp

    # B6: облачная проверка через VirusTotal
    src/core/VirusTotalClient.h
    src/core/VirusTotalClient.cpp

    # B9: динамический анализ — наблюдение за поведением
    src/core/BehaviorReport.h
    src/core/BehaviorMonitor.h
    src/core/BehaviorMonitor.cpp
    src/core/FileActivityWatcher.h
    src/core/FileActivityWatcher.cpp
    src/core/RegistryActivityWatcher.h
    src/core/RegistryActivityWatcher.cpp
    src/core/NetworkActivityWatcher.h
    src/core/NetworkActivityWatcher.cpp
    src/core/BehaviorReportJson.h
    src/core/BehaviorReportJson.cpp
    src/core/SandboxEnvironment.h
    src/core/SandboxEnvironment.cpp
    src/core/WsbGenerator.h
    src/core/WsbGenerator.cpp
    src/core/SandboxSession.h
    src/core/SandboxSession.cpp
    src/core/BehaviorVerdict.h
    src/core/BehaviorVerdict.cpp

    # B10: разделение прав — канал до привилегированного помощника
    src/ipc/HelperProtocol.h
    src/ipc/HelperProtocol.cpp
    src/ipc/PipeChannel.h
    src/ipc/PipeChannel.cpp
    src/ipc/HelperClient.h
    src/ipc/HelperClient.cpp
    src/ipc/ScanService.h
    src/core/ServiceConfig.h
    src/core/ServiceConfig.cpp

    res/resources.qrc
    res/app.rc          # значок exe в проводнике и на панели задач
)

add_executable(ThreatScanner WIN32 ${SOURCES})

target_include_directories(ThreatScanner PRIVATE src)

target_link_libraries(ThreatScanner PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Gui
    Qt6::Network   # B6: VirusTotal API
    Qt6::Svg       # иконки интерфейса
    dwmapi         # фреймлесс-окно: тень и скругление углов от DWM
    advapi32
    bcrypt
    wintrust
    crypt32
    psapi
    iphlpapi    # B4: GetExtendedTcpTable
    ws2_32      # B4: inet_ntop, ntohs
    taskschd    # B5: ITaskService
    comsupp     # B5: _bstr_t, _variant_t
    ole32       # B5: CoInitialize, CoCreateInstance
    oleaut32    # B5: VARIANT
    wbemuuid    # B8: подписки WMI
)

target_compile_definitions(ThreatScanner PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE _UNICODE
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_link_options(ThreatScanner PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTINPUT:${CMAKE_SOURCE_DIR}/res/app.manifest"
        "/MANIFESTUAC:level='asInvoker' uiAccess='false'"
    )
endif()

# Ядро наблюдения без интерфейса. Из него собираются две консольные
# программы: агент, который уезжает в песочницу, и проверка наблюдателя.
# Qt ни той, ни другой не нужен.
set(DYNAMIC_CORE_SOURCES
    src/core/BehaviorMonitor.cpp
    src/core/FileActivityWatcher.cpp
    src/core/RegistryActivityWatcher.cpp
    src/core/NetworkActivityWatcher.cpp
    src/core/BehaviorReportJson.cpp
    src/core/Logger.cpp
)

# Агент песочницы: единственное, что отображается внутрь вместе с
# образцом. Манифест администратора не нужен — внутри песочницы
# пользователь и так администратор.
add_executable(ThreatAgent
    tools/threat_agent.cpp
    ${DYNAMIC_CORE_SOURCES}
)

# Проверка наблюдателя: запускает безвредную мишень и сверяет отчёт
# с ожиданиями. Прав администратора не требует, но без них часть
# каталогов не открывается — это видно в отчёте.
add_executable(dynmon_test
    tools/dynmon_test.cpp
    ${DYNAMIC_CORE_SOURCES}
    src/core/SandboxEnvironment.cpp
    src/core/WsbGenerator.cpp
)

# Привилегированный помощник: всё, что требует прав администратора,
# делает он, а интерфейс работает от обычного пользователя.
add_executable(ThreatHelper
    tools/threat_helper.cpp
    src/ipc/HelperProtocol.cpp
    src/ipc/HelperServer.cpp
    src/ipc/PipeChannel.cpp
    src/ipc/PipeSecurity.cpp
    src/ipc/ScanService.cpp
    src/ipc/SandboxService.cpp
    src/core/ServiceConfig.cpp

    # Слой песочницы: Windows Sandbox запускается только от администратора.
    src/core/SandboxSession.cpp
    src/core/SandboxEnvironment.cpp
    src/core/WsbGenerator.cpp
    src/core/BehaviorReportJson.cpp

    # Ядро проверки целиком: оно и есть то, ради чего нужны права.
    src/core/Scanner.cpp
    src/core/RegistryScanner.cpp
    src/core/FileSystemScanner.cpp
    src/core/ProcessScanner.cpp
    src/core/NetworkScanner.cpp
    src/core/TaskSchedulerScanner.cpp
    src/core/ScriptScanner.cpp
    src/core/PersistenceScanner.cpp
    src/core/SignatureDB.cpp
    src/core/SignatureVerifier.cpp
    src/core/PublisherWhitelist.cpp
    src/core/Hasher.cpp
    src/core/Quarantine.cpp
    src/core/ActionExecutor.cpp
    src/core/ThreatActions.cpp
    src/core/AppSettings.cpp
    src/core/Logger.cpp

    # ScriptScanner и PersistenceScanner переводят свои описания прямо
    # при находке, поэтому словарь нужен и здесь. Язык помощник читает
    # из настроек при запуске — смена языка на лету до него не доходит.
    src/core/Lang.cpp
)
target_link_libraries(ThreatHelper PRIVATE
    Qt6::Core
    advapi32
    bcrypt
    wintrust
    crypt32
    psapi
    iphlpapi
    ws2_32
    taskschd
    comsupp
    ole32
    oleaut32
    wbemuuid
)

if(MSVC)
    target_link_options(ThreatHelper PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    )
endif()

# Служба фоновых проверок: единственное, что умеет работать при закрытом
# окне. Командного канала у неё нет — под SYSTEM это была бы постоянно
# открытая дверь с полными правами.
add_executable(ThreatService
    tools/threat_service.cpp
    src/core/ServiceConfig.cpp

    src/core/Scanner.cpp
    src/core/RegistryScanner.cpp
    src/core/FileSystemScanner.cpp
    src/core/ProcessScanner.cpp
    src/core/NetworkScanner.cpp
    src/core/TaskSchedulerScanner.cpp
    src/core/ScriptScanner.cpp
    src/core/PersistenceScanner.cpp
    src/core/SignatureDB.cpp
    src/core/SignatureVerifier.cpp
    src/core/PublisherWhitelist.cpp
    src/core/Hasher.cpp
    src/core/Quarantine.cpp
    src/core/ActionExecutor.cpp
    src/core/ThreatActions.cpp
    src/core/AppSettings.cpp
    src/core/Logger.cpp
    src/core/Lang.cpp
)
target_link_libraries(ThreatService PRIVATE
    Qt6::Core
    advapi32 bcrypt wintrust crypt32 psapi
    iphlpapi ws2_32 taskschd comsupp ole32 oleaut32 wbemuuid
    shell32     # SHGetKnownFolderPath: общая папка результатов
)

# Проверка канала: поднимает помощника, здоровается, проверяет, что тот
# уходит вместе с каналом. Требует согласия в UAC — как и настоящий запуск.
add_executable(ipc_test
    tools/ipc_test.cpp
    src/ipc/HelperProtocol.cpp
    src/ipc/PipeChannel.cpp
    src/ipc/HelperClient.cpp
    src/core/Logger.cpp
)
target_link_libraries(ipc_test PRIVATE Qt6::Core)

# Проверка слоя песочницы: разбор отчёта туда-обратно и поведение на
# системе, где Windows Sandbox нет. Нужен Qt Core — им разбирается JSON.
add_executable(sandbox_test
    tools/sandbox_test.cpp
    ${DYNAMIC_CORE_SOURCES}
    src/core/SandboxEnvironment.cpp
    src/core/WsbGenerator.cpp
    src/core/SandboxSession.cpp
    src/core/BehaviorVerdict.cpp
    src/core/Hasher.cpp
)
target_link_libraries(sandbox_test PRIVATE Qt6::Core)

foreach(CONSOLE_TARGET ThreatAgent dynmon_test sandbox_test ThreatHelper ipc_test
                       ThreatService)
    set_target_properties(${CONSOLE_TARGET} PROPERTIES
        AUTOMOC OFF
        AUTORCC OFF
        AUTOUIC OFF
    )
    target_include_directories(${CONSOLE_TARGET} PRIVATE src)
    # user32: ExitWindowsEx — агент гасит машину песочницы после отчёта
    target_link_libraries(${CONSOLE_TARGET} PRIVATE advapi32 iphlpapi ws2_32 user32)
    target_compile_definitions(${CONSOLE_TARGET} PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE _UNICODE
        _WIN32_WINNT=0x0A00
    )
endforeach()

# Исключения: обе цели собирают QObject-классы (HelperClient и Lang),
# без moc они не слинкуются.
set_target_properties(ipc_test PROPERTIES AUTOMOC ON)
set_target_properties(ThreatHelper PROPERTIES AUTOMOC ON)
set_target_properties(ThreatService PROPERTIES AUTOMOC ON)

# Без агента рядом с приложением сеанс песочницы не собрать, без
# помощника не сделать ничего привилегированного — пусть основная цель
# тянет обоих за собой.
add_dependencies(ThreatScanner ThreatAgent ThreatHelper)

if(WIN32)
    set(QT_PLATFORMS_SRC
        "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/Qt6/plugins/platforms"
    )

    add_custom_command(TARGET ThreatScanner POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:ThreatScanner>/platforms"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QT_PLATFORMS_SRC}/qwindows.dll"
            "$<TARGET_FILE_DIR:ThreatScanner>/platforms/"
        COMMENT "Copying Qt platform plugin"
    )

    # Без TLS-бэкенда Qt не умеет https, и запросы к VirusTotal
    # падают с "TLS initialization failed".
    set(QT_TLS_SRC
        "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/Qt6/plugins/tls"
    )
    if(EXISTS "${QT_TLS_SRC}")
        add_custom_command(TARGET ThreatScanner POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${QT_TLS_SRC}"
                "$<TARGET_FILE_DIR:ThreatScanner>/tls"
            COMMENT "Copying Qt TLS backends (required for VirusTotal over HTTPS)"
        )
    else()
        message(WARNING
            "Qt TLS plugins not found at ${QT_TLS_SRC} — "
            "VirusTotal lookups over HTTPS will fail at runtime.")
    endif()

    # qopensslbackend.dll грузит libssl/libcrypto, но vcpkg разворачивает
    # зависимости только для самого .exe — плагины он не обходит,
    # поэтому libssl копируем руками, иначе "TLS initialization failed".
    set(VCPKG_BIN "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin")
    foreach(SSL_DLL libssl-3-x64.dll libcrypto-3-x64.dll)
        if(EXISTS "${VCPKG_BIN}/${SSL_DLL}")
            add_custom_command(TARGET ThreatScanner POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${VCPKG_BIN}/${SSL_DLL}"
                    "$<TARGET_FILE_DIR:ThreatScanner>/"
                COMMENT "Copying ${SSL_DLL} for the Qt OpenSSL TLS backend"
            )
        endif()
    endforeach()
endif()
