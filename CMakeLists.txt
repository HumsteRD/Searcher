cmake_minimum_required(VERSION 3.21)

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(VCPKG_TARGET_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet")
endif()

# Версия приложения — единственное место. Отсюда она попадает в код
# (проверка обновлений), в ресурсы exe и в установщик.
project(ThreatScanner VERSION 2.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Исходники в UTF-8. Без ключа MSVC читает их в кодировке системы
# (CP1251), и широкие литералы с не-ASCII символами собираются неверно.
if(MSVC)
    add_compile_options(/utf-8 /permissive-)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Gui Network Svg Concurrent)
find_package(unofficial-libyara CONFIG REQUIRED)
find_package(ZLIB REQUIRED)

set(TS_DEFINES WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00
               TS_VERSION="${PROJECT_VERSION}")

# ─── Ядро поиска ─────────────────────────────────────────────────────────
# База хэшей, YARA, распаковка, проверка подписи, обход дисков. Без Qt.
add_library(ts_engine STATIC
    src/engine/HashDatabase.cpp
    src/engine/SignatureStore.cpp
    src/engine/YaraEngine.cpp
    src/engine/TrustVerifier.cpp
    src/engine/Unpack.cpp
    src/engine/Classify.cpp
    src/engine/ScriptHeuristics.cpp
    src/engine/FileAnalyzer.cpp
    src/engine/FileWalker.cpp
    src/engine/ScanPipeline.cpp
    src/core/Logger.cpp
)
target_include_directories(ts_engine PUBLIC src)
target_compile_definitions(ts_engine PUBLIC ${TS_DEFINES})
target_link_libraries(ts_engine PUBLIC unofficial::libyara::libyara ZLIB::ZLIB
    wintrust crypt32 bcrypt shell32 ole32 advapi32)

# ─── Модули проверки, действия, карантин ────────────────────────────────
add_library(ts_scan STATIC
    src/core/Scanner.cpp
    src/core/ScanConfig.cpp
    src/core/Detections.cpp
    src/core/CommandTarget.cpp
    src/core/ThreatJson.cpp
    src/core/FileSystemScanner.cpp
    src/core/ProcessScanner.cpp
    src/core/AutorunScanner.cpp
    src/core/TaskSchedulerScanner.cpp
    src/core/PersistenceScanner.cpp
    src/core/NetworkScanner.cpp
    src/core/ThreatActions.cpp
    src/core/ActionExecutor.cpp
    src/core/Quarantine.cpp
    src/core/ServiceConfig.cpp
    src/core/Hasher.cpp
)
target_link_libraries(ts_scan PUBLIC ts_engine Qt6::Core
    psapi iphlpapi ws2_32 taskschd comsupp oleaut32 wbemuuid)

# ─── Наблюдение за поведением (песочница) ───────────────────────────────
add_library(ts_behavior STATIC
    src/core/BehaviorMonitor.cpp
    src/core/FileActivityWatcher.cpp
    src/core/RegistryActivityWatcher.cpp
    src/core/NetworkActivityWatcher.cpp
    src/core/BehaviorReportJson.cpp
    src/core/Logger.cpp
)
target_include_directories(ts_behavior PUBLIC src)
target_compile_definitions(ts_behavior PUBLIC ${TS_DEFINES})
target_link_libraries(ts_behavior PUBLIC advapi32 iphlpapi ws2_32 user32)

add_library(ts_sandbox STATIC
    src/core/SandboxEnvironment.cpp
    src/core/WsbGenerator.cpp
    src/core/SandboxSession.cpp
    src/core/BehaviorVerdict.cpp
    src/core/BehaviorMonitor.cpp
    src/core/FileActivityWatcher.cpp
    src/core/RegistryActivityWatcher.cpp
    src/core/NetworkActivityWatcher.cpp
    src/core/BehaviorReportJson.cpp
)
target_link_libraries(ts_sandbox PUBLIC ts_scan Qt6::Core advapi32 iphlpapi ws2_32 user32)

foreach(LIB ts_engine ts_scan ts_behavior ts_sandbox)
    set_target_properties(${LIB} PROPERTIES AUTOMOC OFF AUTORCC OFF AUTOUIC OFF)
endforeach()

# ─── Интерфейс ───────────────────────────────────────────────────────────
file(GLOB TS_UI_SOURCES CONFIGURE_DEPENDS
    src/app/*.cpp src/app/*.h
    src/ui/*.cpp src/ui/*.h
    src/pages/*.cpp src/pages/*.h
)

set(TS_IPC_CLIENT
    src/ipc/HelperProtocol.cpp
    src/ipc/HelperProtocol.h
    src/ipc/PipeChannel.cpp
    src/ipc/PipeChannel.h
    src/ipc/HelperClient.cpp
    src/ipc/HelperClient.h
)

configure_file(res/app.rc.in ${CMAKE_BINARY_DIR}/app.rc @ONLY)

add_executable(ThreatScanner WIN32
    src/main.cpp
    ${TS_UI_SOURCES}
    ${TS_IPC_CLIENT}
    res/resources.qrc
    ${CMAKE_BINARY_DIR}/app.rc
)
set_target_properties(ThreatScanner PROPERTIES AUTOMOC ON AUTORCC ON)
target_include_directories(ThreatScanner PRIVATE src)
target_link_libraries(ThreatScanner PRIVATE
    ts_sandbox ts_scan ts_engine
    Qt6::Core Qt6::Widgets Qt6::Gui Qt6::Network Qt6::Svg Qt6::Concurrent
    dwmapi uxtheme
)
if(MSVC)
    target_link_options(ThreatScanner PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTINPUT:${CMAKE_SOURCE_DIR}/res/app.manifest"
        "/MANIFESTUAC:level='asInvoker' uiAccess='false'"
    )
endif()

# ─── Консольные программы ────────────────────────────────────────────────
# Агент песочницы: единственное, что отображается внутрь вместе с образцом.
add_executable(ThreatAgent tools/threat_agent.cpp)
target_link_libraries(ThreatAgent PRIVATE ts_behavior)

# Агент уезжает в песочницу одним файлом, а внутри — чистая Windows без
# библиотек Visual C++: с динамической средой выполнения он там просто не
# запустится («не найден VCRUNTIME140.dll»). Поэтому среда выполнения
# вшита в него статически — и в библиотеку, из которой он собран.
set_property(TARGET ts_behavior ThreatAgent PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Привилегированный помощник: всё, что требует прав администратора.
add_executable(ThreatHelper
    tools/threat_helper.cpp
    src/ipc/HelperProtocol.cpp
    src/ipc/HelperServer.cpp
    src/ipc/PipeChannel.cpp
    src/ipc/PipeSecurity.cpp
    src/ipc/ScanService.cpp
    src/ipc/SandboxService.cpp
)
set_target_properties(ThreatHelper PROPERTIES AUTOMOC ON)
target_link_libraries(ThreatHelper PRIVATE ts_sandbox ts_scan ts_engine Qt6::Core)
if(MSVC)
    target_link_options(ThreatHelper PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
endif()

# Служба фоновых проверок. Командного канала у неё нет.
add_executable(ThreatService tools/threat_service.cpp)
target_link_libraries(ThreatService PRIVATE ts_scan ts_engine Qt6::Core)

# Проверки из командной строки.
add_executable(engine_scan tools/engine_scan.cpp)
target_link_libraries(engine_scan PRIVATE ts_engine)

add_executable(engine_selftest tools/engine_selftest.cpp)
target_link_libraries(engine_selftest PRIVATE ts_engine)

add_executable(scan_cli tools/scan_cli.cpp)
target_link_libraries(scan_cli PRIVATE ts_scan ts_engine Qt6::Core)

add_executable(core_selftest tools/core_selftest.cpp)
target_link_libraries(core_selftest PRIVATE ts_scan ts_engine Qt6::Core)

add_executable(dynmon_test tools/dynmon_test.cpp
    src/core/SandboxEnvironment.cpp src/core/WsbGenerator.cpp)
target_link_libraries(dynmon_test PRIVATE ts_behavior)
# Та же среда выполнения, что у ts_behavior: смешивать их в одном exe нельзя.
set_property(TARGET dynmon_test PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(sandbox_test tools/sandbox_test.cpp)
target_link_libraries(sandbox_test PRIVATE ts_sandbox ts_scan ts_engine)

add_executable(ipc_test tools/ipc_test.cpp
    src/ipc/HelperProtocol.cpp src/ipc/PipeChannel.cpp src/ipc/HelperClient.cpp)
set_target_properties(ipc_test PROPERTIES AUTOMOC ON)
target_link_libraries(ipc_test PRIVATE ts_engine Qt6::Core)

foreach(T ThreatAgent ThreatHelper ThreatService engine_scan engine_selftest scan_cli core_selftest dynmon_test sandbox_test ipc_test)
    target_include_directories(${T} PRIVATE src)
    target_compile_definitions(${T} PRIVATE ${TS_DEFINES})
endforeach()

add_dependencies(ThreatScanner ThreatAgent ThreatHelper ThreatService)

# ─── Файлы рядом с exe ───────────────────────────────────────────────────
# Базы сигнатур, плагины Qt и OpenSSL: без плагинов нет окна и https.
set(VCPKG_ROOT_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
foreach(T ThreatScanner engine_scan engine_selftest scan_cli)
    add_custom_command(TARGET ${T} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_SOURCE_DIR}/res/signatures"
                "$<TARGET_FILE_DIR:${T}>/signatures")
endforeach()

add_custom_command(TARGET ThreatScanner POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ThreatScanner>/platforms"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${VCPKG_ROOT_DIR}/Qt6/plugins/platforms/qwindows.dll"
            "$<TARGET_FILE_DIR:ThreatScanner>/platforms/"
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${VCPKG_ROOT_DIR}/Qt6/plugins/tls"
            "$<TARGET_FILE_DIR:ThreatScanner>/tls"
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${VCPKG_ROOT_DIR}/Qt6/plugins/imageformats"
            "$<TARGET_FILE_DIR:ThreatScanner>/imageformats"
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${VCPKG_ROOT_DIR}/Qt6/plugins/iconengines"
            "$<TARGET_FILE_DIR:ThreatScanner>/iconengines"
    COMMENT "Copying Qt plugins"
)
foreach(SSL_DLL libssl-3-x64.dll libcrypto-3-x64.dll)
    if(EXISTS "${VCPKG_ROOT_DIR}/bin/${SSL_DLL}")
        add_custom_command(TARGET ThreatScanner POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${VCPKG_ROOT_DIR}/bin/${SSL_DLL}" "$<TARGET_FILE_DIR:ThreatScanner>/")
    endif()
endforeach()
