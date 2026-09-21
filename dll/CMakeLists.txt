set(DLL_NAME unpacker)

set(CAPSTONE_ROOT "${CMAKE_SOURCE_DIR}/../wow-IAT-fix/OverwatchDumpFix")
if (NOT EXISTS "${CAPSTONE_ROOT}/include/capstone/capstone.h")
    set(CAPSTONE_ROOT "${CMAKE_SOURCE_DIR}/../wow-IAT-fix/OverwatchDumpFix")
endif()

include_directories(
    Include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
    "${CAPSTONE_ROOT}/include"
)

set(SOURCE_FILES
    concolic.cpp
    dumper.cpp
    imports.cpp
    iat_deobfuscate.cpp
    relocations.cpp
    log.cpp
    main.cpp
    misc.cpp
)

add_library(${DLL_NAME} SHARED ${SOURCE_FILES})
target_link_libraries(${DLL_NAME}
    shlwapi.lib
    asmjit.lib
    udis86.lib
    "${CAPSTONE_ROOT}/capstone_dll.lib"
)

# Capstone DLL must sit next to unpacker.dll at runtime
add_custom_command(TARGET ${DLL_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CAPSTONE_ROOT}/capstone.dll"
        $<TARGET_FILE_DIR:${DLL_NAME}>
)

install(TARGETS ${DLL_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}")
install(FILES "${CAPSTONE_ROOT}/capstone.dll" DESTINATION "${CMAKE_INSTALL_PREFIX}")
