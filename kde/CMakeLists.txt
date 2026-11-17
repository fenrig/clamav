# KDE Plasma/Dolphin integration.
#
# The shell launcher remains the fallback when the optional Qt/PySide6 helper
# is unavailable. Dolphin discovers service menus in this directory.
if(NOT C_LINUX)
    return()
endif()

find_package(Qt6 QUIET COMPONENTS Core Gui Widgets Network)
if(Qt6_FOUND)
    find_program(CLAMAV_LRELEASE_EXECUTABLE lrelease REQUIRED)
    set(CLAMAV_TRANSLATION_INSTALL_DIR "${CMAKE_INSTALL_DATADIR}/clamav/translations")
    set(CLAMAV_SCAN_DUTCH_QM "${CMAKE_CURRENT_BINARY_DIR}/clamav-scan_nl.qm")
    set(CLAMAV_QUARANTINE_DUTCH_QM "${CMAKE_CURRENT_BINARY_DIR}/clamav-quarantine_nl.qm")
    add_custom_command(OUTPUT ${CLAMAV_SCAN_DUTCH_QM}
        COMMAND ${CLAMAV_LRELEASE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/translations/clamav-scan_nl.ts -qm ${CLAMAV_SCAN_DUTCH_QM}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/translations/clamav-scan_nl.ts)
    add_custom_command(OUTPUT ${CLAMAV_QUARANTINE_DUTCH_QM}
        COMMAND ${CLAMAV_LRELEASE_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/translations/clamav-quarantine_nl.ts -qm ${CLAMAV_QUARANTINE_DUTCH_QM}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/translations/clamav-quarantine_nl.ts)
    add_custom_target(clamav-dutch-translations ALL DEPENDS ${CLAMAV_SCAN_DUTCH_QM} ${CLAMAV_QUARANTINE_DUTCH_QM})
    add_executable(clamav-scan-gui clamav-scan-gui.cpp)
    target_link_libraries(clamav-scan-gui PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network clamav-quarantine)
    target_compile_definitions(clamav-scan-gui PRIVATE
        CLAMAV_TRANSLATION_DIR="${CMAKE_INSTALL_FULL_DATADIR}/clamav/translations")
    add_dependencies(clamav-scan-gui clamav-dutch-translations)
    install(TARGETS clamav-scan-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)

    add_executable(clamav-quarantine-gui clamav-quarantine-gui.cpp)
    target_link_libraries(clamav-quarantine-gui PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets clamav-quarantine)
    target_compile_definitions(clamav-quarantine-gui PRIVATE
        CLAMAV_TRANSLATION_DIR="${CMAKE_INSTALL_FULL_DATADIR}/clamav/translations")
    add_dependencies(clamav-quarantine-gui clamav-dutch-translations)
    install(TARGETS clamav-quarantine-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)
    install(FILES ${CLAMAV_SCAN_DUTCH_QM} ${CLAMAV_QUARANTINE_DUTCH_QM}
        DESTINATION ${CLAMAV_TRANSLATION_INSTALL_DIR} COMPONENT programs)

    add_executable(clamav-scan-quarantine-helper clamav-scan-quarantine.c)
    target_link_libraries(clamav-scan-quarantine-helper PRIVATE
        clamav-quarantine JSONC::jsonc OpenSSL::Crypto)
    target_compile_options(clamav-scan-quarantine-helper PRIVATE -D_GNU_SOURCE)
    set_target_properties(clamav-scan-quarantine-helper PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}")
    install(TARGETS clamav-scan-quarantine-helper RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)
    install(
        FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/clamav-quarantine.desktop
        DESTINATION
            ${CMAKE_INSTALL_DATADIR}/applications
        COMPONENT programs)
    install(
        FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/clamav-scan-gui.desktop
        DESTINATION
            ${CMAKE_INSTALL_DATADIR}/applications
        COMPONENT programs)
else()
    message(STATUS "Native ClamAV scan GUI disabled: Qt6 Core/Gui/Widgets/Network are required")
endif()

if(ENABLE_KDE_KCM)
    find_package(Qt6 QUIET COMPONENTS Core Widgets DBus)
    find_package(KF6ConfigWidgets QUIET)
    find_package(KF6I18n QUIET)
    find_package(KF6CoreAddons QUIET)
    find_package(KF6KCMUtils QUIET)
    if(Qt6_FOUND AND KF6ConfigWidgets_FOUND AND KF6I18n_FOUND AND KF6CoreAddons_FOUND AND KF6KCMUtils_FOUND)
        add_subdirectory(kcm)
    else()
        message(STATUS "KDE ClamAV KCM disabled: Qt6 and KDE Frameworks 6 ConfigWidgets/I18n are required")
    endif()
endif()

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-scan.desktop
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/kio/servicemenus
    COMPONENT programs)
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-scan-removable.desktop
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/solid/actions
    COMPONENT programs)
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav.svg
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps
    RENAME clamav.svg
    COMPONENT programs)
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav-quarantine.svg
    DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps
    RENAME clamav-quarantine.svg
    COMPONENT programs)
# End of KDE integration targets.
