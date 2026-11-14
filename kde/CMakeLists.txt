# KDE Plasma/Dolphin integration.
#
# The shell launcher remains the fallback when the optional Qt/PySide6 helper
# is unavailable. Dolphin discovers service menus in this directory.
if(NOT C_LINUX)
    return()
endif()

find_package(Qt6 QUIET COMPONENTS Core Gui Widgets Network)
if(Qt6_FOUND)
    add_executable(clamav-scan-gui clamav-scan-gui.cpp)
    target_link_libraries(clamav-scan-gui PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network)
    install(TARGETS clamav-scan-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)

    add_executable(clamav-quarantine-gui clamav-quarantine-gui.cpp)
    target_link_libraries(clamav-quarantine-gui PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets clamav-quarantine)
    install(TARGETS clamav-quarantine-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)

    add_executable(clamav-scan-quarantine clamav-scan-quarantine.c)
    target_link_libraries(clamav-scan-quarantine PRIVATE
        clamav-quarantine JSONC::jsonc OpenSSL::Crypto)
    target_compile_options(clamav-scan-quarantine PRIVATE -D_GNU_SOURCE)
    set_target_properties(clamav-scan-quarantine PROPERTIES
        COMPILE_FLAGS "${WARNCFLAGS}")
    install(TARGETS clamav-scan-quarantine RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)
    install(
        FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/clamav-quarantine.desktop
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
# End of KDE integration targets.
