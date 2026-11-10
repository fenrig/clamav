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
