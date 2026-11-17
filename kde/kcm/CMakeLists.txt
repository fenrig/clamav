find_package(KF6ConfigWidgets REQUIRED)
find_package(KF6I18n REQUIRED)
find_package(KF6CoreAddons REQUIRED)
find_package(KF6KCMUtils REQUIRED)
include("${KF6KCMUtils_DIR}/KF6KCMUtilsMacros.cmake")

find_program(CLAMAV_MSGFMT_EXECUTABLE msgfmt REQUIRED)
set(CLAMAV_KCM_DUTCH_MO "${CMAKE_CURRENT_BINARY_DIR}/kcm_clamav.mo")
add_custom_command(OUTPUT ${CLAMAV_KCM_DUTCH_MO}
    COMMAND ${CLAMAV_MSGFMT_EXECUTABLE} -o ${CLAMAV_KCM_DUTCH_MO}
        ${CMAKE_CURRENT_SOURCE_DIR}/po/nl.po
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/po/nl.po)
add_custom_target(clamav-kcm-dutch-translation ALL DEPENDS ${CLAMAV_KCM_DUTCH_MO})

set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Widgets DBus Network)

add_executable(clamav-kcm-helper helper.cpp)
target_link_libraries(clamav-kcm-helper PRIVATE Qt6::Core)
target_compile_definitions(clamav-kcm-helper PRIVATE
    CLAMAV_CONF_DIR="${CONFDIR}"
    CLAMAV_DATA_DIR="${DATADIR}"
    CLAMAV_LIBEXEC_DIR="${CMAKE_INSTALL_FULL_LIBEXECDIR}")
install(TARGETS clamav-kcm-helper DESTINATION ${CMAKE_INSTALL_LIBEXECDIR} COMPONENT programs)

configure_file(org.clamav.kcm.policy.in org.clamav.kcm.policy @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.clamav.kcm.policy
    DESTINATION ${CMAKE_INSTALL_DATADIR}/polkit-1/actions COMPONENT programs)

add_library(kcm_clamav MODULE kcm_clamav.cpp)
add_dependencies(kcm_clamav clamav-kcm-dutch-translation)
target_link_libraries(kcm_clamav PRIVATE
    Qt6::Core Qt6::Widgets Qt6::DBus Qt6::Network
    KF6::ConfigWidgets KF6::I18n KF6::CoreAddons KF6::KCMUtils
    clamav-quarantine)
target_compile_definitions(kcm_clamav PRIVATE
    CLAMAV_CONF_DIR="${CONFDIR}"
    CLAMAV_DATA_DIR="${DATADIR}"
    CLAMAV_LIBEXEC_DIR="${CMAKE_INSTALL_FULL_LIBEXECDIR}")
set_target_properties(kcm_clamav PROPERTIES
    OUTPUT_NAME kcm_clamav
    PREFIX "")
install(TARGETS kcm_clamav DESTINATION ${CMAKE_INSTALL_LIBDIR}/qt6/plugins/plasma/kcms/systemsettings COMPONENT programs)
install(FILES ${CLAMAV_KCM_DUTCH_MO}
    DESTINATION ${CMAKE_INSTALL_LOCALEDIR}/nl/LC_MESSAGES COMPONENT programs)
install(FILES kcm_clamav.json DESTINATION ${CMAKE_INSTALL_LIBDIR}/qt6/plugins/plasma/kcms/systemsettings COMPONENT programs)

# System Settings discovers KCModules through an application desktop entry in
# addition to the plugin metadata. Generate that entry from the KCM JSON.
set(KDE_INSTALL_APPDIR "${CMAKE_INSTALL_DATADIR}/applications")
kcmutils_generate_desktop_file(kcm_clamav)
