# Thunderbird attachment-scanning integration.
# Kept in its own subtree so distributions can package or rebase it
# independently from the desktop file-manager integrations.

if(NOT C_LINUX)
    return()
endif()

# This is deliberately a separate, non-default target. It packages only the
# WebExtension files and does not become part of the normal ClamAV build.
set(CLAMAV_THUNDERBIRD_XPI
    ${CMAKE_CURRENT_BINARY_DIR}/clamav-thunderbird.xpi)
set(THUNDERBIRD_EXTENSION_DIR
    "${CMAKE_INSTALL_LIBDIR}/thunderbird/extensions"
    CACHE PATH "System Thunderbird extension directory")
set(FIREFOX_EXTENSION_DIR
    "${CMAKE_INSTALL_LIBDIR}/firefox/browser/extensions"
    CACHE PATH "System Firefox extension directory")
set(CLAMAV_THUNDERBIRD_EXTENSION_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/extension/manifest.json
    ${CMAKE_CURRENT_SOURCE_DIR}/extension/background.js
    ${CMAKE_CURRENT_SOURCE_DIR}/extension/message-display.js
    ${CMAKE_CURRENT_SOURCE_DIR}/extension/message-display.css
    ${CMAKE_CURRENT_SOURCE_DIR}/extension/options.html
    ${CMAKE_CURRENT_SOURCE_DIR}/extension/options.js
    ${CMAKE_CURRENT_SOURCE_DIR}/extension/logo.svg)

add_executable(clamav-thunderbird-host
    native/clamav-native-host.c)
target_link_libraries(clamav-thunderbird-host
    PRIVATE
        clamav-quarantine
        JSONC::jsonc
        OpenSSL::Crypto)
set_target_properties(clamav-thunderbird-host PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}")

add_custom_command(
    OUTPUT
        ${CLAMAV_THUNDERBIRD_XPI}
    COMMAND
        ${CMAKE_COMMAND} -E tar cf ${CLAMAV_THUNDERBIRD_XPI}
            --format=zip
            manifest.json background.js message-display.js message-display.css
            options.html options.js logo.svg
    DEPENDS
        ${CLAMAV_THUNDERBIRD_EXTENSION_FILES}
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/extension
    COMMENT "Packaging clamav-thunderbird.xpi")

add_custom_target(clamav-thunderbird-xpi ALL
    DEPENDS ${CLAMAV_THUNDERBIRD_XPI})

set(CLAMAV_FIREFOX_XPI
    ${CMAKE_CURRENT_BINARY_DIR}/clamav-firefox.xpi)
set(CLAMAV_FIREFOX_EXTENSION_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../firefox/extension/manifest.json
    ${CMAKE_CURRENT_SOURCE_DIR}/../firefox/extension/background.js)
add_custom_command(
    OUTPUT
        ${CLAMAV_FIREFOX_XPI}
    COMMAND
        ${CMAKE_COMMAND} -E tar cf ${CLAMAV_FIREFOX_XPI}
            --format=zip manifest.json background.js
    DEPENDS
        ${CLAMAV_FIREFOX_EXTENSION_FILES}
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/../firefox/extension
    COMMENT "Packaging clamav-firefox.xpi")
add_custom_target(clamav-firefox-xpi ALL
    DEPENDS ${CLAMAV_FIREFOX_XPI})

# The target is part of the default build, while remaining isolated from the
# rest of the ClamAV targets and independently invokable by name.
install(
    FILES
        ${CLAMAV_THUNDERBIRD_XPI}
    DESTINATION
        ${THUNDERBIRD_EXTENSION_DIR}
    RENAME
        clamav-thunderbird@clamav.net.xpi
    OPTIONAL
    COMPONENT programs)

install(
    FILES
        ${CLAMAV_FIREFOX_XPI}
    DESTINATION
        ${FIREFOX_EXTENSION_DIR}
    RENAME
        clamav-firefox@clamav.net.xpi
    OPTIONAL
    COMPONENT programs)

set(CLAMAV_THUNDERBIRD_HOST_MANIFEST
    ${CMAKE_CURRENT_BINARY_DIR}/org.clamav.thunderbird.json)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/org.clamav.thunderbird.json.in
    ${CLAMAV_THUNDERBIRD_HOST_MANIFEST}
    @ONLY)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/extension/manifest.json
        ${CMAKE_CURRENT_SOURCE_DIR}/extension/background.js
        ${CMAKE_CURRENT_SOURCE_DIR}/extension/message-display.js
        ${CMAKE_CURRENT_SOURCE_DIR}/extension/message-display.css
        ${CMAKE_CURRENT_SOURCE_DIR}/extension/options.html
        ${CMAKE_CURRENT_SOURCE_DIR}/extension/options.js
        ${CMAKE_CURRENT_SOURCE_DIR}/extension/logo.svg
        ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/clamav/thunderbird
    COMPONENT programs)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/../firefox/extension/manifest.json
        ${CMAKE_CURRENT_SOURCE_DIR}/../firefox/extension/background.js
        ${CMAKE_CURRENT_SOURCE_DIR}/../firefox/README.md
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/clamav/firefox
    COMPONENT programs)

install(
    TARGETS clamav-thunderbird-host
    DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/clamav
    COMPONENT programs)

install(
    FILES
        ${CLAMAV_THUNDERBIRD_HOST_MANIFEST}
    DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/mozilla/native-messaging-hosts
    COMPONENT programs)
