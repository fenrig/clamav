add_library(clamav-quarantine STATIC quarantine.c quarantine.h)
target_link_libraries(clamav-quarantine PUBLIC JSONC::jsonc OpenSSL::Crypto)
target_include_directories(clamav-quarantine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(clamav-quarantine PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")

add_executable(clamav-quarantine-cleanup cleanup.c)
target_link_libraries(clamav-quarantine-cleanup PRIVATE clamav-quarantine)
set_target_properties(clamav-quarantine-cleanup PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")
install(TARGETS clamav-quarantine-cleanup RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)

configure_file(clamav-quarantine-cleanup.service.in clamav-quarantine-cleanup.service @ONLY)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/clamav-quarantine-cleanup.service
    clamav-quarantine-cleanup.timer
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/user
    COMPONENT programs)
