add_library(clamav-quarantine STATIC quarantine.c quarantine.h)
target_link_libraries(clamav-quarantine PUBLIC JSONC::jsonc)
target_include_directories(clamav-quarantine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(clamav-quarantine PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")
