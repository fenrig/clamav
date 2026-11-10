# Desktop-neutral launcher plus integrations for file managers outside KDE.

install(
    PROGRAMS
        ${CMAKE_SOURCE_DIR}/kde/clamav-scan
    DESTINATION
        ${CMAKE_INSTALL_BINDIR}
    COMPONENT programs)

install(
    FILES
        ${CMAKE_SOURCE_DIR}/kde/clamav.svg
    DESTINATION
        ${CMAKE_INSTALL_BINDIR}
    COMPONENT programs)

# Nautilus exposes executable files in this directory as Scripts in the
# context menu.  The script receives the selected files as positional args.
install(
    PROGRAMS
        "${CMAKE_CURRENT_SOURCE_DIR}/nautilus/Scan for viruses with ClamAV"
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/nautilus/scripts
    COMPONENT programs)

# Nemo has a native action format and loads actions from this directory.
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/nemo/clamav-scan.nemo_action
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/nemo/actions
    COMPONENT programs)
