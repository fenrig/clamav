# Firefox ClamAV download scanner

This WebExtension scans completed Firefox downloads through the shared ClamAV
native-messaging host. It uses a persistent `connectNative()` connection and
serializes requests through one native host process.

The extension reports clean scans and scan failures using Firefox notifications.
Automatic download scanning is enabled by default and can be changed from the
extension's settings page. Disabling it stops new automatic scans; it does not
remove existing quarantine entries.
When ClamAV detects a virus, the native host moves the file into the per-user
`~/.local/share/clamav/quarantine` directory (or `$XDG_DATA_HOME/clamav/quarantine`)
and reports the quarantine path in the result.

The CMake install default targets Arch Linux's system extension directory:
`${CMAKE_INSTALL_LIBDIR}/firefox/browser/extensions`. Override
`FIREFOX_EXTENSION_DIR` when packaging for a different Firefox layout.
