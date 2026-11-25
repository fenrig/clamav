# Firefox ClamAV download scanner

This WebExtension scans completed Firefox downloads through the shared ClamAV
native-messaging host. It uses a persistent `connectNative()` connection and
allows a configurable number of scan requests in flight through one native
host process. The default is two, capped at half the available CPU cores.

The extension reports clean scans and scan failures using Firefox notifications.
Automatic download scanning is enabled by default and can be changed from the
extension's settings page. Disabling it stops new automatic scans; it does not
remove existing quarantine entries.
When ClamAV detects a virus, the native host moves the file into the per-user
`~/.local/share/clamav/quarantine` directory (or `$XDG_DATA_HOME/clamav/quarantine`)
and reports the quarantine path in the result.

Recognizable file-backed `POST` and `PUT` uploads are also checked locally by
default. If ClamAV detects a threat, the first upload request is paused and a
warning identifies the file and destination site. The user can repeat the
upload within 15 minutes to explicitly continue; this is a warning-only safeguard. If Firefox
does not expose a local file for a custom or chunked upload, the upload is not
blocked and the extension reports that it could not inspect it. Upload
scanning can be disabled from the settings page.

The CMake install default targets Arch Linux's system extension directory:
`${CMAKE_INSTALL_LIBDIR}/firefox/browser/extensions`. Override
`FIREFOX_EXTENSION_DIR` when packaging for a different Firefox layout.
