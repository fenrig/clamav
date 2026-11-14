# Firefox ClamAV download scanner

This WebExtension scans completed Firefox downloads through the shared ClamAV
native-messaging host. It uses a persistent `connectNative()` connection and
serializes requests through one native host process.

The extension reports clean scans and scan failures using Firefox notifications.
When ClamAV detects a virus, the native host moves the file into the per-user
`~/.local/share/clamav/quarantine` directory (or `$XDG_DATA_HOME/clamav/quarantine`)
and reports the quarantine path in the result.
