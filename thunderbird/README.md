# Thunderbird ClamAV scanner

This integration adds **Scan attachment for viruses** to Thunderbird's
attachment context menu and **Scan message attachments for viruses** to the
message-list context menu. The message-list menu also provides **Scan email for
viruses and phishing**, including a force-rescan variant. The attachment action
scans all attachments in the selected message; the email action also scans HTML
message links. Force-rescan actions bypass the positive-result cache. It downloads each selected attachment to Thunderbird's
temporary download area, sends the path to the native ClamAV host, and removes
the temporary file after the scan.

The WebExtension and native host are intentionally kept in this directory so
they can be packaged or rebased independently from the file-manager and KDE
integrations. The extension requires the native host manifest installed in the
Mozilla native-messaging directory and the `org.clamav.thunderbird` extension
ID from `manifest.json`.

Automatic scanning is enabled by default, including HTML and plain-text
message-body scanning for ClamAV phishing detections. The message warning banner includes
buttons to rescan the message attachments and links, delete the displayed mail,
and permanently remove detected attachments. Attachment deletion leaves
Thunderbird's placeholder metadata in the message; link-only detections only
offer mail deletion. This checks the message content locally and does not open
links or contact websites. The original manual
attachment actions remain available as a fallback, including a force-rescan
action that bypasses the cache. It does not replace mail-server scanning. Virus
detections receive a red warning banner and a persistent **ClamAV: Virus** tag;
phishing detections receive an orange warning banner and a persistent
**ClamAV: Phishing** tag. The banner explains that the message may be a phishing
attack and advises users not to click links or provide personal information.
A clean rescan removes the corresponding tags when no detections remain.
The Thunderbird **Tools** menu also provides a manual full-library scan that
walks all real account folders and scans every message without producing a
notification for each clean result. The same menu provides cancellation; if
Thunderbird is closed during a scan, abandoned temporary scan files are cleaned
up the next time the extension starts.
Temporary scan files are removed after each scan, including failed scans and
virus detections. Abandoned files are also cleaned when the extension starts.
When an attachment is infected, its temporary scan copy is moved to the same
per-user ClamAV quarantine used by Firefox; the original message is not changed
unless the user chooses one of the message or attachment deletion actions.

The native host is a persistent C program connection. Thunderbird uses
`connectNative()` and serializes scan requests through one native-host process
per Thunderbird background context. On Linux the host opens the attachment and passes
the file descriptor directly to `clamd` using the Unix-socket `FILDES` protocol;
it falls back to `clamscan` if the daemon socket is unavailable. The default
Arch Linux socket is `/run/clamav/clamd.ctl`. Set `CLAMAV_CLAMD_SOCKET` when a
different socket path is configured.

The options page controls automatic scanning per Thunderbird account. The SHA-256 result cache has configurable maximum age and
entry count, defaulting to 180 days or 1,000 entries. Only positive detections
are cached; clean and failed scans are never cached. Setting either limit to
zero disables that part of caching. Diagnostic scan logging is disabled by
default and can be enabled from the options page when troubleshooting.

The XPI is packaged by its isolated CMake target, which is included in the
default build and can also be invoked directly:

    cmake --build <build-directory> --target clamav-thunderbird-xpi

The resulting `clamav-thunderbird.xpi` is written to the build tree's
`thunderbird` directory. Build that target before installation; the XPI is
then installed as `clamav-thunderbird@clamav.net.xpi` in the configurable
`THUNDERBIRD_EXTENSION_DIR` (by default
`${prefix}/lib/thunderbird/extensions`).
