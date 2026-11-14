# Plasma integration

The ClamAV Plasma module is enabled by default on Linux builds with Qt 6 and
KDE Frameworks 6 (`KF6ConfigWidgets` and `KF6I18n`). It is intentionally
dependency-gated so the core ClamAV build remains usable on systems without
Plasma development packages.

The module reports clamd statistics, database/service state, and FreshClam
timer state. It can reload or restart the daemon and trigger the packaged
`clamav-freshclam-once.service`. Configuration changes are restricted to the
documented ClamAV settings and are written atomically by the polkit-authorized
`clamav-kcm-helper`; the KCM never executes user-provided shell commands as
root.

The KDE file-scan dialog is a native Qt 6 application installed as
`clamav-scan-gui`. It provides the scan output, cancellation, queue/thread
statistics, and CPU/disk-I/O cards with the platform Qt/Breeze styling. The
`clamav-scan` launcher prefers it when available and retains its shell/KDialog
fallback for builds without Qt 6.

Dolphin also provides a separate “Scan and quarantine” action. It uses the same
direct ClamD Unix-socket scanner as the browser integrations and moves infected
regular files into the current user's secure quarantine store. Directory
selections are scanned recursively; directories and clean files are never moved.
The removable-media service menu uses the same action, while quarantine data
always remains on the local user's data volume rather than on the removable
device.

The on-demand database state is reported by clamd through an additional
`DATABASE:` line in its `STATS` response. Older daemons remain supported; the
KCM simply reports the extended state as unavailable.
