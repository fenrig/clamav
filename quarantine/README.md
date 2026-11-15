# ClamAV quarantine store

This static library owns the per-user quarantine format used by the native
browser host and future quarantine-management applications.

The store is located under `$XDG_DATA_HOME/clamav/quarantine`, or
`~/.local/share/clamav/quarantine` when `XDG_DATA_HOME` is unset. Directories
are mode `0700`; payload and metadata files are mode `0600`. Payloads receive
opaque random identifiers and are never stored with their original filename.

The current API stores a scanned file and records metadata atomically. Metadata
includes the originating component (`firefox`, `thunderbird`, or `plasma`),
the original filename, the source path, the detection, the SHA-256, and the
quarantine timestamp. Move and copy semantics are selected by the caller.
The Qt/KF6-compatible manager displays these fields and supports listing,
restore, and deletion.

Audit events are appended as JSON Lines to `$XDG_STATE_HOME/clamav/quarantine.log`,
or `~/.local/state/clamav/quarantine.log`. Each record includes a Unix timestamp,
action, success flag, quarantine ID when available, component, source, and a
short detail value. The log is user-owned and mode `0600`; logging is best-effort.
