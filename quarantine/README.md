# ClamAV quarantine store

This static library owns the per-user quarantine format used by the native
browser host and future quarantine-management applications.

The store is located under `$XDG_DATA_HOME/clamav/quarantine`, or
`~/.local/share/clamav/quarantine` when `XDG_DATA_HOME` is unset. Directories
are mode `0700`; payload and metadata files are mode `0600`. Payloads receive
opaque random identifiers and are never stored with their original filename.

The current API stores a scanned file and records metadata atomically. Move
and copy semantics are selected by the caller. Listing, restore, and deletion
operations will use the same format for the Qt/KF6 quarantine manager.
