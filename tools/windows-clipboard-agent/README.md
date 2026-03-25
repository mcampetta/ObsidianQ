This directory is archival only.

The active tray helper is no longer a separate WinForms executable. Clipboard-agent mode now runs inside the launcher via:

- `tools/windows-gui/Program.cs`
- launcher argument: `--clipboard-agent`

Why this was retired:

- the separate tray binary increased Windows packaging size
- it duplicated tray and clipboard logic that now lives in the integrated launcher
- keeping both implementations around caused maintenance and validation confusion

If this directory is kept in the repo, it should contain notes only and not a buildable tray implementation.
