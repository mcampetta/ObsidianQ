# ObsidianQ — Tester Guide

## What's in the bundle

```
ObsidianQBundle/
├── obsidianq.exe                ← Rust CLI (post-quantum crypto engine)
├── ObsidianQ.Launcher.exe       ← Windows GUI (double-click to open)
├── install_context_menu.cmd     ← Adds right-click menu in Explorer (no admin)
├── uninstall_context_menu.cmd   ← Removes right-click menu
├── README_TESTERS.md            ← This file
└── keys/
    └── README_KEYS.txt          ← How to generate PQC key pairs
```

Both EXEs must stay in the **same folder** — the GUI locates the CLI by looking next to itself.

---

## Quick start (password mode — no keys needed)

1. Double-click **`ObsidianQ.Launcher.exe`**.
2. Click **BROWSE** next to *Input file* and pick any file.
3. The output path fills in automatically (`.obsq` appended for encrypt).
4. Enter a password (and confirm it).
5. Click **▶ RUN**.
6. To decrypt: open a `.obsq` file the same way — the output path strips `.obsq`.

---

## Install context menu (optional)

Right-click `install_context_menu.cmd` → **Run** (or just double-click).

- Right-click **any file** → *ObsidianQ Encrypt/Decrypt…*
- Right-click a **`.obsq` file** → *ObsidianQ Decrypt…*

No administrator password required. To remove: run `uninstall_context_menu.cmd`.

---

## PQC (post-quantum) mode

Generate a key pair once with the CLI:

```bat
obsidianq.exe keygen --pubkey recipient.pub.pem --privkey recipient.priv.pem
```

- Give the sender `recipient.pub.pem` (public — safe to share).
- Keep `recipient.priv.pem` private.
- In the GUI, toggle **PQC** and browse to the appropriate key file.

See `keys\README_KEYS.txt` for full details.

---

## Cipher suite options

| Suite | Flag | Notes |
|-------|------|-------|
| XChaCha20-Poly1305 | `xchacha20` | **Default.** Faster on software stacks. |
| AES-256-GCM | `aesgcm` | Faster on AES-NI hardware. |

Suite is stored in the file header — decryption is automatic.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| "obsidianq.exe not found" | The two EXEs are not in the same folder |
| Password mismatch error | GUI shows the mismatch before launching — re-enter |
| "UnsupportedVersion(1)" | File was made with a pre-release build; re-encrypt |
| Context menu missing | Restart Explorer.exe or log off / log on |

---

## For developers — building the bundle

```powershell
# From repo root (PowerShell):
powershell -ExecutionPolicy Bypass -File tools\release\build_bundle.ps1

# Or double-click:
tools\release\build_bundle.cmd
```

Output lands in `dist\ObsidianQBundle\` plus `dist\ObsidianQBundle.zip`.

To clean: `powershell -File tools\release\clean_bundle.ps1`
