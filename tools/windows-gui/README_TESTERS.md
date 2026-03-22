# ObsidianQ â€” Tester Guide

## What's in the bundle

```
ObsidianQBundle/
â”œâ”€â”€ obsidianq.exe                â† Rust CLI (post-quantum crypto engine)
â”œâ”€â”€ ObsidianQ.Launcher.exe       â† Windows GUI (double-click to open)
â”œâ”€â”€ install_context_menu.cmd     â† Adds right-click menu in Explorer (no admin)
â”œâ”€â”€ uninstall_context_menu.cmd   â† Removes right-click menu
â”œâ”€â”€ README_TESTERS.md            â† This file
â””â”€â”€ keys/
    â””â”€â”€ README_KEYS.txt          â† How to generate recipient key pairs
```

Both EXEs must stay in the **same folder** â€” the GUI locates the CLI by looking next to itself.

---

## Quick start (password mode â€” no keys needed)

1. Double-click **`ObsidianQ.Launcher.exe`**.
2. Click **BROWSE** next to *Input file* and pick any file.
3. The output path fills in automatically (`.obsq` appended for encrypt).
4. Enter a password (and confirm it).
5. Click **â–¶ RUN**.
6. To decrypt: open a `.obsq` file the same way â€” the output path strips `.obsq`.

---

## Install context menu (optional)

Right-click `install_context_menu.cmd` â†’ **Run** (or just double-click).

- Right-click **any file** â†’ *ObsidianQ Encrypt/Decryptâ€¦*
- Right-click a **`.obsq` file** â†’ *ObsidianQ Decryptâ€¦*

No administrator password required. To remove: run `uninstall_context_menu.cmd`.

---

## Recipient mode

Generate a key pair once with the CLI:

```bat
obsidianq.exe keygen --pubkey recipient.pub.bin --privkey recipient.priv.bin
```

- Give the sender `recipient.pub.bin` (public â€” safe to share).
- Keep `recipient.priv.bin` private.
- In the GUI, toggle **PQC** and browse to the appropriate key file.

See `keys\README_KEYS.txt` for full details.

---

## Cipher suite options

| Suite | Flag | Notes |
|-------|------|-------|
| XChaCha20-Poly1305 | `xchacha20` | **Default.** Faster on software stacks. |
| AES-256-GCM | `aesgcm` | Faster on AES-NI hardware. |

Suite is stored in the file header â€” decryption is automatic.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| "obsidianq.exe not found" | The two EXEs are not in the same folder |
| Password mismatch error | GUI shows the mismatch before launching â€” re-enter |
| "UnsupportedVersion(1)" | File was made with a pre-release build; re-encrypt |
| Context menu missing | Restart Explorer.exe or log off / log on |

---

## For developers â€” building the bundle

```powershell
# From repo root (PowerShell):
powershell -ExecutionPolicy Bypass -File tools\release\build_bundle.ps1

# Or double-click:
tools\release\build_bundle.cmd
```

Output lands in `dist\ObsidianQBundle\`.

To clean: `powershell -File tools\release\clean_bundle.ps1`

