# ObsidianQ

Local-first, high-performance encryption for files, text, and vault workflows.

ObsidianQ combines practical desktop UX with modern cryptography, including password-based protection and Secure Contacts key-based exchange for trusted sharing.

## Highlights

- File encryption/decryption with password or Secure Contacts key-based mode
- Secure Contacts identity and trusted contact management
- Public Identity import/export (`.obsqpub`) with metadata
- Encrypted Vault workflows (create, load, add/extract/remove, rekey)
- Container metadata inspection without decrypting content
- Streaming progress for major file/vault transfer operations
- Windows shell integration and file associations

## Security Model (At a Glance)

ObsidianQ is designed around local-first trust:

- Encryption/decryption operations happen on your machine
- Private keys remain under user control
- Public identities are exchanged directly between users
- No required cloud key server for core workflows

Core crypto building blocks used by the project include:

- ML-KEM-768 (Kyber) for post-quantum key exchange
- XChaCha20-Poly1305 for authenticated encryption
- Argon2id for password hardening
- BLAKE3 for hashing/fingerprints

## Project Structure

- `crates/obsidianq-cli` - CLI entrypoint and commands
- `crates/obsidianq-core` - core cryptographic/container logic
- `crates/obsidianq-vault` - vault format and vault operations
- `crates/obsidianq-fs` - filesystem/vfs support
- `tools/windows-gui` - Windows Launcher (WinForms)
- `docs/` - specs and design docs
- `docs/site/` - GitHub Pages site template

## Quick Start (Windows Launcher)

1. Build or open the launcher from `tools/windows-gui`.
2. Launch `ObsidianQ.Launcher.exe`.
3. On first run, set up or restore a local keypair when prompted (recommended).
4. Use:
   - `File` for file encryption/decryption
   - `Text` for short text encryption/decryption
   - `Vault` for encrypted vault operations
   - `Secure Contacts` for identity/contact-based exchange

Important:
- `ObsidianQ.Launcher.exe` and `obsidianq.exe` must remain in the same folder.
- The launcher invokes `obsidianq.exe` for runtime operations.

## Quick Start (CLI)

From repository root:

```powershell
cargo build --release -p obsidianq-cli
```

Example command patterns:

```powershell
# Encrypt/decrypt file (password mode)
obsidianq.exe encrypt --in "input.txt" --out "input.obsq" --password-stdin
obsidianq.exe decrypt --in "input.obsq" --out "input.txt" --password-stdin

# Generate keypair
obsidianq.exe keygen --pubkey "pub.bin" --privkey "priv.bin"

# Export/import Public Identity
obsidianq.exe key export-public --output "identity.obsqpub"
obsidianq.exe contacts import "identity.obsqpub"
```

## Build

### Rust workspace

```powershell
cargo build
```

### Windows Launcher

```powershell
dotnet build tools/windows-gui/ObsidianQ.Launcher.csproj -c Debug
```

## Screenshots / Demo

Repository media used by the site:

- `docs/assets/filetab.png`
- `docs/assets/securecontacts.png`
- `docs/assets/vault.png`
- `docs/assets/demo.mp4`

GitHub Pages template:

- `docs/index.html`

See `docs/site/README.md` for publish instructions.

## Releases and Integrity

- Latest release: `https://github.com/mcampetta/ObsidianQ/releases/latest`
- Release assets include:
  - `ObsidianQBundle.zip`
  - `ObsidianQBundle.sha256`
- Verify bundle integrity before use:

```powershell
Get-FileHash .\ObsidianQBundle.zip -Algorithm SHA256
```

Compare the resulting hash with the published `.sha256` file.

## Backup and Recovery

- Key backup/recovery guide: `docs/KEY_RECOVERY_AND_BACKUP.md`
- Use Settings in launcher:
  - `BACKUP LOCAL KEYPAIR`
  - `RESTORE LOCAL KEYPAIR`

## Current Notes

- The launcher is single-instance and forwards file-association opens to the running instance.
- Vault transfer workflows now use streaming progress parsing where available.
- Secure Contacts is the default key-based mode label across the UI.

## Security Disclaimer

ObsidianQ is built with strong primitives and practical defaults, but no software is risk-free.
Validate your threat model, maintain backups, protect private keys, and keep dependencies/releases current.
