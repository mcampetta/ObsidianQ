<img width="783" height="706" alt="filetab" src="https://github.com/user-attachments/assets/6961b11a-a53b-42e5-8bb7-ee019da73034" />

# ObsidianQ

Local-first, high-performance encryption for files, text, vaults, inspection, and secure delivery workflows.

ObsidianQ combines practical desktop UX with modern cryptography, including password-based protection, hybrid Secure Contacts recipient exchange, and recipient-friendly Secure Delivery workflows.

## Highlights

- File encryption/decryption with password or Secure Contacts recipient mode
- Secure Delivery workflows with recommended ZIP browser bundle, encrypted package-only, and Single EXE advanced outputs
- Secure Contacts identity and trusted contact management
- Built-in clipboard helper tray mode for quick text encrypt/decrypt and contact actions
- Public Identity import/export (`.obsqpub`) with metadata
- Encrypted Vault workflows (create, load, add/extract/remove, rekey)
- Container metadata inspection for `.obsq`, vault, ZIP package, and Single EXE package formats
- Streaming progress for major file/vault transfer operations
- Windows shell integration, package creation shortcuts, and file associations

## Security Model (At a Glance)

ObsidianQ is designed around local-first trust:

- Encryption/decryption operations happen on your machine
- Private keys remain under user control
- Public identities are exchanged directly between users
- No required cloud key server for core workflows

Core crypto building blocks used by the project include:

- Kyber Round 3 (`pqcrypto-kyber`) for current Secure Contacts recipient key exchange
- X25519 alongside Kyber Round 3 for the current hybrid recipient protection flow
- XChaCha20-Poly1305 for authenticated encryption
- Argon2id for password hardening
- BLAKE3 for hashing/fingerprints

ObsidianQ does not currently claim FIPS 203 ML-KEM compliance or interoperability with standardized ML-KEM implementations.

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
3. On first run, review the guided setup options for shell integration, Secure Contacts keypair setup, and the optional clipboard helper tray mode.
4. Use:
   - `File` for file encryption/decryption
   - `Text` for short text encryption/decryption
   - `Vault` for encrypted vault operations
   - `Inspect` for metadata and integrity review
   - `Secure Delivery` for portable password-protected delivery
   - `Secure Contacts` for identity/contact-based exchange
   - `Settings` to launch or configure the built-in clipboard helper tray mode

Important:
- `obsidianq.exe` is still included for direct CLI use and transparent local runtime access.
- The launcher prefers a local `obsidianq.exe` when present, but also carries an embedded fallback for normal desktop use.
- Secure Delivery defaults to a ZIP bundle with an offline browser decryptor; Single EXE remains available as an advanced compatibility option.

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

## Cross-Platform CLI Builds

- GitHub Actions matrix build: `.github/workflows/cli-matrix.yml`
- Targets: Linux, macOS, Windows
- On version tags (`v*`), CLI binaries are attached to the GitHub Release
- Local Linux/macOS validation checklist: `docs/CLI_LINUX_MAC_TESTING.md`

## Security Status

- ObsidianQ has not yet completed a formal third-party security audit.
- Public review and issue reports are welcome.
- Current security notes and architecture references:
  - `SECURITY.md`
  - `THREAT_MODEL.md`
  - `docs/SECURITY_ARCHITECTURE.md`
  - `docs/FORMAT.md`
  - `DISCLAIMER.md`

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
- Verify bundle integrity before use with your own trusted hash tooling:

```powershell
Get-FileHash .\ObsidianQBundle.zip -Algorithm SHA256
```

## Backup and Recovery

- Key backup/recovery guide: `docs/KEY_RECOVERY_AND_BACKUP.md`
- Use Settings in launcher:
  - `BACKUP LOCAL KEYPAIR`
  - `RESTORE LOCAL KEYPAIR`

## Current Notes

- The launcher is single-instance and forwards file-association opens to the running instance.
- Vault transfer workflows now use streaming progress parsing where available.
- Secure Contacts is the default key-based mode label across the UI.
- Explorer shell actions support direct package creation and folder package workflows.
- Clipboard helper actions are available from the launcher tray mode and can be configured from Settings.

## Security Disclaimer

ObsidianQ is built with strong primitives and practical defaults, but no software is risk-free.
Validate your threat model, maintain backups, protect private keys, and keep dependencies/releases current.

## Security Documentation

For more detail, see:

- [Security Policy](SECURITY.md)
- [Threat Model](THREAT_MODEL.md)
- [Security Architecture](docs/SECURITY_ARCHITECTURE.md)
- [Format Notes](docs/FORMAT.md)
- [Disclaimer](DISCLAIMER.md)
