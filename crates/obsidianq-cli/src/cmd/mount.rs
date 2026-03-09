//! `obsidianq mount` â€” mount a container as a read-only virtual drive.
//!
//! Usage:
//!   obsidianq mount --in vault.obsq --drive Z: --password-stdin
//!   obsidianq mount --in vault.obsq --drive Z: --privkey recipient.priv.bin
//!
//! Requires WinFSP to be installed (https://github.com/winfsp/winfsp/releases)
//! and the CLI to be built with `--features winfsp`.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use zeroize::{Zeroize, Zeroizing};

use obsidianq_core::{
    crypto::{
        kdf::{self, Argon2Params},
        kem::{self, CT_BYTES, DK_BYTES},
    },
    format::{FileHeader, Mode},
    open_container,
};
use obsidianq_fs::{is_winfsp_available, mount_container};

use super::read_priv;

#[derive(Args)]
pub struct MountArgs {
    /// Input .obsq container file
    #[arg(long)]
    pub r#in: PathBuf,

    /// Drive letter to mount at (e.g. Z or Z:)
    #[arg(long)]
    pub drive: String,

    /// Read password from stdin (one line). For password-mode containers.
    #[arg(long, conflicts_with = "privkey")]
    pub password_stdin: bool,

    /// Private key file for PQC-mode containers (.bin raw bytes by default; .pem also supported).
    #[arg(long, conflicts_with = "password_stdin")]
    pub privkey: Option<PathBuf>,
}

pub fn run(args: MountArgs) -> Result<()> {
    // â”€â”€ Validate drive letter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let dl = args
        .drive
        .trim_end_matches(':')
        .chars()
        .next()
        .context("--drive must be a letter such as Z or Z:")?
        .to_ascii_uppercase();
    if !('A'..='Z').contains(&dl) {
        bail!("invalid drive letter '{dl}' â€” use Aâ€“Z");
    }

    // â”€â”€ Check WinFSP availability â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if !is_winfsp_available() {
        bail!(
            "WinFSP is not installed.\n\
             Download: https://github.com/winfsp/winfsp/releases\n\
             Install the WinFSP package, then retry."
        );
    }

    // â”€â”€ Peek at header to determine mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let mut peek = BufReader::new(fs::File::open(&args.r#in).context("open container")?);
    let header = FileHeader::read_from(&mut peek).context("parse container header")?;

    // â”€â”€ Derive master key â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let master_key = match header.mode {
        Mode::Password => {
            if !args.password_stdin && args.privkey.is_none() {
                bail!("password-mode container: use --password-stdin");
            }
            let password = if args.password_stdin {
                let mut raw = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut raw)
                    .context("read password from stdin")?;
                let pw = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
                raw.zeroize();
                pw
            } else {
                Zeroizing::new(rpassword::prompt_password("Password: ").context("password prompt")?)
            };

            if header.kem_data.len() != 32 {
                bail!(
                    "malformed header: expected 32-byte salt, got {}",
                    header.kem_data.len()
                );
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&header.kem_data);
            kdf::derive_password_key(password.as_bytes(), &salt, &Argon2Params::default())
                .context("key derivation")?
        }
        Mode::Pqc => {
            let pk_path = args
                .privkey
                .as_ref()
                .context("PQC-mode container: use --privkey <private-key.bin>")?;
            let dk_raw = read_priv(pk_path).context("read private key")?;
            if dk_raw.len() != DK_BYTES {
                bail!(
                    "private key is {} bytes, expected {}",
                    dk_raw.len(),
                    DK_BYTES
                );
            }
            let dk_arr: [u8; DK_BYTES] = dk_raw
                .try_into()
                .map_err(|_| anyhow::anyhow!("private key has wrong length"))?;
            if header.kem_data.len() != CT_BYTES + 32 {
                bail!(
                    "malformed header: expected {} bytes KEM data",
                    CT_BYTES + 32
                );
            }
            let ct_arr: [u8; CT_BYTES] = header.kem_data[..CT_BYTES]
                .try_into()
                .map_err(|_| anyhow::anyhow!("KEM ciphertext wrong length"))?;
            let mut hkdf_salt = [0u8; 32];
            hkdf_salt.copy_from_slice(&header.kem_data[CT_BYTES..]);
            let ss = kem::decapsulate(&dk_arr, &ct_arr).context("KEM decapsulation")?;
            kdf::derive_root_key(ss.as_bytes(), &hkdf_salt).context("root key derivation")?
        }
    };

    // â”€â”€ Build the seekable container manifest (verifies both MACs) â”€â”€â”€â”€â”€â”€â”€â”€
    let mut reader = BufReader::new(fs::File::open(&args.r#in).context("open container")?);
    let manifest = open_container(&master_key, &mut reader).context("open container manifest")?;

    println!("Container verified:");
    println!("  File      : {}", args.r#in.display());
    println!("  Chunks    : {}", manifest.chunk_refs.len());
    println!("  Plain size: {} bytes", manifest.total_plaintext_len);
    println!("  Mount at  : {dl}:");

    // â”€â”€ Mount (blocks until Ctrl+C or unmount command) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    mount_container(&args.r#in, master_key, manifest, dl).map_err(|e| anyhow::anyhow!("{e}"))
}
