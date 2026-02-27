pub mod benchmark;
pub mod decrypt;
pub mod encrypt;
pub mod inspect;
pub mod keygen;
pub mod mount;
pub mod unmount;

use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use std::path::Path;

// ── Key file I/O helpers ──────────────────────────────────────────────────────

const PUB_HEADER:  &str = "-----BEGIN OBSIDIANQ PUBLIC KEY-----";
const PUB_FOOTER:  &str = "-----END OBSIDIANQ PUBLIC KEY-----";
const PRIV_HEADER: &str = "-----BEGIN OBSIDIANQ PRIVATE KEY-----";
const PRIV_FOOTER: &str = "-----END OBSIDIANQ PRIVATE KEY-----";

pub fn write_pem_pub(path: &Path, raw: &[u8]) -> Result<()> {
    let b64 = Base64::encode_string(raw);
    let pem = format!("{}\n{}\n{}\n", PUB_HEADER, b64, PUB_FOOTER);
    std::fs::write(path, pem)?;
    Ok(())
}

pub fn write_pem_priv(path: &Path, raw: &[u8]) -> Result<()> {
    let b64 = Base64::encode_string(raw);
    let pem = format!("{}\n{}\n{}\n", PRIV_HEADER, b64, PRIV_FOOTER);
    std::fs::write(path, pem)
        .map_err(|e| anyhow::anyhow!("write private key: {e}"))?;
    Ok(())
}

pub fn read_pem_pub(path: &Path) -> Result<Vec<u8>> {
    let s = std::fs::read_to_string(path)?;
    decode_pem(&s, PUB_HEADER, PUB_FOOTER)
}

pub fn read_pem_priv(path: &Path) -> Result<Vec<u8>> {
    let s = std::fs::read_to_string(path)?;
    decode_pem(&s, PRIV_HEADER, PRIV_FOOTER)
}

fn decode_pem(s: &str, header: &str, footer: &str) -> Result<Vec<u8>> {
    let start = s
        .find(header)
        .map(|i| i + header.len())
        .with_context(|| format!("PEM header '{header}' not found"))?;
    let end = s[start..]
        .find(footer)
        .map(|i| start + i)
        .with_context(|| format!("PEM footer '{footer}' not found"))?;

    let b64: String = s[start..end].chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = Base64::decode_vec(&b64).map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;
    Ok(bytes)
}

