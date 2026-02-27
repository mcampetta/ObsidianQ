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

// Key file I/O helpers

const PUB_HEADER:  &str = "-----BEGIN OBSIDIANQ PUBLIC KEY-----";
const PUB_FOOTER:  &str = "-----END OBSIDIANQ PUBLIC KEY-----";
const PRIV_HEADER: &str = "-----BEGIN OBSIDIANQ PRIVATE KEY-----";
const PRIV_FOOTER: &str = "-----END OBSIDIANQ PRIVATE KEY-----";

pub fn write_pub(path: &Path, raw: &[u8]) -> Result<()> {
    if is_pem_path(path) {
        let b64 = Base64::encode_string(raw);
        let pem = format!("{}\n{}\n{}\n", PUB_HEADER, b64, PUB_FOOTER);
        std::fs::write(path, pem)?;
    } else {
        std::fs::write(path, raw)?;
    }
    Ok(())
}

pub fn write_priv(path: &Path, raw: &[u8]) -> Result<()> {
    if is_pem_path(path) {
        let b64 = Base64::encode_string(raw);
        let pem = format!("{}\n{}\n{}\n", PRIV_HEADER, b64, PRIV_FOOTER);
        std::fs::write(path, pem)
            .map_err(|e| anyhow::anyhow!("write private key: {e}"))?;
    } else {
        std::fs::write(path, raw)
            .map_err(|e| anyhow::anyhow!("write private key: {e}"))?;
    }
    Ok(())
}

pub fn read_pub(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    decode_pem_or_raw(bytes, PUB_HEADER, PUB_FOOTER)
}

pub fn read_priv(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    decode_pem_or_raw(bytes, PRIV_HEADER, PRIV_FOOTER)
}

fn is_pem_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("pem"))
        .unwrap_or(false)
}

fn decode_pem_or_raw(bytes: Vec<u8>, header: &str, footer: &str) -> Result<Vec<u8>> {
    if let Ok(s) = std::str::from_utf8(&bytes) {
        if s.contains(header) {
            return decode_pem(s, header, footer);
        }
    }
    Ok(bytes)
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
