pub mod benchmark;
pub mod contacts;
pub mod decrypt;
pub mod delivery;
pub mod encrypt;
pub mod exchange;
pub mod inspect;
pub mod json_output;
pub mod key;
pub mod keygen;
pub mod mount;
pub mod secure_connect;
pub mod unmount;
pub mod vault;

use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use std::path::Path;

use obsidianq_core::crypto::{
    hybrid::{X25519_PRIVATE_BYTES, X25519_PUBLIC_BYTES},
    kem::{DK_BYTES, EK_BYTES},
};

// Key file I/O helpers

const PUB_HEADER: &str = "-----BEGIN OBSIDIANQ PUBLIC KEY-----";
const PUB_FOOTER: &str = "-----END OBSIDIANQ PUBLIC KEY-----";
const PRIV_HEADER: &str = "-----BEGIN OBSIDIANQ PRIVATE KEY-----";
const PRIV_FOOTER: &str = "-----END OBSIDIANQ PRIVATE KEY-----";
const HYBRID_PUB_MAGIC: &[u8; 8] = b"OBSQHPK1";
const HYBRID_PRIV_MAGIC: &[u8; 8] = b"OBSQHSK1";

pub struct RecipientPublicMaterial {
    pub kyber_public: [u8; EK_BYTES],
    pub x25519_public: Option<[u8; X25519_PUBLIC_BYTES]>,
}

pub struct RecipientPrivateMaterial {
    pub kyber_private: [u8; DK_BYTES],
    pub x25519_private: Option<[u8; X25519_PRIVATE_BYTES]>,
}

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

pub fn write_pub_material(
    path: &Path,
    kyber_public: &[u8; EK_BYTES],
    x25519_public: Option<&[u8; X25519_PUBLIC_BYTES]>,
) -> Result<()> {
    let raw = if let Some(classical) = x25519_public {
        let mut out = Vec::with_capacity(HYBRID_PUB_MAGIC.len() + EK_BYTES + X25519_PUBLIC_BYTES);
        out.extend_from_slice(HYBRID_PUB_MAGIC);
        out.extend_from_slice(kyber_public);
        out.extend_from_slice(classical);
        out
    } else {
        kyber_public.to_vec()
    };
    write_pub(path, &raw)
}

pub fn write_priv(path: &Path, raw: &[u8]) -> Result<()> {
    if is_pem_path(path) {
        let b64 = Base64::encode_string(raw);
        let pem = format!("{}\n{}\n{}\n", PRIV_HEADER, b64, PRIV_FOOTER);
        std::fs::write(path, pem).map_err(|e| anyhow::anyhow!("write private key: {e}"))?;
    } else {
        std::fs::write(path, raw).map_err(|e| anyhow::anyhow!("write private key: {e}"))?;
    }
    Ok(())
}

pub fn write_priv_material(
    path: &Path,
    kyber_private: &[u8; DK_BYTES],
    x25519_private: Option<&[u8; X25519_PRIVATE_BYTES]>,
) -> Result<()> {
    let raw = if let Some(classical) = x25519_private {
        let mut out =
            Vec::with_capacity(HYBRID_PRIV_MAGIC.len() + DK_BYTES + X25519_PRIVATE_BYTES);
        out.extend_from_slice(HYBRID_PRIV_MAGIC);
        out.extend_from_slice(kyber_private);
        out.extend_from_slice(classical);
        out
    } else {
        kyber_private.to_vec()
    };
    write_priv(path, &raw)
}

pub fn read_pub(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let raw = decode_pem_or_raw(bytes, PUB_HEADER, PUB_FOOTER)?;
    let material = parse_public_material_bytes(&raw)?;
    Ok(material.kyber_public.to_vec())
}

pub fn read_priv(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let raw = decode_pem_or_raw(bytes, PRIV_HEADER, PRIV_FOOTER)?;
    let material = parse_private_material_bytes(&raw)?;
    Ok(material.kyber_private.to_vec())
}

pub fn read_pub_material(path: &Path) -> Result<RecipientPublicMaterial> {
    let bytes = std::fs::read(path)?;
    let raw = decode_pem_or_raw(bytes, PUB_HEADER, PUB_FOOTER)?;
    parse_public_material_bytes(&raw)
}

pub fn read_priv_material(path: &Path) -> Result<RecipientPrivateMaterial> {
    let bytes = std::fs::read(path)?;
    let raw = decode_pem_or_raw(bytes, PRIV_HEADER, PRIV_FOOTER)?;
    parse_private_material_bytes(&raw)
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

fn parse_public_material_bytes(raw: &[u8]) -> Result<RecipientPublicMaterial> {
    if raw.starts_with(HYBRID_PUB_MAGIC) {
        let expected = HYBRID_PUB_MAGIC.len() + EK_BYTES + X25519_PUBLIC_BYTES;
        if raw.len() != expected {
            return Err(anyhow::anyhow!(
                "hybrid public key has wrong length: expected {expected}, got {}",
                raw.len()
            ));
        }
        let mut kyber_public = [0u8; EK_BYTES];
        kyber_public.copy_from_slice(&raw[HYBRID_PUB_MAGIC.len()..HYBRID_PUB_MAGIC.len() + EK_BYTES]);
        let mut x25519_public = [0u8; X25519_PUBLIC_BYTES];
        x25519_public.copy_from_slice(&raw[HYBRID_PUB_MAGIC.len() + EK_BYTES..]);
        return Ok(RecipientPublicMaterial {
            kyber_public,
            x25519_public: Some(x25519_public),
        });
    }
    if raw.len() != EK_BYTES {
        return Err(anyhow::anyhow!(
            "public key has wrong length: expected {EK_BYTES}, got {}",
            raw.len()
        ));
    }
    let mut kyber_public = [0u8; EK_BYTES];
    kyber_public.copy_from_slice(raw);
    Ok(RecipientPublicMaterial {
        kyber_public,
        x25519_public: None,
    })
}

fn parse_private_material_bytes(raw: &[u8]) -> Result<RecipientPrivateMaterial> {
    if raw.starts_with(HYBRID_PRIV_MAGIC) {
        let expected = HYBRID_PRIV_MAGIC.len() + DK_BYTES + X25519_PRIVATE_BYTES;
        if raw.len() != expected {
            return Err(anyhow::anyhow!(
                "hybrid private key has wrong length: expected {expected}, got {}",
                raw.len()
            ));
        }
        let mut kyber_private = [0u8; DK_BYTES];
        kyber_private
            .copy_from_slice(&raw[HYBRID_PRIV_MAGIC.len()..HYBRID_PRIV_MAGIC.len() + DK_BYTES]);
        let mut x25519_private = [0u8; X25519_PRIVATE_BYTES];
        x25519_private.copy_from_slice(&raw[HYBRID_PRIV_MAGIC.len() + DK_BYTES..]);
        return Ok(RecipientPrivateMaterial {
            kyber_private,
            x25519_private: Some(x25519_private),
        });
    }
    if raw.len() != DK_BYTES {
        return Err(anyhow::anyhow!(
            "private key has wrong length: expected {DK_BYTES}, got {}",
            raw.len()
        ));
    }
    let mut kyber_private = [0u8; DK_BYTES];
    kyber_private.copy_from_slice(raw);
    Ok(RecipientPrivateMaterial {
        kyber_private,
        x25519_private: None,
    })
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

    let b64: String = s[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = Base64::decode_vec(&b64).map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hybrid_public_material() {
        let mut raw = Vec::new();
        raw.extend_from_slice(HYBRID_PUB_MAGIC);
        raw.extend_from_slice(&[7u8; EK_BYTES]);
        raw.extend_from_slice(&[9u8; X25519_PUBLIC_BYTES]);

        let parsed = parse_public_material_bytes(&raw).expect("parse hybrid public");
        assert_eq!(parsed.kyber_public, [7u8; EK_BYTES]);
        assert_eq!(parsed.x25519_public, Some([9u8; X25519_PUBLIC_BYTES]));
    }

    #[test]
    fn parses_legacy_private_material() {
        let raw = vec![5u8; DK_BYTES];
        let parsed = parse_private_material_bytes(&raw).expect("parse legacy private");
        assert_eq!(parsed.kyber_private, [5u8; DK_BYTES]);
        assert!(parsed.x25519_private.is_none());
    }
}
