//! Key derivation — HKDF-SHA256 for root key and per-chunk subkeys,
//! Argon2id for password-based key derivation.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ObsidianError, Result};

// ── Master key ────────────────────────────────────────────────────────────────

/// A 32-byte master key.  Zeroizes on drop.
///
/// `Clone` is intentionally absent.  If you need a second independent
/// binding, construct a new instance via `from_bytes`.  This prevents
/// accidental long-lived key copies that escape their intended scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub(crate) [u8; 32]);

impl MasterKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ── HKDF helpers ─────────────────────────────────────────────────────────────

const APP_LABEL: &[u8] = b"obsidianq-v1";

/// Derive a 32-byte root symmetric key from a raw shared secret and a salt.
/// Used by both password mode and PQC mode (both produce a 32-byte IKM).
///
/// info = "obsidianq-v1-root"
pub fn derive_root_key(ikm: &[u8], salt: &[u8]) -> Result<MasterKey> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"obsidianq-v1-root", &mut okm)
        .map_err(|_| ObsidianError::KdfError)?;
    Ok(MasterKey(okm))
}

/// Derive a per-chunk 32-byte subkey.
///
/// K_chunk_i = HKDF-SHA256(
///     IKM   = K_master,
///     salt  = header_hash,   ← binds subkey to this specific file's header
///     info  = APP_LABEL || "-chunk-" || chunk_index_le64,
/// )
///
/// Using `header_hash` as the HKDF salt means every chunk key is tied to
/// the full header.  Two files sharing K_master but with different headers
/// derive orthogonal PRKs and therefore orthogonal chunk keys.
pub fn derive_chunk_key(
    master: &MasterKey,
    header_hash: &[u8; 32],
    chunk_index: u64,
) -> Result<ChunkKey> {
    let hk = Hkdf::<Sha256>::new(Some(header_hash.as_slice()), master.as_bytes());

    // info = "obsidianq-v1" (12) + "-chunk-" (7) + index_le64 (8) = 27 bytes
    let mut info = Vec::with_capacity(APP_LABEL.len() + 7 + 8);
    info.extend_from_slice(APP_LABEL);
    info.extend_from_slice(b"-chunk-");
    info.extend_from_slice(&chunk_index.to_le_bytes());

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|_| ObsidianError::KdfError)?;
    Ok(ChunkKey(okm))
}

/// A 32-byte per-chunk AEAD key.  Zeroizes on drop.
///
/// `Clone` is intentionally absent — see `MasterKey` rationale above.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChunkKey(pub(crate) [u8; 32]);

impl ChunkKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ── Argon2id ─────────────────────────────────────────────────────────────────

/// Argon2id parameters.  Conservative defaults targeting ~500 ms on a
/// mid-range 2024 laptop — tune for your threat model.
///
/// EXTENSION POINT: adjust before generating production keys.
pub struct Argon2Params {
    /// Memory in KiB (default 64 MiB)
    pub m_cost: u32,
    /// Iterations (default 3)
    pub t_cost: u32,
    /// Parallelism (default 4)
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65536, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Derive a 32-byte key from a password + 32-byte salt using Argon2id.
pub fn derive_password_key(
    password: &[u8],
    salt: &[u8; 32],
    params: &Argon2Params,
) -> Result<MasterKey> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| ObsidianError::PasswordHashError)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut okm = [0u8; 32];
    argon
        .hash_password_into(password, salt.as_slice(), &mut okm)
        .map_err(|_| ObsidianError::PasswordHashError)?;

    Ok(MasterKey(okm))
}
