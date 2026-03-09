//! Deterministic nonce derivation for AEAD ciphers.
//!
//! Nonces are derived — never random — to make the scheme:
//!   1. Reproducible for seek/partial-decrypt.
//!   2. Free of per-chunk CSPRNG calls in the hot path.
//!   3. Provably non-repeating given (file_id, chunk_index) uniqueness.
//!
//! Nonce material:
//!   nonce_bytes = HKDF-SHA256(
//!       IKM  = file_id[16] || chunk_index_le64[8],
//!       salt = [],
//!       info = "obsidianq-v1-nonce-" || suite_byte,
//!   )
//!
//! Including `suite_byte` in the info string ensures nonce spaces are
//! domain-separated across cipher suites.  A (file_id, chunk_index) pair
//! that appears in both an XChaCha20 file and an AES-GCM file will produce
//! distinct nonces, preventing any cross-suite key/nonce collision.
//!
//! XChaCha20-Poly1305 uses a 192-bit (24-byte) nonce.
//! AES-256-GCM       uses a  96-bit (12-byte) nonce.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{ObsidianError, Result};

// Suite bytes must match SuiteId repr values in format.rs.
const SUITE_XCHACHA20: u8 = 0x00;
const SUITE_AESGCM: u8 = 0x01;

/// Derive a 24-byte nonce for XChaCha20-Poly1305.
pub fn derive_xchacha20_nonce(file_id: &[u8; 16], chunk_index: u64) -> Result<[u8; 24]> {
    let mut okm = [0u8; 24];
    derive_nonce_bytes(file_id, chunk_index, SUITE_XCHACHA20, &mut okm)?;
    Ok(okm)
}

/// Derive a 12-byte nonce for AES-256-GCM.
pub fn derive_aesgcm_nonce(file_id: &[u8; 16], chunk_index: u64) -> Result<[u8; 12]> {
    // Derive 24 bytes, take first 12.  Both outputs come from the same expansion
    // with a suite-specific info string, so they are fully domain-separated.
    let mut buf = [0u8; 24];
    derive_nonce_bytes(file_id, chunk_index, SUITE_AESGCM, &mut buf)?;
    let mut okm = [0u8; 12];
    okm.copy_from_slice(&buf[..12]);
    Ok(okm)
}

fn derive_nonce_bytes(
    file_id: &[u8; 16],
    chunk_index: u64,
    suite_byte: u8,
    out: &mut [u8],
) -> Result<()> {
    // IKM: file_id (16 B) || chunk_index LE (8 B) — fixed-width, no ambiguity.
    let mut ikm = [0u8; 24];
    ikm[..16].copy_from_slice(file_id);
    ikm[16..].copy_from_slice(&chunk_index.to_le_bytes());

    // Info: fixed prefix || suite_byte — distinct per suite.
    let prefix = b"obsidianq-v1-nonce-";
    let mut info = [0u8; 20]; // prefix(19) + suite_byte(1)
    info[..19].copy_from_slice(prefix);
    info[19] = suite_byte;

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    hk.expand(&info, out).map_err(|_| ObsidianError::KdfError)
}
