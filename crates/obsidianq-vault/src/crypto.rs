//! Per-block encrypt / decrypt — thin wrappers around obsidianq-core.
//!
//! Zero new crypto code: reuses exactly:
//! - `kdf::derive_chunk_key` for per-block keys
//! - `aead::encrypt_chunk` / `aead::decrypt_chunk` for AEAD
//! - `aead::build_aad` for the 40-byte AAD (header_hash ‖ block_idx_le64)
//!
//! The vault's `immutable_mac` doubles as the `header_hash` for KDF —
//! it is a 32-byte BLAKE3-keyed MAC of the entire immutable header, which
//! is exactly the domain-separated binding that KDF needs.

use std::io::{Read, Seek, SeekFrom, Write};

use obsidianq_core::crypto::{aead, kdf};

use crate::format::{superblock_offsets_for_version, ImmutableHeader};
use crate::{Result, VaultError};

// ---------------------------------------------------------------------------
// MAC helpers (for ImmutableHeader and Superblock MACs)
// ---------------------------------------------------------------------------

/// Compute BLAKE3-keyed MAC:
///   output = BLAKE3-keyed(master_key, domain || "\x00" || data)
pub fn vault_mac(master_key: &kdf::MasterKey, domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(master_key.as_bytes());
    h.update(domain);
    h.update(b"\x00");
    h.update(data);
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Block I/O
// ---------------------------------------------------------------------------

/// Compute the file byte offset of block `block_idx`.
#[inline]
pub fn block_offset(version: u8, block_idx: u64, block_size: u32) -> Result<u64> {
    let (_, _, blocks_start) = superblock_offsets_for_version(version)?;
    Ok(blocks_start + block_idx * block_size as u64)
}

/// Read and decrypt block `block_idx` from `file`.
///
/// Returns a `Vec<u8>` of length `block_size - 16` (usable plaintext).
pub fn read_block<F: Read + Seek>(
    file: &mut F,
    header: &ImmutableHeader,
    master_key: &kdf::MasterKey,
    header_hash: &[u8; 32],
    block_idx: u64,
) -> Result<Vec<u8>> {
    let offset = block_offset(header.version, block_idx, header.block_size)?;
    file.seek(SeekFrom::Start(offset))?;

    let mut ciphertext = vec![0u8; header.block_size as usize];
    file.read_exact(&mut ciphertext)?;

    let chunk_key = kdf::derive_chunk_key(master_key, header_hash, block_idx)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    let aad = aead::build_aad(header_hash, block_idx);

    aead::decrypt_chunk(
        header.suite,
        &chunk_key,
        &header.file_id,
        block_idx,
        &ciphertext,
        &aad,
    )
    .map_err(|e| VaultError::CryptoError(e.to_string()))
}

/// Encrypt `plaintext` (length must be `block_size - 16`) and write to `file`.
pub fn write_block<F: Read + Write + Seek>(
    file: &mut F,
    header: &ImmutableHeader,
    master_key: &kdf::MasterKey,
    header_hash: &[u8; 32],
    block_idx: u64,
    plaintext: &[u8],
) -> Result<()> {
    let chunk_key = kdf::derive_chunk_key(master_key, header_hash, block_idx)
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;
    let aad = aead::build_aad(header_hash, block_idx);

    let ciphertext = aead::encrypt_chunk(
        header.suite,
        &chunk_key,
        &header.file_id,
        block_idx,
        plaintext,
        &aad,
    )
    .map_err(|e| VaultError::CryptoError(e.to_string()))?;

    // Ensure the file is large enough before writing.
    let end_offset =
        block_offset(header.version, block_idx, header.block_size)? + header.block_size as u64;
    let current_len = file.seek(SeekFrom::End(0))?;
    if end_offset > current_len {
        // Extend the file (fills new space with zeros).
        file.seek(SeekFrom::Start(current_len))?;
        let gap = end_offset - current_len - ciphertext.len() as u64;
        if gap > 0 {
            // Write zeros for any gap before this block.
            // This is safe: the intermediate bytes are encrypted zeros from other blocks,
            // or will be overwritten when those blocks are committed.
            let zeros = vec![0u8; gap.min(4096) as usize];
            let mut remaining = gap;
            while remaining > 0 {
                let n = remaining.min(4096) as usize;
                file.write_all(&zeros[..n])?;
                remaining -= n as u64;
            }
        }
    }

    let offset = block_offset(header.version, block_idx, header.block_size)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&ciphertext)?;
    Ok(())
}
