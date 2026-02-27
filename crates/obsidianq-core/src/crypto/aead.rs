//! AEAD cipher dispatch — XChaCha20-Poly1305 and AES-256-GCM.
//!
//! EXTENSION POINT: add new SuiteIds here to experiment with other AEAD
//! constructions without touching the engine.

use aes_gcm::{Aes256Gcm, aead::{KeyInit, Aead, Payload}};
use chacha20poly1305::XChaCha20Poly1305;

use crate::crypto::kdf::ChunkKey;
use crate::crypto::nonce;
use crate::error::{ObsidianError, Result};
use crate::format::SuiteId;

/// Encrypt `plaintext` returning `ciphertext || tag` (tag is last 16 bytes).
///
/// `aad` is authenticated but not encrypted.  We bind:
///   aad = header_hash (32B) || chunk_index (8B LE)
pub fn encrypt_chunk(
    suite:       SuiteId,
    key:         &ChunkKey,
    file_id:     &[u8; 16],
    chunk_index: u64,
    plaintext:   &[u8],
    aad:         &[u8],
) -> Result<Vec<u8>> {
    match suite {
        SuiteId::XChaCha20Poly1305 => {
            let nonce = nonce::derive_xchacha20_nonce(file_id, chunk_index)?;
            let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
            cipher
                .encrypt(nonce.as_slice().into(), Payload { msg: plaintext, aad })
                .map_err(|_| ObsidianError::AeadEncryptError)
        }
        SuiteId::Aes256Gcm => {
            let nonce = nonce::derive_aesgcm_nonce(file_id, chunk_index)?;
            let cipher = Aes256Gcm::new(key.as_bytes().into());
            cipher
                .encrypt(nonce.as_slice().into(), Payload { msg: plaintext, aad })
                .map_err(|_| ObsidianError::AeadEncryptError)
        }
    }
}

/// Decrypt `ciphertext_and_tag` returning plaintext.
pub fn decrypt_chunk(
    suite:       SuiteId,
    key:         &ChunkKey,
    file_id:     &[u8; 16],
    chunk_index: u64,
    ciphertext:  &[u8],
    aad:         &[u8],
) -> Result<Vec<u8>> {
    match suite {
        SuiteId::XChaCha20Poly1305 => {
            let nonce = nonce::derive_xchacha20_nonce(file_id, chunk_index)?;
            let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
            cipher
                .decrypt(nonce.as_slice().into(), Payload { msg: ciphertext, aad })
                .map_err(|_| ObsidianError::AeadDecryptError)
        }
        SuiteId::Aes256Gcm => {
            let nonce = nonce::derive_aesgcm_nonce(file_id, chunk_index)?;
            let cipher = Aes256Gcm::new(key.as_bytes().into());
            cipher
                .decrypt(nonce.as_slice().into(), Payload { msg: ciphertext, aad })
                .map_err(|_| ObsidianError::AeadDecryptError)
        }
    }
}

/// Build the AAD for a given chunk:
///   aad = header_hash || chunk_index_le64
///
/// This ties every chunk ciphertext to the exact header it belongs to,
/// preventing header-swap and chunk-reorder attacks.
pub fn build_aad(header_hash: &[u8; 32], chunk_index: u64) -> [u8; 40] {
    let mut aad = [0u8; 40];
    aad[..32].copy_from_slice(header_hash);
    aad[32..].copy_from_slice(&chunk_index.to_le_bytes());
    aad
}
