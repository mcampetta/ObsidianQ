//! Per-chunk lazy decryption for the virtual filesystem.
//!
//! Security contract:
//!   - Plaintext is held in a `ZeroizingVec` and dropped (zeroized) as soon
//!     as the calling read operation completes.
//!   - The container file is opened read-only for each read call and closed
//!     immediately after.  This keeps the file handle lifetime minimal and
//!     avoids any long-lived OS buffering of plaintext bytes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use obsidianq_core::{
    ChunkRef, ContainerManifest,
    crypto::{aead::{self, build_aad}, kdf::{self, MasterKey}},
};
use zeroize::Zeroizing;

use crate::error::{FsError, Result};

/// Decrypt exactly one chunk and return its plaintext wrapped in a `Zeroizing`
/// buffer.  The caller is responsible for dropping the buffer promptly after use.
///
/// # Arguments
/// * `container_path` — path to the `.obsq` file on disk.
/// * `master_key`     — master key (borrowed; not cloned).
/// * `manifest`       — parsed container manifest.
/// * `cr`             — the specific `ChunkRef` to decrypt.
pub fn decrypt_chunk_from_file(
    container_path: &Path,
    master_key:     &MasterKey,
    manifest:       &ContainerManifest,
    cr:             &ChunkRef,
) -> Result<Zeroizing<Vec<u8>>> {
    // Open the container file read-only for this single chunk access.
    let mut f = File::open(container_path)?;
    f.seek(SeekFrom::Start(cr.ct_file_offset))?;

    let mut ciphertext = vec![0u8; cr.ct_len];
    f.read_exact(&mut ciphertext)?;
    drop(f); // close file handle immediately

    // Derive the per-chunk subkey.
    let subkey = kdf::derive_chunk_key(master_key, &manifest.header_hash, cr.index)
        .map_err(FsError::Container)?;

    // Build AAD and decrypt.
    let aad = build_aad(&manifest.header_hash, cr.index);
    let plaintext = aead::decrypt_chunk(
        manifest.header.suite,
        &subkey,
        &manifest.header.file_id,
        cr.index,
        &ciphertext,
        &aad,
    )
    .map_err(|e| FsError::Container(e))?;

    // Zeroize the ciphertext buffer before returning.
    let mut ct_zeroize = ciphertext;
    use zeroize::Zeroize as _;
    ct_zeroize.zeroize();

    Ok(Zeroizing::new(plaintext))
}

/// Fill `out_buf` from a virtual file read at `[file_offset, file_offset+len)`.
///
/// This may decrypt multiple chunks if the read spans a chunk boundary.
/// Returns the number of bytes actually written into `out_buf`.
pub fn read_virtual(
    container_path: &Path,
    master_key:     &MasterKey,
    manifest:       &ContainerManifest,
    file_offset:    u64,
    out_buf:        &mut [u8],
) -> Result<usize> {
    use crate::manifest::{chunk_inner_offset, chunks_for_range};

    if out_buf.is_empty() { return Ok(0); }

    // Clamp read to actual file size.
    let avail = manifest.total_plaintext_len.saturating_sub(file_offset);
    if avail == 0 { return Ok(0); }
    let len = (out_buf.len() as u64).min(avail) as usize;
    let out_buf = &mut out_buf[..len];

    let chunk_size = manifest.header.chunk_size as u64;
    let needed_chunks = chunks_for_range(manifest, file_offset, len);

    let mut written = 0usize;

    for cr in needed_chunks {
        let pt = decrypt_chunk_from_file(container_path, master_key, manifest, cr)?;

        // Byte range within this chunk's plaintext that overlaps [file_offset, file_offset+len)
        let chunk_pt_start = cr.index * chunk_size;
        let inner_start    = chunk_inner_offset(file_offset + written as u64, cr.index, manifest.header.chunk_size);
        let inner_end      = pt.len().min(inner_start + (len - written));

        let src = &pt[inner_start..inner_end];
        out_buf[written..written + src.len()].copy_from_slice(src);
        written += src.len();

        // `pt` (Zeroizing<Vec<u8>>) is zeroized here when it drops.
        drop(pt);

        if written >= len { break; }
        let _ = chunk_pt_start; // suppress unused warning
    }

    Ok(written)
}
