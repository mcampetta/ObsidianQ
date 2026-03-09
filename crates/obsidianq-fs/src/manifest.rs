//! Re-exports container manifest types from `obsidianq-core` and adds
//! FS-layer helpers for mapping virtual byte offsets to chunk indices.

pub use obsidianq_core::{ChunkRef, ContainerManifest};

/// Given a virtual file byte range `[offset, offset+length)`, return the
/// slice of `ChunkRef`s that overlap with it.
///
/// All chunks have the same plaintext size (`header.chunk_size`) except the
/// last, which may be smaller.
pub fn chunks_for_range<'a>(
    manifest: &'a ContainerManifest,
    offset: u64,
    length: usize,
) -> &'a [ChunkRef] {
    if length == 0 || manifest.chunk_refs.is_empty() {
        return &[];
    }
    let chunk_size = manifest.header.chunk_size as u64;
    let end = offset
        .saturating_add(length as u64)
        .min(manifest.total_plaintext_len);
    if offset >= end {
        return &[];
    }

    let first = (offset / chunk_size) as usize;
    let last = ((end - 1) / chunk_size) as usize;

    let n = manifest.chunk_refs.len();
    let first = first.min(n);
    let last = (last + 1).min(n);
    &manifest.chunk_refs[first..last]
}

/// Byte offset within a chunk's plaintext where the virtual offset `file_offset`
/// falls, given the chunk index.
pub fn chunk_inner_offset(file_offset: u64, chunk_index: u64, chunk_size: u32) -> usize {
    let chunk_start = chunk_index * chunk_size as u64;
    file_offset.saturating_sub(chunk_start) as usize
}
