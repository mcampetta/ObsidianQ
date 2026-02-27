//! Chunked parallel encryption / decryption engine.
//!
//! Pipeline (encryption):
//!   Read → Split into chunks → [optional: zstd compress] →
//!   Derive per-chunk subkey → AEAD encrypt (parallel via rayon) →
//!   Write header + chunk records + footer
//!
//! Pipeline (decryption):
//!   Read full file → Verify header MAC → Parse footer from tail →
//!   Zero-copy chunk boundary scan → Parallel AEAD decrypt →
//!   Stream-write plaintext chunks (no full-file concat)
//!
//! MAC domain separation (v2 format):
//!   Header MAC : BLAKE3-keyed(K_master, "obsidianq-v1-header\x00" || canonical_header)
//!   Footer MAC : BLAKE3-keyed(K_master, "obsidianq-v1-footer\x00" || header_hash || chunk_tags)
//!
//! The footer explicitly binds the header_hash, preventing cross-file footer
//! substitution even if K_master were ever reused.

use std::io::{Read, Seek, SeekFrom, Write};

use rayon::prelude::*;
use zeroize::Zeroize;

use crate::crypto::{
    aead::{self, build_aad},
    kdf::{self, MasterKey},
};
use crate::error::{ObsidianError, Result};
use crate::format::{self, ChunkRecord, FileFooter, FileHeader, SuiteId, flags};

pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024; // 1 MiB

// ── MAC helpers ───────────────────────────────────────────────────────────────

/// Domain-separated BLAKE3 keyed MAC using the streaming API so we can feed
/// multiple data segments without extra allocation.
///
/// Output = BLAKE3-keyed(key, domain || "\x00" || segments...)
fn mac_keyed(key: &[u8; 32], domain: &[u8], segments: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(domain);
    h.update(b"\x00"); // null separator between domain and data
    for seg in segments {
        h.update(seg);
    }
    h.finalize().into()
}

// Domain labels — changing these would be a format-breaking version bump.
const DOMAIN_HEADER: &[u8] = b"obsidianq-v1-header";
const DOMAIN_FOOTER: &[u8] = b"obsidianq-v1-footer";

// ── Encryption ────────────────────────────────────────────────────────────────

/// All the information needed to start encrypting, independent of key source.
pub struct EncryptParams {
    pub master_key: MasterKey,
    /// KEM data embedded in header:
    ///   Password mode : 32-byte Argon2id salt
    ///   PQC mode      : 1088-byte KEM ciphertext || 32-byte HKDF salt
    pub kem_data:   Vec<u8>,
    pub mode:       format::Mode,
    pub suite:      SuiteId,
    pub chunk_size: u32,
    pub compress:   bool,
    /// Random 16-byte file ID (caller generates this).
    pub file_id:    [u8; 16],
}

/// Encrypt `reader` → write `.obsq` format to `writer`.
///
/// Returns number of chunks written.
pub fn encrypt<R, W>(params: EncryptParams, reader: &mut R, writer: &mut W) -> Result<u64>
where
    R: Read,
    W: Write,
{
    // 1. Read all plaintext into memory.
    //    EXTENSION POINT: replace with streaming per-chunk I/O for files that
    //    exceed available RAM.
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    // 2. Optional compression (before encryption — never after).
    let body: Vec<u8> = if params.compress {
        zstd::encode_all(plaintext.as_slice(), 3)
            .map_err(|e| ObsidianError::CompressionError(e.to_string()))?
    } else {
        plaintext
    };

    // 3. Build header (MAC field zeroed for now — filled in step 5).
    let flags_byte = if params.compress { flags::COMPRESSED } else { 0 };
    let mut header = FileHeader {
        version:    format::VERSION,
        mode:       params.mode,
        suite:      params.suite,
        flags:      flags_byte,
        chunk_size: params.chunk_size,
        file_id:    params.file_id,
        kem_data:   params.kem_data,
        mac:        [0u8; 32],
    };

    // 4. Canonical header bytes for MAC computation (excludes the mac field).
    let canonical     = header.canonical_bytes_for_mac();
    let header_hash: [u8; 32] = blake3::hash(&canonical).into();

    // 5. Header MAC — domain-separated so it can never collide with footer MAC.
    //    DOMAIN_HEADER || "\x00" || canonical_header
    header.mac = mac_keyed(params.master_key.as_bytes(), DOMAIN_HEADER, &[&canonical]);

    // 6. Write header.
    header.write_to(writer)?;

    // 7. Split body into chunks and encrypt in parallel.
    let cs      = params.chunk_size as usize;
    let chunks: Vec<&[u8]> = body.chunks(cs).collect();
    let n_chunks = chunks.len() as u64;

    let results: Vec<Result<ChunkRecord>> = chunks
        .into_par_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let idx    = i as u64;
            let subkey = kdf::derive_chunk_key(&params.master_key, &header_hash, idx)?;
            let aad    = build_aad(&header_hash, idx);
            let ct     = aead::encrypt_chunk(
                params.suite,
                &subkey,
                &params.file_id,
                idx,
                chunk,
                &aad,
            )?;
            Ok(ChunkRecord { index: idx, ciphertext: ct })
        })
        .collect();

    // 8. Write chunks in index order and accumulate tags for footer MAC.
    let mut records: Vec<ChunkRecord> = results.into_iter().collect::<Result<_>>()?;
    records.sort_by_key(|r| r.index);

    let mut tag_accumulator: Vec<u8> = Vec::with_capacity(n_chunks as usize * 16);
    for rec in &records {
        let tag_start = rec.ciphertext.len().saturating_sub(16);
        tag_accumulator.extend_from_slice(&rec.ciphertext[tag_start..]);
        rec.write_to(writer)?;
    }

    // 9. Footer MAC — domain-separated AND explicitly binds header_hash.
    //    DOMAIN_FOOTER || "\x00" || header_hash || concatenated_chunk_tags
    //
    //    Binding header_hash closes the gap where footer from file A could
    //    theoretically be substituted into file B if K_master were shared.
    let global_mac = mac_keyed(
        params.master_key.as_bytes(),
        DOMAIN_FOOTER,
        &[header_hash.as_slice(), &tag_accumulator],
    );

    FileFooter { chunk_count: n_chunks, global_mac }.write_to(writer)?;

    Ok(n_chunks)
}

// ── Decryption ────────────────────────────────────────────────────────────────

/// Decrypt an `.obsq` stream into `writer`.
///
/// Performance notes (v2 engine):
///   - One `read_to_end` into `raw` (unavoidable — footer is at the tail).
///   - Chunk boundary scan is zero-copy: we record (index, ct_start, ct_end)
///     offsets into `raw` without allocating per-chunk ciphertext buffers.
///   - Parallel AEAD decryption over slices into `raw`.
///   - Plaintext chunks written directly to `writer` in order — no full-file
///     concatenation buffer.
///   - Peak memory: ~2× file size (raw ciphertext + decrypted plaintexts),
///     down from ~4× in the previous implementation.
pub fn decrypt<R, W>(master_key: &MasterKey, reader: &mut R, writer: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    // 1. Read the full file into memory.  The footer is at the tail so we
    //    cannot avoid buffering the whole file unless the caller provides Seek.
    //    EXTENSION POINT: accept R: Read + Seek to avoid this.
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw)?;

    // 2. Parse and verify header.
    let (header, mut pos) = {
        let mut cur = std::io::Cursor::new(&raw);
        let h   = FileHeader::read_from(&mut cur)?;
        let end = cur.position() as usize;
        (h, end)
    };

    let canonical    = header.canonical_bytes_for_mac();
    let header_hash: [u8; 32] = blake3::hash(&canonical).into();

    let expected_mac = mac_keyed(master_key.as_bytes(), DOMAIN_HEADER, &[&canonical]);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(expected_mac.as_slice(), header.mac.as_slice())) {
        return Err(ObsidianError::HeaderMacFailure);
    }

    // 3. Parse footer from the last 40 bytes.
    //    Footer layout: chunk_count (u64 LE) || global_mac ([u8; 32]) = 40 bytes.
    const FOOTER_SIZE: usize = 8 + 32;
    if raw.len() < FOOTER_SIZE {
        return Err(ObsidianError::TruncatedHeader { needed: FOOTER_SIZE, got: raw.len() });
    }
    let footer_offset = raw.len() - FOOTER_SIZE;
    let footer = {
        let mut cur = std::io::Cursor::new(&raw[footer_offset..]);
        FileFooter::read_from(&mut cur)?
    };

    // 4. Zero-copy chunk boundary scan.
    //    Instead of allocating a Vec<u8> per chunk (the old approach), we
    //    record byte ranges into `raw`.  This eliminates O(n) ciphertext copies.
    //
    //    Each chunk record on disk: index(8) || ct_len(4) || ciphertext(ct_len)
    let body_end = footer_offset;
    let mut chunk_refs: Vec<(u64, usize, usize)> = // (index, ct_start, ct_end)
        Vec::with_capacity(footer.chunk_count as usize);

    while pos < body_end {
        // Need at least 12 bytes for the record header (index + ct_len).
        if pos + 12 > body_end {
            return Err(ObsidianError::TruncatedHeader {
                needed: pos + 12,
                got:    body_end,
            });
        }
        let idx = u64::from_le_bytes([
            raw[pos],   raw[pos+1], raw[pos+2], raw[pos+3],
            raw[pos+4], raw[pos+5], raw[pos+6], raw[pos+7],
        ]);
        let ct_len = u32::from_le_bytes([
            raw[pos+8], raw[pos+9], raw[pos+10], raw[pos+11],
        ]) as usize;
        pos += 12;

        if pos + ct_len > body_end {
            return Err(ObsidianError::TruncatedHeader {
                needed: pos + ct_len,
                got:    body_end,
            });
        }
        chunk_refs.push((idx, pos, pos + ct_len));
        pos += ct_len;
    }

    // 5. Verify chunk count.
    if footer.chunk_count != chunk_refs.len() as u64 {
        return Err(ObsidianError::ChunkIndexMismatch {
            expected: footer.chunk_count,
            got:      chunk_refs.len() as u64,
        });
    }

    // 6. Verify footer MAC (domain-separated, binds header_hash).
    //    Tag accumulator: last 16 bytes of each ciphertext, in chunk order.
    let mut tag_acc: Vec<u8> = Vec::with_capacity(chunk_refs.len() * 16);
    for (_, ct_start, ct_end) in &chunk_refs {
        let ct       = &raw[*ct_start..*ct_end];
        let tag_off  = ct.len().saturating_sub(16);
        tag_acc.extend_from_slice(&ct[tag_off..]);
    }

    let expected_global = mac_keyed(
        master_key.as_bytes(),
        DOMAIN_FOOTER,
        &[header_hash.as_slice(), &tag_acc],
    );
    if !bool::from(subtle::ConstantTimeEq::ct_eq(expected_global.as_slice(), footer.global_mac.as_slice())) {
        return Err(ObsidianError::FooterMacFailure);
    }

    // 7. Parallel AEAD decryption over zero-copy slices into `raw`.
    //    rayon distributes chunks across thread pool; each closure borrows
    //    `raw` immutably (safe — no writes during parallel phase).
    let suite   = header.suite;
    let file_id = header.file_id;

    let plaintexts: Vec<Result<(u64, Vec<u8>)>> = chunk_refs
        .par_iter()
        .map(|(idx, ct_start, ct_end)| {
            let ct     = &raw[*ct_start..*ct_end];
            let subkey = kdf::derive_chunk_key(master_key, &header_hash, *idx)?;
            let aad    = build_aad(&header_hash, *idx);
            let pt     = aead::decrypt_chunk(suite, &subkey, &file_id, *idx, ct, &aad)
                .map_err(|_| ObsidianError::ChunkAuthFailure { index: *idx })?;
            Ok((*idx, pt))
        })
        .collect();

    // 8. Sort by chunk index (rayon does not preserve order).
    let mut ordered: Vec<(u64, Vec<u8>)> = plaintexts.into_iter().collect::<Result<_>>()?;
    ordered.sort_by_key(|(i, _)| *i);

    // 9. Output — compressed or direct.
    if header.flags & flags::COMPRESSED != 0 {
        // Compressed path: build contiguous buffer, decompress, write.
        // Pre-size the buffer to avoid reallocations.
        let total_pt_len: usize = ordered.iter().map(|(_, pt)| pt.len()).sum();
        let mut body: Vec<u8>   = Vec::with_capacity(total_pt_len);
        for (_, pt) in &ordered {
            body.extend_from_slice(pt);
        }
        drop(ordered); // release per-chunk plaintext Vecs before decompressing

        let decompressed = zstd::decode_all(body.as_slice())
            .map_err(|e| ObsidianError::DecompressionError(e.to_string()))?;
        body.zeroize();
        writer.write_all(&decompressed)?;
    } else {
        // Non-compressed path: stream each chunk's plaintext directly to the
        // writer.  Eliminates the previous flat_map().collect() O(n) copy.
        for (_, pt) in ordered {
            writer.write_all(&pt)?;
        }
    }

    Ok(())
}

// ── Seekable manifest (random-access container opening) ───────────────────────

/// Byte-range descriptor for a single encrypted chunk within the container file.
/// All offsets are absolute byte positions in the container file on disk.
#[derive(Debug, Clone)]
pub struct ChunkRef {
    /// Chunk index (matches the 8-byte index field stored in each chunk record).
    pub index: u64,
    /// Absolute file offset where the ciphertext bytes start (after the 12-byte record header).
    pub ct_file_offset: u64,
    /// Length of ciphertext in bytes (includes the 16-byte AEAD authentication tag).
    pub ct_len: usize,
}

impl ChunkRef {
    /// Plaintext byte count produced by decrypting this chunk (ct_len minus the 16-byte tag).
    pub fn plaintext_len(&self) -> usize {
        self.ct_len.saturating_sub(16)
    }
}

/// Seekable view of an `.obsq` container, built without loading ciphertext into memory.
///
/// Created by `open_container()`.  Used by the virtual-filesystem layer to
/// perform lazy, per-chunk decryption on demand.
pub struct ContainerManifest {
    pub header:      FileHeader,
    pub header_hash: [u8; 32],
    /// Chunk byte-range map, sorted by chunk index.
    pub chunk_refs:  Vec<ChunkRef>,
    /// Total decrypted plaintext size in bytes.
    /// Accurate only for non-compressed containers.
    pub total_plaintext_len: u64,
}

/// Open an `.obsq` container for seekable/lazy decryption.
///
/// Unlike `decrypt()`, this function:
/// - Reads only the header and chunk *record headers* (12 bytes each) — not the ciphertext.
/// - Verifies both the header MAC and the footer MAC before returning.
/// - Returns a `ContainerManifest` that allows callers to seek and decrypt
///   individual chunks on demand.
///
/// # Errors
/// - Returns `Err` if any MAC verification fails.
/// - Returns `Err` if the `COMPRESSED` flag is set — compressed containers
///   require full decryption to determine plaintext size and cannot be mounted
///   as random-access virtual files.
pub fn open_container<R: Read + Seek>(
    master_key: &kdf::MasterKey,
    reader:     &mut R,
) -> Result<ContainerManifest> {
    // 1. Seek to start and parse the header.  Record the stream position
    //    immediately after, which is the first byte of the chunk body.
    reader.seek(SeekFrom::Start(0))?;
    let header = FileHeader::read_from(reader)?;
    let body_start: u64 = reader.seek(SeekFrom::Current(0))?;

    // 2. Compressed containers cannot be seekably random-accessed —
    //    we cannot determine plaintext size without full decompression.
    if header.flags & flags::COMPRESSED != 0 {
        return Err(ObsidianError::CompressionError(
            "cannot mount compressed container: plaintext size unknown \
             without full decompression (Phase 1 limitation)".into(),
        ));
    }

    // 3. Verify header MAC.
    let canonical    = header.canonical_bytes_for_mac();
    let header_hash: [u8; 32] = blake3::hash(&canonical).into();
    let expected_mac = mac_keyed(master_key.as_bytes(), DOMAIN_HEADER, &[&canonical]);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(expected_mac.as_slice(), header.mac.as_slice())) {
        return Err(ObsidianError::HeaderMacFailure);
    }

    // 4. Locate and parse the footer (last 40 bytes of the file).
    const FOOTER_SIZE: u64 = 8 + 32;
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len < body_start + FOOTER_SIZE {
        return Err(ObsidianError::TruncatedHeader {
            needed: (body_start + FOOTER_SIZE) as usize,
            got:    file_len as usize,
        });
    }
    let footer_offset = file_len - FOOTER_SIZE;
    reader.seek(SeekFrom::Start(footer_offset))?;
    let footer = FileFooter::read_from(reader)?;

    // 5. Scan chunk *record headers* (12 bytes each) to build the offset map.
    //    We do NOT read the ciphertext — we seek past it.
    //    Each on-disk record: index(8) || ct_len(4) || ciphertext(ct_len)
    let mut pos: u64 = body_start;
    let mut chunk_refs = Vec::with_capacity(footer.chunk_count as usize);
    reader.seek(SeekFrom::Start(pos))?;

    while pos < footer_offset {
        let mut rec_hdr = [0u8; 12];
        reader.read_exact(&mut rec_hdr)?;

        let idx    = u64::from_le_bytes(rec_hdr[0..8].try_into().unwrap());
        let ct_len = u32::from_le_bytes(rec_hdr[8..12].try_into().unwrap()) as usize;
        let ct_file_offset = pos + 12;

        if ct_file_offset + ct_len as u64 > footer_offset {
            return Err(ObsidianError::TruncatedHeader {
                needed: (ct_file_offset + ct_len as u64) as usize,
                got:    footer_offset as usize,
            });
        }
        chunk_refs.push(ChunkRef { index: idx, ct_file_offset, ct_len });

        pos = ct_file_offset + ct_len as u64;
        reader.seek(SeekFrom::Start(pos))?;
    }

    // 6. Verify chunk count.
    if footer.chunk_count != chunk_refs.len() as u64 {
        return Err(ObsidianError::ChunkIndexMismatch {
            expected: footer.chunk_count,
            got:      chunk_refs.len() as u64,
        });
    }

    // 7. Verify footer MAC.  Requires reading the last 16 bytes (AEAD tag)
    //    from each chunk ciphertext.  Seek to each tag individually.
    let mut tag_acc: Vec<u8> = Vec::with_capacity(chunk_refs.len() * 16);
    for cr in &chunk_refs {
        if cr.ct_len < 16 {
            return Err(ObsidianError::ChunkAuthFailure { index: cr.index });
        }
        let tag_offset = cr.ct_file_offset + (cr.ct_len as u64 - 16);
        reader.seek(SeekFrom::Start(tag_offset))?;
        let mut tag = [0u8; 16];
        reader.read_exact(&mut tag)?;
        tag_acc.extend_from_slice(&tag);
    }
    let expected_global = mac_keyed(
        master_key.as_bytes(),
        DOMAIN_FOOTER,
        &[header_hash.as_slice(), &tag_acc],
    );
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        expected_global.as_slice(),
        footer.global_mac.as_slice(),
    )) {
        return Err(ObsidianError::FooterMacFailure);
    }

    // 8. Sort by index (guaranteed in order by the writer, but be defensive).
    chunk_refs.sort_by_key(|r| r.index);

    let total_plaintext_len: u64 = chunk_refs.iter().map(|r| r.plaintext_len() as u64).sum();

    Ok(ContainerManifest { header, header_hash, chunk_refs, total_plaintext_len })
}

/// Compute the BLAKE3 hash of the canonical serialised header (excludes mac).
pub fn hash_header(header: &FileHeader) -> [u8; 32] {
    blake3::hash(&header.canonical_bytes_for_mac()).into()
}
