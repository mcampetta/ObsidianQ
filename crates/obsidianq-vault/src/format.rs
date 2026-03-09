//! On-disk binary layout for the `.vault` vault format.
//!
//! ## Fixed offsets (by version)
//! ```text
//! v1:
//!   Offset 0    : Immutable section  (2048 bytes, padded)
//!   Offset 2048 : Superblock A       (128 bytes)
//!   Offset 2176 : Superblock B       (128 bytes)
//!   Offset 2304 : Block 0            (first BAT block)
//!
//! v2:
//!   Offset 0    : Immutable section  (8192 bytes, padded)
//!   Offset 8192 : Superblock A       (128 bytes)
//!   Offset 8320 : Superblock B       (128 bytes)
//!   Offset 8448 : Block 0            (first BAT block)
//! ```
//!
//! Each block is `block_size` bytes on disk = plaintext ‖ 16-byte AEAD tag.
//! Usable plaintext per block = `block_size − 16`.

use byteorder::{ReadBytesExt, LE};
use obsidianq_core::format::{Mode, SuiteId};
use std::io::{Cursor, Read, Write};

use crate::{Result, VaultError};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

pub const MAGIC: &[u8; 9] = b"OBSQVAULT";
pub const LEGACY_MAGIC: &[u8; 5] = b"OBSQV";
pub const LEGACY_MAGIC_DEV: &[u8; 4] = b"OBSV";
pub const VERSION_V1: u8 = 0x01;
pub const VERSION_V2: u8 = 0x02;
pub const VERSION: u8 = VERSION_V2;

/// Default block size (64 KiB).
pub const BLOCK_SIZE_DEFAULT: u32 = 65_536;
/// Usable plaintext bytes per block at default block size.
pub const USABLE_DEFAULT: usize = (BLOCK_SIZE_DEFAULT - 16) as usize; // 65520

pub const IMMUTABLE_SECTION_SIZE_V1: usize = 2048;
pub const IMMUTABLE_SECTION_SIZE_V2: usize = 8192;
pub const SUPERBLOCK_SIZE: usize = 128;

pub fn immutable_section_size_for_version(version: u8) -> Result<usize> {
    match version {
        VERSION_V1 => Ok(IMMUTABLE_SECTION_SIZE_V1),
        VERSION_V2 => Ok(IMMUTABLE_SECTION_SIZE_V2),
        other => Err(VaultError::UnsupportedVersion(other)),
    }
}

pub fn superblock_offsets_for_version(version: u8) -> Result<(u64, u64, u64)> {
    let imm = immutable_section_size_for_version(version)? as u64;
    let sb_a = imm;
    let sb_b = sb_a + SUPERBLOCK_SIZE as u64;
    let blocks_start = sb_b + SUPERBLOCK_SIZE as u64;
    Ok((sb_a, sb_b, blocks_start))
}

pub fn immutable_kem_capacity_for_version(version: u8) -> Result<usize> {
    // canonical bytes = MAGIC + version + mode + suite + flags + block_size + file_id + kem_len + kem_data
    let fixed_canonical = MAGIC.len() + 1 + 1 + 1 + 1 + 4 + 16 + 2;
    let section = immutable_section_size_for_version(version)?;
    let reserved_for_mac = 32usize;
    section
        .checked_sub(fixed_canonical + reserved_for_mac)
        .ok_or_else(|| VaultError::FormatError("immutable section too small".into()))
}

/// Directory entries per block (255 × 256 bytes = 65280 bytes of entries).
pub const DIR_ENTRIES_PER_BLOCK: usize = 255;
/// Fixed directory entry size.
pub const DIR_ENTRY_SIZE: usize = 256;
/// File index block pointers: 65520 / 8 = 8190.
pub const INDEX_PTRS_PER_BLOCK: usize = 8190;
/// For chained index blocks, last 2 slots are metadata:
/// - slot `INDEX_DATA_PTRS_PER_CHAIN_BLOCK` stores `INDEX_CHAIN_SENTINEL` when chained.
/// - slot `INDEX_DATA_PTRS_PER_CHAIN_BLOCK + 1` stores next index block pointer.
pub const INDEX_DATA_PTRS_PER_CHAIN_BLOCK: usize = INDEX_PTRS_PER_BLOCK - 2;
pub const INDEX_CHAIN_SENTINEL: u64 = u64::MAX - 1;

/// Entry type constants.
pub const ENTRY_FREE: u8 = 0;
pub const ENTRY_FILE: u8 = 1;
pub const ENTRY_DIR: u8 = 2;

/// Maximum UTF-8 bytes in an entry name.
pub const ENTRY_NAME_MAX: usize = 208;

// ---------------------------------------------------------------------------
// ImmutableHeader (version-specific padded size)
// ---------------------------------------------------------------------------

/// The immutable section at the start of every `.vault` file.
///
/// Once written during `create`, this section is never modified.
/// The `immutable_mac` is also used as the `header_hash` for all per-block
/// key derivation (via `derive_chunk_key`).
#[derive(Debug, Clone)]
pub struct ImmutableHeader {
    pub version: u8,
    pub mode: Mode,
    pub suite: SuiteId,
    pub flags: u8,
    /// Block size in bytes (default 65536; stored as u32 LE on disk).
    pub block_size: u32,
    /// Random 16-byte file ID for nonce derivation.
    pub file_id: [u8; 16],
    /// KEM data: 32-byte Argon2 salt (password) or KEM-CT ‖ HKDF-salt (PQC).
    pub kem_data: Vec<u8>,
    /// BLAKE3-keyed MAC over all preceding bytes in this section.
    pub immutable_mac: [u8; 32],
}

impl ImmutableHeader {
    /// Serialize everything BEFORE the MAC for MAC computation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.kem_data.len());
        buf.extend_from_slice(MAGIC);
        buf.push(self.version);
        buf.push(self.mode as u8);
        buf.push(self.suite as u8);
        buf.push(self.flags);
        buf.extend_from_slice(&self.block_size.to_le_bytes());
        buf.extend_from_slice(&self.file_id);
        buf.extend_from_slice(&(self.kem_data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.kem_data);
        buf
    }

    /// Write exactly `immutable_section_size_for_version(self.version)` bytes
    /// (canonical + MAC + padding).
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        let immutable_size = immutable_section_size_for_version(self.version)?;
        let canonical = self.canonical_bytes();
        let written = canonical.len() + 32;
        if written > immutable_size {
            return Err(VaultError::FormatError("immutable header too large".into()));
        }
        w.write_all(&canonical)?;
        w.write_all(&self.immutable_mac)?;
        // Zero-pad to the immutable section size for this vault version.
        let pad = immutable_size - written;
        w.write_all(&vec![0u8; pad])?;
        Ok(())
    }

    /// Read and parse a version-sized immutable section. Does NOT verify the MAC.
    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        // Read enough bytes to identify magic + version.
        let mut head = [0u8; 16];
        r.read_exact(&mut head)?;

        let magic_len = if head.starts_with(MAGIC) {
            MAGIC.len()
        } else if head.starts_with(LEGACY_MAGIC) {
            eprintln!("[WARN] Opening legacy vault header magic 'OBSQV'.");
            LEGACY_MAGIC.len()
        } else if head.starts_with(LEGACY_MAGIC_DEV) {
            eprintln!("[WARN] Opening legacy vault header magic 'OBSV'.");
            LEGACY_MAGIC_DEV.len()
        } else {
            return Err(VaultError::InvalidMagic);
        };
        if magic_len >= head.len() {
            return Err(VaultError::FormatError("truncated immutable header".into()));
        }
        let version = head[magic_len];
        let immutable_size = immutable_section_size_for_version(version)?;

        let mut raw = vec![0u8; immutable_size];
        raw[..head.len()].copy_from_slice(&head);
        r.read_exact(&mut raw[head.len()..])?;

        let mut cur = Cursor::new(&raw[magic_len..]);

        let version_read = cur.read_u8()?;
        if version_read != version {
            return Err(VaultError::FormatError(
                "immutable header version mismatch".into(),
            ));
        }
        if version != VERSION_V1 && version != VERSION_V2 {
            return Err(VaultError::UnsupportedVersion(version));
        }

        let mode = Mode::try_from(cur.read_u8()?).map_err(|_| VaultError::InvalidMode)?;
        let suite = SuiteId::try_from(cur.read_u8()?).map_err(|_| VaultError::InvalidSuite)?;
        let flags = cur.read_u8()?;
        let block_size = cur.read_u32::<LE>()?;

        let mut file_id = [0u8; 16];
        cur.read_exact(&mut file_id)?;

        let kem_len = cur.read_u16::<LE>()? as usize;
        let mut kem_data = vec![0u8; kem_len];
        cur.read_exact(&mut kem_data)?;

        let pos = magic_len + cur.position() as usize;
        let mut immutable_mac = [0u8; 32];
        immutable_mac.copy_from_slice(&raw[pos..pos + 32]);

        Ok(ImmutableHeader {
            version,
            mode,
            suite,
            flags,
            block_size,
            file_id,
            kem_data,
            immutable_mac,
        })
    }

    /// Compute usable plaintext bytes per block for this header.
    pub fn usable_bytes(&self) -> usize {
        (self.block_size - 16) as usize
    }
}

// ---------------------------------------------------------------------------
// Superblock (128 bytes, dual-slot)
// ---------------------------------------------------------------------------

/// Dual-slot crash-safe superblock (128 bytes each).
///
/// On open, both slots are read; the one with a valid MAC and the higher
/// `commit_counter` is the active state.
#[derive(Debug, Clone, Default)]
pub struct Superblock {
    pub commit_counter: u64,    // monotonically increasing
    pub total_block_count: u64, // current data blocks (auto-grows)
    pub bat_block_count: u32,   // leading BAT blocks (always 1 in v1)
    pub root_dir_block: u64,    // data block index of root DirBlock
    // 68 bytes reserved (128 - 28 fields - 32 mac = 68)
    pub slot_mac: [u8; 32],
}

impl Superblock {
    /// Serialize the fields before the MAC (96 bytes: 28 data + 68 reserved).
    pub fn body_bytes(&self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        buf[0..8].copy_from_slice(&self.commit_counter.to_le_bytes());
        buf[8..16].copy_from_slice(&self.total_block_count.to_le_bytes());
        buf[16..20].copy_from_slice(&self.bat_block_count.to_le_bytes());
        buf[20..28].copy_from_slice(&self.root_dir_block.to_le_bytes());
        // bytes 28..96 are reserved zeros
        buf
    }

    /// Write exactly 128 bytes.
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        w.write_all(&self.body_bytes())?;
        w.write_all(&self.slot_mac)?;
        Ok(())
    }

    /// Read exactly 128 bytes. Does NOT verify the MAC.
    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut raw = [0u8; SUPERBLOCK_SIZE];
        r.read_exact(&mut raw)?;
        let mut cur = Cursor::new(&raw[..]);

        let commit_counter = cur.read_u64::<LE>()?;
        let total_block_count = cur.read_u64::<LE>()?;
        let bat_block_count = cur.read_u32::<LE>()?;
        let root_dir_block = cur.read_u64::<LE>()?;

        let mut slot_mac = [0u8; 32];
        slot_mac.copy_from_slice(&raw[SUPERBLOCK_SIZE - 32..]);

        Ok(Superblock {
            commit_counter,
            total_block_count,
            bat_block_count,
            root_dir_block,
            slot_mac,
        })
    }
}

// ---------------------------------------------------------------------------
// DirBlock (occupies one vault data block's usable bytes = 65520 bytes)
// ---------------------------------------------------------------------------

/// In-memory representation of a directory block.
///
/// On-disk layout (65520 bytes total):
/// - header (16 bytes): entry_count(2) + flags(2) + next_dir_block(8) + pad(4)
/// - entries: 255 × 256 bytes = 65280 bytes
/// - trailing pad: 224 bytes
#[derive(Debug, Clone)]
pub struct DirBlock {
    pub entry_count: u16,
    pub next_dir_block: u64,    // u64::MAX = no continuation
    pub entries: Vec<DirEntry>, // always exactly DIR_ENTRIES_PER_BLOCK
}

const DIR_BLOCK_HEADER: usize = 16;

impl DirBlock {
    /// Create an empty dir block (all entries free, no continuation).
    pub fn empty() -> Self {
        DirBlock {
            entry_count: 0,
            next_dir_block: u64::MAX,
            entries: vec![DirEntry::free(); DIR_ENTRIES_PER_BLOCK],
        }
    }

    /// Serialize to exactly `usable_bytes` (65520) bytes.
    pub fn to_bytes(&self, usable_bytes: usize) -> Vec<u8> {
        let mut buf = vec![0u8; usable_bytes];
        // header
        buf[0..2].copy_from_slice(&self.entry_count.to_le_bytes());
        // flags (2 bytes) = 0
        buf[4..12].copy_from_slice(&self.next_dir_block.to_le_bytes());
        // pad (4 bytes) = 0
        // entries
        for (i, entry) in self.entries.iter().enumerate() {
            let off = DIR_BLOCK_HEADER + i * DIR_ENTRY_SIZE;
            buf[off..off + DIR_ENTRY_SIZE].copy_from_slice(&entry.to_bytes());
        }
        // trailing pad is already zeroed
        buf
    }

    /// Parse from a byte slice of length `usable_bytes`.
    pub fn from_bytes(data: &[u8]) -> Self {
        let entry_count = u16::from_le_bytes([data[0], data[1]]);
        let next_dir_block = u64::from_le_bytes(data[4..12].try_into().unwrap());

        let mut entries = Vec::with_capacity(DIR_ENTRIES_PER_BLOCK);
        for i in 0..DIR_ENTRIES_PER_BLOCK {
            let off = DIR_BLOCK_HEADER + i * DIR_ENTRY_SIZE;
            entries.push(DirEntry::from_bytes(&data[off..off + DIR_ENTRY_SIZE]));
        }

        DirBlock {
            entry_count,
            next_dir_block,
            entries,
        }
    }
}

// ---------------------------------------------------------------------------
// DirEntry (256 bytes)
// ---------------------------------------------------------------------------

/// Fixed-size directory entry (256 bytes).
///
/// Layout:
/// ```text
/// entry_type : u8    (0=free, 1=file, 2=dir)
/// attr       : u8    (0=normal, 1=hidden, 2=readonly)
/// name_len   : u8    (length of UTF-8 name, 1–208)
/// _pad       : u8
/// size       : u64   (plaintext file size; 0 for dirs)
/// index_block: u64   (file: index block idx; dir: first DirBlock idx; MAX=empty)
/// block_count: u32   (allocated data blocks for this file)
/// created    : u64   (Windows FILETIME)
/// modified   : u64
/// accessed   : u64
/// name       : [u8; 208]  (UTF-8, zero-padded)
/// ```
/// Total: 4 + 8 + 8 + 4 + 24 + 208 = 256 bytes.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub entry_type: u8,
    pub attr: u8,
    pub name_len: u8,
    pub size: u64,
    pub index_block: u64,
    pub block_count: u32,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub name: [u8; ENTRY_NAME_MAX],
}

impl DirEntry {
    pub fn free() -> Self {
        DirEntry {
            entry_type: ENTRY_FREE,
            attr: 0,
            name_len: 0,
            size: 0,
            index_block: u64::MAX,
            block_count: 0,
            created: 0,
            modified: 0,
            accessed: 0,
            name: [0; ENTRY_NAME_MAX],
        }
    }

    pub fn name_str(&self) -> &str {
        std::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("<invalid>")
    }

    pub fn to_bytes(&self) -> [u8; DIR_ENTRY_SIZE] {
        let mut b = [0u8; DIR_ENTRY_SIZE];
        b[0] = self.entry_type;
        b[1] = self.attr;
        b[2] = self.name_len;
        // b[3] = pad = 0
        b[4..12].copy_from_slice(&self.size.to_le_bytes());
        b[12..20].copy_from_slice(&self.index_block.to_le_bytes());
        b[20..24].copy_from_slice(&self.block_count.to_le_bytes());
        b[24..32].copy_from_slice(&self.created.to_le_bytes());
        b[32..40].copy_from_slice(&self.modified.to_le_bytes());
        b[40..48].copy_from_slice(&self.accessed.to_le_bytes());
        b[48..48 + ENTRY_NAME_MAX].copy_from_slice(&self.name);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        debug_assert_eq!(b.len(), DIR_ENTRY_SIZE);
        let mut name = [0u8; ENTRY_NAME_MAX];
        name.copy_from_slice(&b[48..48 + ENTRY_NAME_MAX]);
        DirEntry {
            entry_type: b[0],
            attr: b[1],
            name_len: b[2],
            size: u64::from_le_bytes(b[4..12].try_into().unwrap()),
            index_block: u64::from_le_bytes(b[12..20].try_into().unwrap()),
            block_count: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            created: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            modified: u64::from_le_bytes(b[32..40].try_into().unwrap()),
            accessed: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            name,
        }
    }
}

// ---------------------------------------------------------------------------
// FileIndexBlock helpers
// ---------------------------------------------------------------------------

/// Parse an index block plaintext (usable_bytes) into a Vec<u64> of block pointers.
/// Entries beyond `block_count` are u64::MAX (unused).
pub fn parse_index_block(plain: &[u8]) -> Vec<u64> {
    plain
        .chunks_exact(8)
        .take(INDEX_PTRS_PER_BLOCK)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

/// Serialize a block_map into `usable_bytes` bytes (remaining space filled with u64::MAX).
pub fn serialize_index_block(block_map: &[u64], usable_bytes: usize) -> Vec<u8> {
    let mut buf = vec![0xFFu8; usable_bytes]; // fill with 0xFF = u64::MAX bytes
    for (i, &ptr) in block_map.iter().take(INDEX_PTRS_PER_BLOCK).enumerate() {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&ptr.to_le_bytes());
    }
    buf
}

/// Serialize raw pointer slots (exactly INDEX_PTRS_PER_BLOCK values expected).
pub fn serialize_index_block_raw(ptrs: &[u64], usable_bytes: usize) -> Vec<u8> {
    let mut buf = vec![0xFFu8; usable_bytes];
    for (i, &ptr) in ptrs.iter().take(INDEX_PTRS_PER_BLOCK).enumerate() {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&ptr.to_le_bytes());
    }
    buf
}
